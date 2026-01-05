/*
 * LOTL Detector - execve Tracing
 * 
 * This BPF program traces process execution via the execve syscall.
 * It captures:
 * - Process metadata (PID, UID, filename, arguments)
 * - Environment variables (LD_PRELOAD, LD_LIBRARY_PATH)
 * - Busybox applet detection
 * - Rate limiting to survive fork bombs
 * 
 * Uses bcc-style macros for compatibility with Python bcc bindings.
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

/* Include common definitions - will be concatenated by loader */
/* #include "common.h" */

/* ─────────────────────────────────────────────────────────────────────────────
 * BPF MAPS
 * ───────────────────────────────────────────────────────────────────────────── */

/* Ring buffer for events - 32MB */
BPF_RINGBUF_OUTPUT(events, 1 << 25);

/* Ring buffer for alerts - 1MB */
BPF_RINGBUF_OUTPUT(alerts, 1 << 20);

/* Statistics counters */
BPF_PERCPU_ARRAY(stats, __u64, 8);

/* Rate limiting per-PID */
BPF_LRU_HASH(exec_rate, __u32, struct rate_limit, 65536);

/* Configuration */
BPF_ARRAY(config, __u32, 4);

/* ─────────────────────────────────────────────────────────────────────────────
 * RATE LIMITING CONSTANTS
 * ───────────────────────────────────────────────────────────────────────────── */

#define RATE_LIMIT_WINDOW_NS    1000000000ULL   /* 1 second */
#define RATE_LIMIT_MAX_EXEC     100             /* Max 100 execs/sec/pid */
#define RATE_LIMIT_SAMPLE       100             /* Sample 1 in 100 when limited */

/* ─────────────────────────────────────────────────────────────────────────────
 * HELPER: Update statistics counter
 * ───────────────────────────────────────────────────────────────────────────── */

static __always_inline void update_stat(__u32 key)
{
    __u64 *val = stats.lookup(&key);
    if (val) {
        (*val)++;
    }
}

/* ─────────────────────────────────────────────────────────────────────────────
 * HELPER: Check and update rate limit
 * 
 * Returns: 0 if should process, 1 if rate limited (skip), 2 if sampled
 * ───────────────────────────────────────────────────────────────────────────── */

static __always_inline int check_rate_limit(__u32 pid, __u64 now)
{
    struct rate_limit *rl = exec_rate.lookup(&pid);
    
    if (rl) {
        if (now - rl->window_start > RATE_LIMIT_WINDOW_NS) {
            /* New window */
            rl->window_start = now;
            rl->count = 1;
        } else {
            rl->count++;
            if (rl->count > RATE_LIMIT_MAX_EXEC) {
                /* Rate limited - sample 1 in RATE_LIMIT_SAMPLE */
                if (rl->count % RATE_LIMIT_SAMPLE != 0) {
                    update_stat(STAT_EVENTS_DROPPED);
                    return 1;  /* Skip this event */
                }
                return 2;  /* Sampled event */
            }
        }
    } else {
        /* First exec from this PID */
        struct rate_limit new_rl = {
            .window_start = now,
            .count = 1,
        };
        exec_rate.update(&pid, &new_rl);
    }
    
    return 0;  /* Process normally */
}

/* ─────────────────────────────────────────────────────────────────────────────
 * HELPER: Capture environment variable if it matches prefix
 * 
 * Scans environment for a variable starting with prefix and copies its value.
 * ───────────────────────────────────────────────────────────────────────────── */

static __always_inline int capture_env_var(
    const char *const *envp,
    const char *prefix,
    int prefix_len,
    char *out,
    int out_len)
{
    #pragma unroll
    for (int i = 0; i < 64; i++) {
        const char *env;
        if (bpf_probe_read_user(&env, sizeof(env), &envp[i]) < 0 || !env) {
            break;
        }
        
        char buf[24];
        if (bpf_probe_read_user_str(buf, sizeof(buf), env) < 0) {
            continue;
        }
        
        /* Check prefix match */
        int match = 1;
        #pragma unroll
        for (int j = 0; j < 16 && j < prefix_len; j++) {
            if (buf[j] != prefix[j]) {
                match = 0;
                break;
            }
        }
        
        if (match) {
            /* Found it - copy value (skip prefix) */
            bpf_probe_read_user_str(out, out_len, env + prefix_len);
            return 1;
        }
    }
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * EXECVE TRACEPOINT
 * 
 * Traces sys_enter_execve to capture process execution details.
 * ───────────────────────────────────────────────────────────────────────────── */

TRACEPOINT_PROBE(syscalls, sys_enter_execve)
{
    __u64 now = bpf_ktime_get_ns();
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    /* ─── Rate limiting ─── */
    int rate_status = check_rate_limit(pid, now);
    if (rate_status == 1) {
        return 0;  /* Skip - rate limited */
    }
    
    /* ─── Reserve ring buffer space ─── */
    struct exec_event *e = events.ringbuf_reserve(sizeof(*e));
    if (!e) {
        update_stat(STAT_EVENTS_DROPPED);
        return 0;
    }
    
    /* ─── Initialize event ─── */
    __builtin_memset(e, 0, sizeof(*e));
    e->timestamp_ns = now;
    e->pid = pid;
    e->uid = uid;
    e->gid = bpf_get_current_uid_gid() >> 32;
    e->type = EVENT_EXECVE;
    e->rate_limited = (rate_status == 2) ? 1 : 0;
    
    /* Get parent PID from task struct */
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        bpf_probe_read_kernel(&e->ppid, sizeof(e->ppid), &task->real_parent->tgid);
        bpf_probe_read_kernel(&e->start_time_ns, sizeof(e->start_time_ns), &task->start_time);
    }
    
    /* Get process comm */
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    /* ─── Read filename ─── */
    const char *filename = (const char *)args->filename;
    int fname_ret = bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);
    if (fname_ret < 0) {
        events.ringbuf_discard(e, 0);
        return 0;
    }
    
    /* Get filename length for suffix checks */
    int fname_len = fname_ret > 0 ? fname_ret - 1 : 0;  /* -1 for null terminator */
    
    /* ─── Check for memfd execution pattern ─── */
    if (is_path_proc_fd(e->filename)) {
        e->is_memfd = 1;
        
        /* Send immediate alert for memfd execution */
        struct alert_event *alert = alerts.ringbuf_reserve(sizeof(*alert));
        if (alert) {
            __builtin_memset(alert, 0, sizeof(*alert));
            alert->timestamp_ns = now;
            alert->pid = pid;
            alert->uid = uid;
            alert->type = ALERT_MEMFD_EXEC;
            alert->severity = SEVERITY_CRITICAL;
            bpf_get_current_comm(&alert->comm, sizeof(alert->comm));
            bpf_probe_read_user_str(alert->filename, sizeof(alert->filename), filename);
            alerts.ringbuf_submit(alert, 0);
            update_stat(STAT_ALERTS_TOTAL);
        }
    }
    
    /* ─── Check for busybox ─── */
    if (is_busybox_path(e->filename, fname_len)) {
        e->is_busybox = 1;
    }
    
    /* ─── Read arguments ─── */
    const char *const *argv = (const char *const *)args->argv;
    
    #pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        const char *arg;
        if (bpf_probe_read_user(&arg, sizeof(arg), &argv[i]) < 0 || !arg) {
            break;
        }
        
        int arg_ret = bpf_probe_read_user_str(e->args[i], MAX_ARG_LEN, arg);
        if (arg_ret == MAX_ARG_LEN) {
            e->args_truncated = 1;
        }
    }
    
    /* Check if more args exist beyond MAX_ARGS */
    const char *extra_arg;
    if (bpf_probe_read_user(&extra_arg, sizeof(extra_arg), &argv[MAX_ARGS]) == 0 && extra_arg) {
        e->args_count_exceeded = 1;
    }
    
    /* ─── If busybox, capture applet name (argv[1] typically) ─── */
    if (e->is_busybox && e->args[1][0] != '\0') {
        __builtin_memcpy(e->busybox_applet, e->args[1], MAX_APPLET_LEN);
    }
    
    /* ─── Capture environment variables ─── */
    const char *const *envp = (const char *const *)args->envp;
    
    /* LD_PRELOAD= */
    if (capture_env_var(envp, "LD_PRELOAD=", 11, e->env_ld_preload, sizeof(e->env_ld_preload))) {
        /* Send alert for LD_PRELOAD */
        struct alert_event *alert = alerts.ringbuf_reserve(sizeof(*alert));
        if (alert) {
            __builtin_memset(alert, 0, sizeof(*alert));
            alert->timestamp_ns = now;
            alert->pid = pid;
            alert->uid = uid;
            alert->type = ALERT_LD_PRELOAD;
            alert->severity = SEVERITY_HIGH;
            bpf_get_current_comm(&alert->comm, sizeof(alert->comm));
            bpf_probe_read_user_str(alert->filename, sizeof(alert->filename), filename);
            alerts.ringbuf_submit(alert, 0);
            update_stat(STAT_ALERTS_TOTAL);
        }
    }
    
    /* LD_LIBRARY_PATH= */
    capture_env_var(envp, "LD_LIBRARY_PATH=", 16, e->env_ld_library_path, sizeof(e->env_ld_library_path));
    
    /* ─── Get inode for copy detection ─── */
    /* Note: This is tricky in tracepoint - may need LSM hook for accurate inode */
    e->inode = 0;  /* Will be filled by LSM if available */
    
    /* ─── Update stats and submit ─── */
    update_stat(STAT_EVENTS_TOTAL);
    events.ringbuf_submit(e, 0);
    
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * EXECVE EXIT TRACEPOINT
 * 
 * Optional: Track exec failures
 * ───────────────────────────────────────────────────────────────────────────── */

TRACEPOINT_PROBE(syscalls, sys_exit_execve)
{
    /* Only track failures for now */
    long ret = args->ret;
    if (ret < 0) {
        /* Exec failed - could log this if needed */
    }
    return 0;
}

