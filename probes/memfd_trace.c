/*
 * LOTL Detector - memfd_create Tracing
 * 
 * This BPF program traces memfd_create syscalls to detect
 * fileless execution attempts.
 * 
 * memfd_create creates an anonymous file that exists only in memory.
 * This is commonly abused for:
 * - In-memory payload execution
 * - Avoiding filesystem-based detection
 * - Staging malicious code
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

/* ─────────────────────────────────────────────────────────────────────────────
 * MEMFD TRACKING MAP
 * 
 * Track PIDs that have created memfds for correlation with execve.
 * ───────────────────────────────────────────────────────────────────────────── */

/* PID -> timestamp of last memfd_create */
BPF_LRU_HASH(memfd_pids, __u32, __u64, 4096);

/* ─────────────────────────────────────────────────────────────────────────────
 * MEMFD_CREATE TRACEPOINT
 * 
 * Traces sys_enter_memfd_create to detect anonymous file creation.
 * ───────────────────────────────────────────────────────────────────────────── */

TRACEPOINT_PROBE(syscalls, sys_enter_memfd_create)
{
    __u64 now = bpf_ktime_get_ns();
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    /* Track this PID as having created a memfd */
    memfd_pids.update(&pid, &now);
    
    /* Send alert for memfd creation */
    struct alert_event *alert = alerts.ringbuf_reserve(sizeof(*alert));
    if (alert) {
        __builtin_memset(alert, 0, sizeof(*alert));
        alert->timestamp_ns = now;
        alert->pid = pid;
        alert->uid = uid;
        alert->type = ALERT_MEMFD_CREATE;
        alert->severity = SEVERITY_MEDIUM;  /* Creation is suspicious but not critical */
        bpf_get_current_comm(&alert->comm, sizeof(alert->comm));
        
        /* Capture the name argument */
        const char *name = (const char *)args->uname;
        if (name) {
            bpf_probe_read_user_str(alert->filename, sizeof(alert->filename), name);
        }
        
        alerts.ringbuf_submit(alert, 0);
    }
    
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * HELPER: Check if PID has recently created memfd
 * ───────────────────────────────────────────────────────────────────────────── */

static __always_inline int has_recent_memfd(__u32 pid, __u64 now)
{
    __u64 *ts = memfd_pids.lookup(&pid);
    if (!ts) {
        return 0;
    }
    
    /* Consider memfd "recent" if created within last 5 seconds */
    if (now - *ts < 5000000000ULL) {
        return 1;
    }
    
    return 0;
}

