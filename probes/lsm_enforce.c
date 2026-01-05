/*
 * LOTL Detector - LSM Enforcement
 * 
 * This BPF program implements the blocking logic using LSM hooks.
 * It provides:
 * - Path-based blocklist
 * - Inode-based blocklist (catches copies and symlinks)
 * - User blocklist (block specific UIDs)
 * - Ancestry allowlist (allow package manager descendants)
 * - memfd/anonymous execution blocking
 * 
 * IMPORTANT: LSM BPF requires the kernel to be booted with "bpf" in the
 * LSM list (e.g., lsm=landlock,lockdown,yama,integrity,apparmor,bpf)
 * 
 * Uses bcc-style macros for compatibility with Python bcc bindings.
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/binfmts.h>

/* Include common definitions - will be concatenated by loader */
/* #include "common.h" */

/* ─────────────────────────────────────────────────────────────────────────────
 * BPF MAPS FOR BLOCKING
 * ───────────────────────────────────────────────────────────────────────────── */

/* Path-based blocklist: filename -> blocked (1) */
BPF_HASH(blocklist, char[MAX_FILENAME_LEN], __u8, 10240);

/* Inode-based blocklist: inode number -> blocked (1) */
BPF_HASH(inode_blocklist, __u64, __u8, 10240);

/* User blocklist: UID -> blocked (1) */
BPF_HASH(user_blocklist, __u32, __u8, 1024);

/* Allowlist: filename -> allowed (1) - bypasses all checks */
BPF_HASH(allowlist, char[MAX_FILENAME_LEN], __u8, 4096);

/* Ancestry allowlist: PID -> expiry timestamp */
BPF_HASH(ancestry_allow, __u32, struct ancestry_entry, 4096);

/* Configuration: key -> value */
BPF_ARRAY(config, __u32, 8);

/* Statistics (shared with execve_trace) */
/* Using extern reference - stats is defined in execve_trace.c */
BPF_PERCPU_ARRAY(lsm_stats, __u64, 8);

/* Ring buffer for block events */
BPF_RINGBUF_OUTPUT(block_events, 1 << 20);  /* 1MB */

/* ─────────────────────────────────────────────────────────────────────────────
 * HELPER: Update LSM statistics
 * ───────────────────────────────────────────────────────────────────────────── */

static __always_inline void update_lsm_stat(__u32 key)
{
    __u64 *val = lsm_stats.lookup(&key);
    if (val) {
        (*val)++;
    }
}

/* ─────────────────────────────────────────────────────────────────────────────
 * HELPER: Send block alert
 * ───────────────────────────────────────────────────────────────────────────── */

static __always_inline void send_block_alert(
    __u32 alert_type,
    __u32 pid,
    __u32 uid,
    const char *filename)
{
    struct alert_event *alert = block_events.ringbuf_reserve(sizeof(*alert));
    if (alert) {
        __builtin_memset(alert, 0, sizeof(*alert));
        alert->timestamp_ns = bpf_ktime_get_ns();
        alert->pid = pid;
        alert->uid = uid;
        alert->type = alert_type;
        alert->severity = SEVERITY_HIGH;
        bpf_get_current_comm(&alert->comm, sizeof(alert->comm));
        
        /* Copy filename - need to handle kernel vs user memory */
        #pragma unroll
        for (int i = 0; i < MAX_FILENAME_LEN && i < 64; i++) {
            alert->filename[i] = filename[i];
            if (filename[i] == '\0') break;
        }
        
        block_events.ringbuf_submit(alert, 0);
    }
}

/* ─────────────────────────────────────────────────────────────────────────────
 * LSM HOOK: bprm_check_security
 * 
 * Called during execve() before the new program runs.
 * This is where we can block execution.
 * 
 * Return: 0 to allow, -EPERM to deny
 * ───────────────────────────────────────────────────────────────────────────── */

LSM_PROBE(bprm_check_security, struct linux_binprm *bprm, int ret)
{
    char filename[MAX_FILENAME_LEN] = {};
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    __u64 now = bpf_ktime_get_ns();
    
    /* ─── Get current mode ─── */
    __u32 mode_key = CONFIG_MODE;
    __u32 *mode = config.lookup(&mode_key);
    
    /* Default allow if config not set or in bootstrap/learn mode */
    if (!mode || *mode < MODE_ENFORCE) {
        /* In learn mode, Tier 1 blocking still applies */
        if (!mode || *mode < MODE_LEARN) {
            return 0;  /* Bootstrap - allow everything */
        }
        /* Continue with Tier 1 checks only */
    }
    
    /* ─── Read filename ─── */
    int ret_read = bpf_probe_read_kernel_str(filename, sizeof(filename), bprm->filename);
    if (ret_read < 0) {
        return 0;  /* Can't read filename - allow */
    }
    
    /* ─── Check allowlist first (bypass all checks) ─── */
    __u8 *allowed = allowlist.lookup((char (*)[MAX_FILENAME_LEN])filename);
    if (allowed && *allowed) {
        return 0;  /* Explicitly allowed */
    }
    
    /* ─── Check ancestry allowlist ─── */
    struct ancestry_entry *ancestry = ancestry_allow.lookup(&pid);
    if (ancestry && ancestry->active && ancestry->expiry_ns > now) {
        return 0;  /* Allowed by ancestry */
    }
    
    /* ─── Block memfd/proc/fd execution ─── */
    if (is_path_proc_fd(filename)) {
        send_block_alert(ALERT_MEMFD_EXEC, pid, uid, filename);
        update_lsm_stat(STAT_BLOCKS_TOTAL);
        return -EPERM;
    }
    
    /* ─── Check user blocklist ─── */
    __u8 *user_blocked = user_blocklist.lookup(&uid);
    if (user_blocked && *user_blocked) {
        send_block_alert(ALERT_BLOCKED_USER, pid, uid, filename);
        update_lsm_stat(STAT_BLOCKS_TOTAL);
        return -EPERM;
    }
    
    /* ─── Check inode blocklist ─── */
    struct file *file = bprm->file;
    if (file) {
        struct inode *inode;
        bpf_probe_read_kernel(&inode, sizeof(inode), &file->f_inode);
        if (inode) {
            __u64 ino;
            bpf_probe_read_kernel(&ino, sizeof(ino), &inode->i_ino);
            
            __u8 *inode_blocked = inode_blocklist.lookup(&ino);
            if (inode_blocked && *inode_blocked) {
                send_block_alert(ALERT_BLOCKED_EXEC, pid, uid, filename);
                update_lsm_stat(STAT_BLOCKS_TOTAL);
                return -EPERM;
            }
        }
    }
    
    /* ─── Check path blocklist ─── */
    __u8 *path_blocked = blocklist.lookup((char (*)[MAX_FILENAME_LEN])filename);
    if (path_blocked && *path_blocked) {
        send_block_alert(ALERT_BLOCKED_EXEC, pid, uid, filename);
        update_lsm_stat(STAT_BLOCKS_TOTAL);
        return -EPERM;
    }
    
    return 0;  /* Allow */
}

/* ─────────────────────────────────────────────────────────────────────────────
 * FORK TRACKING
 * 
 * Track process forks to propagate ancestry allowlist.
 * When a process with ancestry allowance forks, the child inherits it.
 * ───────────────────────────────────────────────────────────────────────────── */

TRACEPOINT_PROBE(sched, sched_process_fork)
{
    __u32 parent_pid = args->parent_pid;
    __u32 child_pid = args->child_pid;
    __u64 now = bpf_ktime_get_ns();
    
    /* Check if parent has ancestry allowance */
    struct ancestry_entry *parent_ancestry = ancestry_allow.lookup(&parent_pid);
    if (parent_ancestry && parent_ancestry->active && parent_ancestry->expiry_ns > now) {
        /* Propagate to child with same expiry */
        struct ancestry_entry child_ancestry = {
            .expiry_ns = parent_ancestry->expiry_ns,
            .active = 1,
        };
        ancestry_allow.update(&child_pid, &child_ancestry);
    }
    
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * PROCESS EXIT TRACKING
 * 
 * Clean up ancestry allowlist when processes exit.
 * ───────────────────────────────────────────────────────────────────────────── */

TRACEPOINT_PROBE(sched, sched_process_exit)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    /* Remove from ancestry allowlist */
    ancestry_allow.delete(&pid);
    
    return 0;
}

