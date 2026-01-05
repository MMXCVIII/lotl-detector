/*
 * LOTL Detector - Self-Protection LSM Hooks
 * 
 * This BPF program implements self-protection mechanisms:
 * - Prevent killing the detector process
 * - Monitor for foreign eBPF program loads
 * - Block writes to /proc/pid/mem
 * 
 * IMPORTANT: Requires BPF LSM to be enabled in kernel.
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

/* ─────────────────────────────────────────────────────────────────────────────
 * LSM HOOK: task_kill
 * 
 * Called when a process attempts to send a signal to another process.
 * We use this to protect the detector from being killed.
 * 
 * Return: 0 to allow, -EPERM to deny
 * ───────────────────────────────────────────────────────────────────────────── */

LSM_PROBE(task_kill, struct task_struct *p, struct kernel_siginfo *info, 
          int sig, const struct cred *cred)
{
    /* Get target PID */
    __u32 target_pid;
    bpf_probe_read_kernel(&target_pid, sizeof(target_pid), &p->tgid);
    
    /* Check if target is the detector */
    __u32 config_key = CONFIG_DETECTOR_PID;
    __u32 *detector_pid = config.lookup(&config_key);
    
    if (!detector_pid || *detector_pid == 0) {
        return 0;  /* Detector PID not set, allow */
    }
    
    if (target_pid != *detector_pid) {
        return 0;  /* Not targeting detector, allow */
    }
    
    /* Someone is trying to kill the detector! */
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    /* Allow self-signals (for graceful shutdown) */
    if (pid == *detector_pid) {
        return 0;
    }
    
    /* Allow SIGCHLD, SIGCONT (harmless) */
    if (sig == 17 || sig == 18) {  /* SIGCHLD=17, SIGCONT=18 */
        return 0;
    }
    
    /* Send alert and block */
    struct alert_event *alert = alerts.ringbuf_reserve(sizeof(*alert));
    if (alert) {
        __builtin_memset(alert, 0, sizeof(*alert));
        alert->timestamp_ns = bpf_ktime_get_ns();
        alert->pid = pid;
        alert->uid = uid;
        alert->type = ALERT_PROC_MEM_WRITE;  /* Reusing for self-protection */
        alert->severity = SEVERITY_CRITICAL;
        alert->target_pid = target_pid;
        bpf_get_current_comm(&alert->comm, sizeof(alert->comm));
        alerts.ringbuf_submit(alert, 0);
        update_stat(STAT_ALERTS_TOTAL);
    }
    
    /* Get current mode */
    __u32 mode_key = CONFIG_MODE;
    __u32 *mode = config.lookup(&mode_key);
    
    /* Only block in enforce mode */
    if (mode && *mode >= MODE_ENFORCE) {
        return -EPERM;
    }
    
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * LSM HOOK: bpf
 * 
 * Called when bpf() syscall is invoked.
 * We monitor for foreign eBPF program loads.
 * 
 * Return: 0 to allow, -EPERM to deny
 * ───────────────────────────────────────────────────────────────────────────── */

/* BPF command types */
#define BPF_PROG_LOAD 5

LSM_PROBE(bpf, int cmd, union bpf_attr *attr, unsigned int size)
{
    /* Only interested in program loads */
    if (cmd != BPF_PROG_LOAD) {
        return 0;
    }
    
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    /* Check if this is the detector loading programs */
    __u32 config_key = CONFIG_DETECTOR_PID;
    __u32 *detector_pid = config.lookup(&config_key);
    
    if (detector_pid && *detector_pid == pid) {
        return 0;  /* Detector loading its own programs, allow */
    }
    
    /* Foreign BPF load detected! */
    struct alert_event *alert = alerts.ringbuf_reserve(sizeof(*alert));
    if (alert) {
        __builtin_memset(alert, 0, sizeof(*alert));
        alert->timestamp_ns = bpf_ktime_get_ns();
        alert->pid = pid;
        alert->uid = uid;
        alert->type = ALERT_FOREIGN_BPF;
        alert->severity = SEVERITY_HIGH;
        bpf_get_current_comm(&alert->comm, sizeof(alert->comm));
        alerts.ringbuf_submit(alert, 0);
        update_stat(STAT_ALERTS_TOTAL);
    }
    
    /* We don't block other BPF programs - just alert */
    /* Blocking would break legitimate tools like tcpdump, bpftrace, etc. */
    
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * LSM HOOK: file_open
 * 
 * Monitor opens of /proc/pid/mem files for write.
 * This is used for process injection.
 * 
 * Return: 0 to allow, -EPERM to deny
 * ───────────────────────────────────────────────────────────────────────────── */

LSM_PROBE(file_open, struct file *file)
{
    /* Check if this is /proc/*/mem */
    char path[64] = {};
    struct dentry *dentry;
    
    bpf_probe_read_kernel(&dentry, sizeof(dentry), &file->f_path.dentry);
    if (!dentry) {
        return 0;
    }
    
    /* Read filename */
    struct qstr d_name;
    bpf_probe_read_kernel(&d_name, sizeof(d_name), &dentry->d_name);
    
    char name[8] = {};
    bpf_probe_read_kernel(name, sizeof(name), d_name.name);
    
    /* Check if it's "mem" */
    if (name[0] != 'm' || name[1] != 'e' || name[2] != 'm' || name[3] != '\0') {
        return 0;
    }
    
    /* Check if opened for write */
    unsigned int flags;
    bpf_probe_read_kernel(&flags, sizeof(flags), &file->f_flags);
    
    if (!(flags & 0x01)) {  /* O_WRONLY = 0x01 */
        return 0;  /* Read-only, allow */
    }
    
    /* Get parent dentry to find PID */
    struct dentry *parent;
    bpf_probe_read_kernel(&parent, sizeof(parent), &dentry->d_parent);
    
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    /* Send alert */
    struct alert_event *alert = alerts.ringbuf_reserve(sizeof(*alert));
    if (alert) {
        __builtin_memset(alert, 0, sizeof(*alert));
        alert->timestamp_ns = bpf_ktime_get_ns();
        alert->pid = pid;
        alert->uid = uid;
        alert->type = ALERT_PROC_MEM_WRITE;
        alert->severity = SEVERITY_CRITICAL;
        bpf_get_current_comm(&alert->comm, sizeof(alert->comm));
        alerts.ringbuf_submit(alert, 0);
        update_stat(STAT_ALERTS_TOTAL);
    }
    
    /* Get current mode */
    __u32 mode_key = CONFIG_MODE;
    __u32 *mode = config.lookup(&mode_key);
    
    /* Block in enforce mode */
    if (mode && *mode >= MODE_ENFORCE) {
        update_lsm_stat(STAT_BLOCKS_TOTAL);
        return -EPERM;
    }
    
    return 0;
}

