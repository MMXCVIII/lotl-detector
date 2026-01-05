/*
 * LOTL Detector - Kernel Module Loading Trace
 * 
 * This BPF program traces kernel module loading syscalls.
 * Module loading is a common technique for:
 * - Kernel rootkits
 * - Privilege escalation
 * - Hiding malicious activity
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

/* ─────────────────────────────────────────────────────────────────────────────
 * INIT_MODULE TRACEPOINT
 * 
 * Traces init_module syscall (loads module from memory).
 * ───────────────────────────────────────────────────────────────────────────── */

TRACEPOINT_PROBE(syscalls, sys_enter_init_module)
{
    __u64 now = bpf_ktime_get_ns();
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    /* Send critical alert for kernel module loading */
    struct alert_event *alert = alerts.ringbuf_reserve(sizeof(*alert));
    if (alert) {
        __builtin_memset(alert, 0, sizeof(*alert));
        alert->timestamp_ns = now;
        alert->pid = pid;
        alert->uid = uid;
        alert->type = ALERT_KERNEL_MODULE;
        alert->severity = SEVERITY_CRITICAL;
        bpf_get_current_comm(&alert->comm, sizeof(alert->comm));
        
        /* Capture module params if provided */
        const char *params = (const char *)args->uargs;
        if (params) {
            bpf_probe_read_user_str(alert->filename, sizeof(alert->filename), params);
        }
        
        alerts.ringbuf_submit(alert, 0);
        update_stat(STAT_ALERTS_TOTAL);
    }
    
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * FINIT_MODULE TRACEPOINT
 * 
 * Traces finit_module syscall (loads module from file descriptor).
 * ───────────────────────────────────────────────────────────────────────────── */

TRACEPOINT_PROBE(syscalls, sys_enter_finit_module)
{
    __u64 now = bpf_ktime_get_ns();
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    /* Send critical alert for kernel module loading */
    struct alert_event *alert = alerts.ringbuf_reserve(sizeof(*alert));
    if (alert) {
        __builtin_memset(alert, 0, sizeof(*alert));
        alert->timestamp_ns = now;
        alert->pid = pid;
        alert->uid = uid;
        alert->type = ALERT_KERNEL_MODULE;
        alert->severity = SEVERITY_CRITICAL;
        bpf_get_current_comm(&alert->comm, sizeof(alert->comm));
        
        /* Capture module params */
        const char *params = (const char *)args->uargs;
        if (params) {
            bpf_probe_read_user_str(alert->filename, sizeof(alert->filename), params);
        }
        
        alerts.ringbuf_submit(alert, 0);
        update_stat(STAT_ALERTS_TOTAL);
    }
    
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────────
 * DELETE_MODULE TRACEPOINT
 * 
 * Traces delete_module syscall (unloads kernel module).
 * Also suspicious as it may indicate cleanup after exploitation.
 * ───────────────────────────────────────────────────────────────────────────── */

TRACEPOINT_PROBE(syscalls, sys_enter_delete_module)
{
    __u64 now = bpf_ktime_get_ns();
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    /* Send alert for module unloading */
    struct alert_event *alert = alerts.ringbuf_reserve(sizeof(*alert));
    if (alert) {
        __builtin_memset(alert, 0, sizeof(*alert));
        alert->timestamp_ns = now;
        alert->pid = pid;
        alert->uid = uid;
        alert->type = ALERT_KERNEL_MODULE;
        alert->severity = SEVERITY_HIGH;  /* Slightly lower than load */
        bpf_get_current_comm(&alert->comm, sizeof(alert->comm));
        
        /* Capture module name */
        const char *name = (const char *)args->name_user;
        if (name) {
            bpf_probe_read_user_str(alert->filename, sizeof(alert->filename), name);
        }
        
        alerts.ringbuf_submit(alert, 0);
    }
    
    return 0;
}

