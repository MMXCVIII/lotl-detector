/*
 * LOTL Detector - ptrace Tracing
 * 
 * This BPF program traces ptrace syscalls to detect:
 * - Process injection attacks
 * - Debugger attachment to sensitive processes
 * - Memory manipulation
 * 
 * ptrace is commonly abused for:
 * - Code injection into running processes
 * - Credential harvesting
 * - Anti-debugging evasion
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

/* ptrace request types we care about */
#define PTRACE_ATTACH       16
#define PTRACE_SEIZE        0x4206
#define PTRACE_POKETEXT     4
#define PTRACE_POKEDATA     5

/* ─────────────────────────────────────────────────────────────────────────────
 * PTRACE TRACEPOINT
 * 
 * Traces sys_enter_ptrace to detect process injection.
 * ───────────────────────────────────────────────────────────────────────────── */

TRACEPOINT_PROBE(syscalls, sys_enter_ptrace)
{
    __u64 now = bpf_ktime_get_ns();
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    long request = args->request;
    long target_pid = args->pid;
    
    /* Filter for suspicious ptrace operations */
    if (request != PTRACE_ATTACH && 
        request != PTRACE_SEIZE &&
        request != PTRACE_POKETEXT &&
        request != PTRACE_POKEDATA) {
        return 0;  /* Not interesting */
    }
    
    /* Check if targeting detector process */
    __u32 config_key = CONFIG_DETECTOR_PID;
    __u32 *detector_pid = config.lookup(&config_key);
    if (detector_pid && *detector_pid == (__u32)target_pid) {
        /* Someone is trying to debug the detector! */
        struct alert_event *alert = alerts.ringbuf_reserve(sizeof(*alert));
        if (alert) {
            __builtin_memset(alert, 0, sizeof(*alert));
            alert->timestamp_ns = now;
            alert->pid = pid;
            alert->uid = uid;
            alert->type = ALERT_PTRACE_ATTACH;
            alert->severity = SEVERITY_CRITICAL;
            alert->target_pid = (__u32)target_pid;
            bpf_get_current_comm(&alert->comm, sizeof(alert->comm));
            alerts.ringbuf_submit(alert, 0);
            update_stat(STAT_ALERTS_TOTAL);
        }
        return 0;
    }
    
    /* Send alert for ptrace attach/injection */
    __u32 severity = SEVERITY_MEDIUM;
    if (request == PTRACE_POKETEXT || request == PTRACE_POKEDATA) {
        severity = SEVERITY_HIGH;  /* Memory modification is more serious */
    }
    
    struct alert_event *alert = alerts.ringbuf_reserve(sizeof(*alert));
    if (alert) {
        __builtin_memset(alert, 0, sizeof(*alert));
        alert->timestamp_ns = now;
        alert->pid = pid;
        alert->uid = uid;
        alert->type = ALERT_PTRACE_ATTACH;
        alert->severity = severity;
        alert->target_pid = (__u32)target_pid;
        bpf_get_current_comm(&alert->comm, sizeof(alert->comm));
        alerts.ringbuf_submit(alert, 0);
    }
    
    return 0;
}

