/*
 * LOTL Detector - Common BPF Definitions
 * 
 * This header contains shared structures and verifier-safe helper functions
 * used across all BPF programs in the LOTL detection system.
 * 
 * VERIFIER COMPLIANCE RULES:
 * - All loops must use #pragma unroll with fixed bounds
 * - Large structs must be allocated via ring buffer, not stack (512 byte limit)
 * - All helpers must be static __always_inline
 * - Always check return values from bpf_probe_read_*
 */

#ifndef __LOTL_COMMON_H
#define __LOTL_COMMON_H

/* ─────────────────────────────────────────────────────────────────────────────
 * SIZE LIMITS
 * Keep these reasonable to stay within BPF constraints
 * ───────────────────────────────────────────────────────────────────────────── */

#define MAX_FILENAME_LEN    256
#define MAX_ARGS            6
#define MAX_ARG_LEN         128
#define MAX_ENV_VAL_LEN     128
#define MAX_COMM_LEN        16
#define MAX_APPLET_LEN      32

/* ─────────────────────────────────────────────────────────────────────────────
 * EVENT TYPES
 * ───────────────────────────────────────────────────────────────────────────── */

enum event_type {
    EVENT_EXECVE        = 1,
    EVENT_MEMFD_CREATE  = 2,
    EVENT_NETWORK       = 3,
    EVENT_MODULE        = 4,
    EVENT_PTRACE        = 5,
    EVENT_EXIT          = 6,
};

/* ─────────────────────────────────────────────────────────────────────────────
 * ALERT TYPES
 * ───────────────────────────────────────────────────────────────────────────── */

enum alert_type {
    ALERT_NONE              = 0,
    ALERT_MEMFD_CREATE      = 1,
    ALERT_MEMFD_EXEC        = 2,
    ALERT_LD_PRELOAD        = 3,
    ALERT_KERNEL_MODULE     = 4,
    ALERT_FOREIGN_BPF       = 5,
    ALERT_PTRACE_ATTACH     = 6,
    ALERT_PROC_MEM_WRITE    = 7,
    ALERT_FORK_BOMB         = 8,
    ALERT_BLOCKED_EXEC      = 9,
    ALERT_BLOCKED_USER      = 10,
};

/* ─────────────────────────────────────────────────────────────────────────────
 * SEVERITY LEVELS
 * ───────────────────────────────────────────────────────────────────────────── */

enum severity_level {
    SEVERITY_INFO       = 0,
    SEVERITY_LOW        = 1,
    SEVERITY_MEDIUM     = 2,
    SEVERITY_HIGH       = 3,
    SEVERITY_CRITICAL   = 4,
};

/* ─────────────────────────────────────────────────────────────────────────────
 * OPERATIONAL MODES
 * ───────────────────────────────────────────────────────────────────────────── */

#define MODE_BOOTSTRAP  0   /* Log only, no alerts, collect baseline */
#define MODE_LEARN      1   /* Alert anomalies, block Tier 1 only */
#define MODE_ENFORCE    2   /* Full blocking + alerts */
#define MODE_PARANOID   3   /* Block everything suspicious */

/* ─────────────────────────────────────────────────────────────────────────────
 * STATS MAP KEYS
 * ───────────────────────────────────────────────────────────────────────────── */

#define STAT_EVENTS_TOTAL       0
#define STAT_EVENTS_DROPPED     1
#define STAT_BLOCKS_TOTAL       2
#define STAT_ALERTS_TOTAL       3

/* ─────────────────────────────────────────────────────────────────────────────
 * CONFIG MAP KEYS
 * ───────────────────────────────────────────────────────────────────────────── */

#define CONFIG_MODE             0
#define CONFIG_DETECTOR_PID     1

/* ─────────────────────────────────────────────────────────────────────────────
 * MAIN EVENT STRUCTURE
 * 
 * This structure is used for execve events. It must be allocated from the
 * ring buffer, not the stack, due to its size.
 * ───────────────────────────────────────────────────────────────────────────── */

struct exec_event {
    /* Timing and identification */
    __u64 timestamp_ns;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u64 start_time_ns;
    __u64 inode;
    
    /* Event metadata */
    __u32 type;
    __u8 blocked;
    __u8 is_memfd;
    __u8 is_busybox;
    __u8 is_stdin_exec;
    __u8 args_truncated;
    __u8 args_count_exceeded;
    __u8 env_truncated;
    __u8 rate_limited;
    
    /* Process info */
    char comm[MAX_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
    char args[MAX_ARGS][MAX_ARG_LEN];
    
    /* Busybox detection */
    char busybox_applet[MAX_APPLET_LEN];
    
    /* Environment variables (security-relevant) */
    char env_ld_preload[MAX_ENV_VAL_LEN];
    char env_ld_library_path[MAX_ENV_VAL_LEN];
};

/* ─────────────────────────────────────────────────────────────────────────────
 * ALERT EVENT STRUCTURE
 * 
 * Smaller structure for immediate alerts that don't need full event data.
 * ───────────────────────────────────────────────────────────────────────────── */

struct alert_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 uid;
    __u32 type;
    __u32 severity;
    __u32 target_pid;       /* For ptrace alerts */
    char comm[MAX_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
};

/* ─────────────────────────────────────────────────────────────────────────────
 * RATE LIMITING STRUCTURE
 * ───────────────────────────────────────────────────────────────────────────── */

struct rate_limit {
    __u64 window_start;
    __u32 count;
    __u32 _pad;
};

/* ─────────────────────────────────────────────────────────────────────────────
 * ANCESTRY ALLOWLIST ENTRY
 * ───────────────────────────────────────────────────────────────────────────── */

struct ancestry_entry {
    __u64 expiry_ns;
    __u8 active;
    __u8 _pad[7];
};

/* ═══════════════════════════════════════════════════════════════════════════
 * VERIFIER-SAFE HELPER FUNCTIONS
 * 
 * All functions must be static __always_inline to be inlined by the compiler.
 * This is required for BPF verifier compliance.
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * str_starts_with - Check if string starts with prefix
 * 
 * @str: The string to check (must be readable)
 * @prefix: The prefix to look for (null-terminated, max 32 chars)
 * 
 * Returns: 1 if str starts with prefix, 0 otherwise
 */
static __always_inline int str_starts_with(const char *str, const char *prefix)
{
    #pragma unroll
    for (int i = 0; i < 32; i++) {
        if (prefix[i] == '\0') {
            return 1;  /* Prefix exhausted = match */
        }
        if (str[i] != prefix[i]) {
            return 0;  /* Mismatch */
        }
    }
    return 1;  /* Prefix >= 32 chars, assume match on first 32 */
}

/*
 * str_equals - Check if two strings are equal
 * 
 * @s1: First string
 * @s2: Second string  
 * @max_len: Maximum length to compare
 * 
 * Returns: 1 if equal, 0 otherwise
 */
static __always_inline int str_equals(const char *s1, const char *s2, int max_len)
{
    #pragma unroll
    for (int i = 0; i < 64 && i < max_len; i++) {
        if (s1[i] != s2[i]) {
            return 0;
        }
        if (s1[i] == '\0') {
            return 1;  /* Both reached end */
        }
    }
    return 1;
}

/*
 * str_len - Get length of string (bounded)
 * 
 * @str: The string to measure
 * @max_len: Maximum length to scan
 * 
 * Returns: Length of string (up to max_len)
 */
static __always_inline int str_len(const char *str, int max_len)
{
    int len = 0;
    #pragma unroll
    for (int i = 0; i < 256 && i < max_len; i++) {
        if (str[i] == '\0') {
            break;
        }
        len++;
    }
    return len;
}

/*
 * str_ends_with - Check if string ends with suffix
 * 
 * @str: The string to check
 * @str_len: Length of str
 * @suffix: The suffix to look for
 * @suffix_len: Length of suffix
 * 
 * Returns: 1 if str ends with suffix, 0 otherwise
 */
static __always_inline int str_ends_with(
    const char *str, int slen,
    const char *suffix, int suffix_len)
{
    if (suffix_len > slen) {
        return 0;
    }
    
    int start = slen - suffix_len;
    
    #pragma unroll
    for (int i = 0; i < 32 && i < suffix_len; i++) {
        if (str[start + i] != suffix[i]) {
            return 0;
        }
    }
    return 1;
}

/*
 * copy_string - Copy string with bounds checking
 * 
 * @dst: Destination buffer
 * @src: Source string
 * @max_len: Maximum bytes to copy
 */
static __always_inline void copy_string(char *dst, const char *src, int max_len)
{
    #pragma unroll
    for (int i = 0; i < 64 && i < max_len; i++) {
        dst[i] = src[i];
        if (src[i] == '\0') {
            break;
        }
    }
}

/*
 * is_path_proc_fd - Check if path looks like /proc/*/fd/* or /dev/fd/*
 * 
 * These paths indicate potential memfd/anonymous file execution.
 * 
 * @path: The path to check
 * 
 * Returns: 1 if matches pattern, 0 otherwise
 */
static __always_inline int is_path_proc_fd(const char *path)
{
    /* Check for /proc/ prefix */
    if (path[0] == '/' && path[1] == 'p' && path[2] == 'r' &&
        path[3] == 'o' && path[4] == 'c' && path[5] == '/') {
        return 1;
    }
    
    /* Check for /dev/fd/ prefix */
    if (path[0] == '/' && path[1] == 'd' && path[2] == 'e' &&
        path[3] == 'v' && path[4] == '/' && path[5] == 'f' &&
        path[6] == 'd' && path[7] == '/') {
        return 1;
    }
    
    return 0;
}

/*
 * is_busybox_path - Check if path ends with /busybox
 * 
 * @path: The path to check
 * @path_len: Length of path
 * 
 * Returns: 1 if path is busybox, 0 otherwise
 */
static __always_inline int is_busybox_path(const char *path, int path_len)
{
    /* Check for /busybox suffix */
    const char busybox[] = "/busybox";
    const int busybox_len = 8;
    
    if (path_len < busybox_len) {
        return 0;
    }
    
    return str_ends_with(path, path_len, busybox, busybox_len);
}

#endif /* __LOTL_COMMON_H */

