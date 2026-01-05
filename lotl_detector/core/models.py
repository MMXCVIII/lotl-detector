"""
Event models for LOTL Detector.

Defines the data structures used for BPF events and alerts,
with C-compatible ctypes for bcc integration.
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass, field
from enum import IntEnum
from typing import ClassVar


# ─────────────────────────────────────────────────────────────────────────────
# Constants (must match common.h)
# ─────────────────────────────────────────────────────────────────────────────

MAX_FILENAME_LEN = 256
MAX_ARGS = 6
MAX_ARG_LEN = 128
MAX_ENV_VAL_LEN = 128
MAX_COMM_LEN = 16
MAX_APPLET_LEN = 32


class EventType(IntEnum):
    """Event types from BPF programs."""

    EXECVE = 1
    MEMFD_CREATE = 2
    NETWORK = 3
    MODULE = 4
    PTRACE = 5
    EXIT = 6


class AlertType(IntEnum):
    """Alert types from BPF programs."""

    NONE = 0
    MEMFD_CREATE = 1
    MEMFD_EXEC = 2
    LD_PRELOAD = 3
    KERNEL_MODULE = 4
    FOREIGN_BPF = 5
    PTRACE_ATTACH = 6
    PROC_MEM_WRITE = 7
    FORK_BOMB = 8
    BLOCKED_EXEC = 9
    BLOCKED_USER = 10


class SeverityLevel(IntEnum):
    """Severity levels for alerts."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class OperationalMode(IntEnum):
    """Operational modes for the detector."""

    BOOTSTRAP = 0
    LEARN = 1
    ENFORCE = 2
    PARANOID = 3


# ─────────────────────────────────────────────────────────────────────────────
# C-Compatible Structures for bcc
# ─────────────────────────────────────────────────────────────────────────────


class ExecEventCType(ctypes.Structure):
    """C-compatible structure matching struct exec_event in common.h."""

    _fields_ = [
        ("timestamp_ns", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("ppid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("gid", ctypes.c_uint32),
        ("start_time_ns", ctypes.c_uint64),
        ("inode", ctypes.c_uint64),
        ("type", ctypes.c_uint32),
        ("blocked", ctypes.c_uint8),
        ("is_memfd", ctypes.c_uint8),
        ("is_busybox", ctypes.c_uint8),
        ("is_stdin_exec", ctypes.c_uint8),
        ("args_truncated", ctypes.c_uint8),
        ("args_count_exceeded", ctypes.c_uint8),
        ("env_truncated", ctypes.c_uint8),
        ("rate_limited", ctypes.c_uint8),
        ("comm", ctypes.c_char * MAX_COMM_LEN),
        ("filename", ctypes.c_char * MAX_FILENAME_LEN),
        ("args", (ctypes.c_char * MAX_ARG_LEN) * MAX_ARGS),
        ("busybox_applet", ctypes.c_char * MAX_APPLET_LEN),
        ("env_ld_preload", ctypes.c_char * MAX_ENV_VAL_LEN),
        ("env_ld_library_path", ctypes.c_char * MAX_ENV_VAL_LEN),
    ]


class AlertEventCType(ctypes.Structure):
    """C-compatible structure matching struct alert_event in common.h."""

    _fields_ = [
        ("timestamp_ns", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("type", ctypes.c_uint32),
        ("severity", ctypes.c_uint32),
        ("target_pid", ctypes.c_uint32),
        ("comm", ctypes.c_char * MAX_COMM_LEN),
        ("filename", ctypes.c_char * MAX_FILENAME_LEN),
    ]


# ─────────────────────────────────────────────────────────────────────────────
# Python Data Classes
# ─────────────────────────────────────────────────────────────────────────────


def _decode_str(data: bytes) -> str:
    """Safely decode bytes to string, handling null terminators."""
    if isinstance(data, bytes):
        # Find null terminator
        null_idx = data.find(b"\x00")
        if null_idx >= 0:
            data = data[:null_idx]
        try:
            return data.decode("utf-8", errors="replace")
        except Exception:
            return data.decode("latin-1", errors="replace")
    return str(data)


@dataclass
class ExecEvent:
    """Parsed execve event."""

    timestamp_ns: int
    pid: int
    ppid: int
    uid: int
    gid: int
    start_time_ns: int
    inode: int
    event_type: EventType
    blocked: bool
    is_memfd: bool
    is_busybox: bool
    is_stdin_exec: bool
    args_truncated: bool
    args_count_exceeded: bool
    env_truncated: bool
    rate_limited: bool
    comm: str
    filename: str
    args: list[str]
    busybox_applet: str
    env_ld_preload: str
    env_ld_library_path: str

    # Validation limits
    MAX_PATH_LEN: ClassVar[int] = 4096
    MAX_ARG_TOTAL_LEN: ClassVar[int] = 131072  # 128KB

    @classmethod
    def from_ctype(cls, event: ExecEventCType) -> "ExecEvent":
        """Create ExecEvent from C structure."""
        args = [_decode_str(event.args[i]) for i in range(MAX_ARGS)]
        # Filter empty args
        args = [a for a in args if a]

        return cls(
            timestamp_ns=event.timestamp_ns,
            pid=event.pid,
            ppid=event.ppid,
            uid=event.uid,
            gid=event.gid,
            start_time_ns=event.start_time_ns,
            inode=event.inode,
            event_type=EventType(event.type),
            blocked=bool(event.blocked),
            is_memfd=bool(event.is_memfd),
            is_busybox=bool(event.is_busybox),
            is_stdin_exec=bool(event.is_stdin_exec),
            args_truncated=bool(event.args_truncated),
            args_count_exceeded=bool(event.args_count_exceeded),
            env_truncated=bool(event.env_truncated),
            rate_limited=bool(event.rate_limited),
            comm=_decode_str(event.comm),
            filename=_decode_str(event.filename),
            args=args,
            busybox_applet=_decode_str(event.busybox_applet),
            env_ld_preload=_decode_str(event.env_ld_preload),
            env_ld_library_path=_decode_str(event.env_ld_library_path),
        )

    def validate(self) -> list[str]:
        """
        Validate event data for sanity.

        Returns:
            List of validation error messages (empty if valid).
        """
        errors = []

        # PID validation
        if self.pid <= 0 or self.pid > 4194304:  # Max PID on Linux
            errors.append(f"Invalid PID: {self.pid}")

        # Path length validation
        if len(self.filename) > self.MAX_PATH_LEN:
            errors.append(f"Filename too long: {len(self.filename)}")

        # Path character validation (basic)
        if self.filename and "\x00" in self.filename:
            errors.append("Filename contains null byte")

        # Total args length check
        total_args_len = sum(len(a) for a in self.args)
        if total_args_len > self.MAX_ARG_TOTAL_LEN:
            errors.append(f"Total args too long: {total_args_len}")

        return errors

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "timestamp_ns": self.timestamp_ns,
            "pid": self.pid,
            "ppid": self.ppid,
            "uid": self.uid,
            "gid": self.gid,
            "start_time_ns": self.start_time_ns,
            "inode": self.inode,
            "event_type": self.event_type.name,
            "blocked": self.blocked,
            "is_memfd": self.is_memfd,
            "is_busybox": self.is_busybox,
            "is_stdin_exec": self.is_stdin_exec,
            "args_truncated": self.args_truncated,
            "rate_limited": self.rate_limited,
            "comm": self.comm,
            "filename": self.filename,
            "args": self.args,
            "busybox_applet": self.busybox_applet,
            "env_ld_preload": self.env_ld_preload,
            "env_ld_library_path": self.env_ld_library_path,
        }


@dataclass
class AlertEvent:
    """Parsed alert event."""

    timestamp_ns: int
    pid: int
    uid: int
    alert_type: AlertType
    severity: SeverityLevel
    target_pid: int
    comm: str
    filename: str
    rule_id: str = ""
    description: str = ""
    mitre_technique: str = ""

    @classmethod
    def from_ctype(cls, event: AlertEventCType) -> "AlertEvent":
        """Create AlertEvent from C structure."""
        return cls(
            timestamp_ns=event.timestamp_ns,
            pid=event.pid,
            uid=event.uid,
            alert_type=AlertType(event.type),
            severity=SeverityLevel(event.severity),
            target_pid=event.target_pid,
            comm=_decode_str(event.comm),
            filename=_decode_str(event.filename),
        )

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "timestamp_ns": self.timestamp_ns,
            "pid": self.pid,
            "uid": self.uid,
            "alert_type": self.alert_type.name,
            "severity": self.severity.name,
            "target_pid": self.target_pid,
            "comm": self.comm,
            "filename": self.filename,
            "rule_id": self.rule_id,
            "description": self.description,
            "mitre_technique": self.mitre_technique,
        }


@dataclass
class Decision:
    """Detection decision for an event."""

    event: ExecEvent
    should_block: bool = False
    alerts: list[AlertEvent] = field(default_factory=list)
    matched_rules: list[str] = field(default_factory=list)
    anomaly_score: float = 0.0
    ancestry_allowed: bool = False

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "event": self.event.to_dict(),
            "should_block": self.should_block,
            "alerts": [a.to_dict() for a in self.alerts],
            "matched_rules": self.matched_rules,
            "anomaly_score": self.anomaly_score,
            "ancestry_allowed": self.ancestry_allowed,
        }

