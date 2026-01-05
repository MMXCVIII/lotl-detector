"""Unit tests for data models."""

import pytest

from lotl_detector.core.models import (
    AlertEvent,
    AlertType,
    EventType,
    ExecEvent,
    OperationalMode,
    SeverityLevel,
)


class TestExecEvent:
    """Tests for ExecEvent model."""

    def test_validate_valid_event(self) -> None:
        """Test validation of valid event."""
        event = ExecEvent(
            timestamp_ns=1234567890,
            pid=1234,
            ppid=1,
            uid=1000,
            gid=1000,
            start_time_ns=1234567890,
            inode=12345,
            event_type=EventType.EXECVE,
            blocked=False,
            is_memfd=False,
            is_busybox=False,
            is_stdin_exec=False,
            args_truncated=False,
            args_count_exceeded=False,
            env_truncated=False,
            rate_limited=False,
            comm="ls",
            filename="/bin/ls",
            args=["ls", "-la"],
            busybox_applet="",
            env_ld_preload="",
            env_ld_library_path="",
        )

        errors = event.validate()
        assert len(errors) == 0

    def test_validate_invalid_pid(self) -> None:
        """Test validation catches invalid PID."""
        event = ExecEvent(
            timestamp_ns=0,
            pid=-1,  # Invalid
            ppid=1,
            uid=1000,
            gid=1000,
            start_time_ns=0,
            inode=0,
            event_type=EventType.EXECVE,
            blocked=False,
            is_memfd=False,
            is_busybox=False,
            is_stdin_exec=False,
            args_truncated=False,
            args_count_exceeded=False,
            env_truncated=False,
            rate_limited=False,
            comm="",
            filename="",
            args=[],
            busybox_applet="",
            env_ld_preload="",
            env_ld_library_path="",
        )

        errors = event.validate()
        assert len(errors) > 0
        assert any("Invalid PID" in e for e in errors)

    def test_to_dict(self) -> None:
        """Test serialization to dictionary."""
        event = ExecEvent(
            timestamp_ns=1234567890,
            pid=1234,
            ppid=1,
            uid=1000,
            gid=1000,
            start_time_ns=1234567890,
            inode=12345,
            event_type=EventType.EXECVE,
            blocked=False,
            is_memfd=False,
            is_busybox=False,
            is_stdin_exec=False,
            args_truncated=False,
            args_count_exceeded=False,
            env_truncated=False,
            rate_limited=False,
            comm="ls",
            filename="/bin/ls",
            args=["ls", "-la"],
            busybox_applet="",
            env_ld_preload="",
            env_ld_library_path="",
        )

        d = event.to_dict()

        assert d["pid"] == 1234
        assert d["filename"] == "/bin/ls"
        assert d["event_type"] == "EXECVE"
        assert d["args"] == ["ls", "-la"]


class TestAlertEvent:
    """Tests for AlertEvent model."""

    def test_to_dict(self) -> None:
        """Test serialization to dictionary."""
        alert = AlertEvent(
            timestamp_ns=1234567890,
            pid=1234,
            uid=1000,
            alert_type=AlertType.BLOCKED_EXEC,
            severity=SeverityLevel.HIGH,
            target_pid=0,
            comm="nc",
            filename="/usr/bin/nc",
            rule_id="tier1-nc",
            description="Netcat blocked",
            mitre_technique="T1059.004",
        )

        d = alert.to_dict()

        assert d["pid"] == 1234
        assert d["alert_type"] == "BLOCKED_EXEC"
        assert d["severity"] == "HIGH"
        assert d["rule_id"] == "tier1-nc"


class TestOperationalMode:
    """Tests for OperationalMode enum."""

    def test_mode_ordering(self) -> None:
        """Test that modes have correct ordering."""
        assert OperationalMode.BOOTSTRAP < OperationalMode.LEARN
        assert OperationalMode.LEARN < OperationalMode.ENFORCE
        assert OperationalMode.ENFORCE < OperationalMode.PARANOID

    def test_mode_from_string(self) -> None:
        """Test creating mode from string."""
        assert OperationalMode["LEARN"] == OperationalMode.LEARN
        assert OperationalMode["ENFORCE"] == OperationalMode.ENFORCE

