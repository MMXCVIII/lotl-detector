"""Unit tests for rule engine."""

import tempfile
from pathlib import Path

import pytest

from lotl_detector.core.models import AlertType, EventType, ExecEvent, SeverityLevel
from lotl_detector.detection.rules.engine import (
    RegexTimeoutError,
    RuleEngine,
    Tier1Rule,
    Tier2Rule,
    safe_regex_match,
)


class TestSafeRegexMatch:
    """Tests for ReDoS-protected regex matching."""

    def test_simple_match(self) -> None:
        """Test simple regex match works."""
        import re

        pattern = re.compile(r"hello.*world")
        result = safe_regex_match(pattern, "hello there world")

        assert result is not None
        assert result.group() == "hello there world"

    def test_no_match(self) -> None:
        """Test no match returns None."""
        import re

        pattern = re.compile(r"xyz")
        result = safe_regex_match(pattern, "abc")

        assert result is None

    def test_complex_pattern(self) -> None:
        """Test complex but safe pattern."""
        import re

        pattern = re.compile(r"base64\s+(-d|--decode)")
        result = safe_regex_match(pattern, "base64 -d input.txt")

        assert result is not None


class TestTier2Rule:
    """Tests for Tier 2 detection rules."""

    def test_compile_patterns(self) -> None:
        """Test regex pattern compilation."""
        rule = Tier2Rule(
            id="test",
            name="Test Rule",
            description="Test",
            mitre="T1059",
            severity="high",
            binaries=["/usr/bin/test"],
            args_pattern=r"--dangerous",
        )
        rule.compile_patterns()

        assert rule._compiled_pattern is not None
        assert len(rule._compiled_binaries) == 1

    def test_compile_wildcard_binary(self) -> None:
        """Test wildcard binary pattern compilation."""
        rule = Tier2Rule(
            id="test",
            name="Test Rule",
            description="Test",
            mitre="T1059",
            severity="high",
            binaries=["/usr/bin/python*"],
            args_pattern=None,
        )
        rule.compile_patterns()

        assert len(rule._compiled_binaries) == 1
        # Should match python3, python3.12, etc.
        assert rule._compiled_binaries[0].search("/usr/bin/python3.12")


class TestRuleEngine:
    """Tests for the rule engine."""

    @pytest.fixture
    def rules_dir(self, tmp_path: Path) -> Path:
        """Create a temporary rules directory."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()

        # Tier 1 rules
        (rules_dir / "tier1_blocklist.yaml").write_text("""
version: 1
blocked_paths:
  - path: /usr/bin/nc
    reason: netcat
    mitre: T1059.004
""")

        # Tier 2 rules
        (rules_dir / "tier2_patterns.yaml").write_text("""
version: 1
rules:
  - id: test-base64
    name: Base64 Decode
    description: Detects base64 decoding
    mitre: T1027
    severity: high
    binaries:
      - /usr/bin/base64
    args_pattern: '-d|--decode'
    enabled: true
settings:
  case_sensitive: false
""")

        # Ancestry rules
        (rules_dir / "ancestry_allowlist.yaml").write_text("""
version: 1
rules:
  - id: test-apt
    name: APT
    description: Allow apt descendants
    ancestors:
      - /usr/bin/apt
    window_seconds: 300
    allowed_descendants:
      - /bin/sh
    enabled: true
""")

        return rules_dir

    def test_load_rules(self, rules_dir: Path) -> None:
        """Test loading rules from files."""
        engine = RuleEngine(rules_dir)
        engine.load_rules()

        assert len(engine.tier1_rules) == 1
        assert len(engine.tier2_rules) == 1
        assert len(engine.ancestry_rules) == 1

    def test_tier1_lookup(self, rules_dir: Path) -> None:
        """Test Tier 1 path lookup."""
        engine = RuleEngine(rules_dir)
        engine.load_rules()

        rule = engine.is_tier1_blocked("/usr/bin/nc")
        assert rule is not None
        assert rule.mitre == "T1059.004"

        rule = engine.is_tier1_blocked("/usr/bin/safe")
        assert rule is None

    def test_evaluate_tier2(self, rules_dir: Path) -> None:
        """Test Tier 2 rule evaluation."""
        engine = RuleEngine(rules_dir)
        engine.load_rules()

        # Create a matching event
        event = ExecEvent(
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
            comm="base64",
            filename="/usr/bin/base64",
            args=["base64", "-d", "input.txt"],
            busybox_applet="",
            env_ld_preload="",
            env_ld_library_path="",
        )

        alerts = engine.evaluate_tier2(event)
        assert len(alerts) == 1
        assert alerts[0].rule_id == "test-base64"

    def test_evaluate_tier2_no_match(self, rules_dir: Path) -> None:
        """Test Tier 2 with non-matching event."""
        engine = RuleEngine(rules_dir)
        engine.load_rules()

        event = ExecEvent(
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
            comm="ls",
            filename="/bin/ls",
            args=["ls", "-la"],
            busybox_applet="",
            env_ld_preload="",
            env_ld_library_path="",
        )

        alerts = engine.evaluate_tier2(event)
        assert len(alerts) == 0

