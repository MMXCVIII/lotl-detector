"""
Rule Engine for LOTL Detector.

Evaluates events against detection rules with:
- Safe YAML loading
- Pre-compiled regex patterns
- 50ms timeout per regex (ReDoS protection)
"""

from __future__ import annotations

import fnmatch
import logging
import re
import signal
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from lotl_detector.core.models import AlertEvent, AlertType, ExecEvent, SeverityLevel

logger = logging.getLogger(__name__)


class RuleEngineError(Exception):
    """Raised for rule engine errors."""


# ─────────────────────────────────────────────────────────────────────────────
# ReDoS Protection
# ─────────────────────────────────────────────────────────────────────────────

REGEX_TIMEOUT_MS = 50


class RegexTimeoutError(Exception):
    """Raised when regex execution times out."""


def _timeout_handler(signum, frame):
    """Signal handler for regex timeout."""
    raise RegexTimeoutError("Regex execution timed out")


def safe_regex_match(
    pattern: re.Pattern,
    text: str,
    timeout_ms: int = REGEX_TIMEOUT_MS,
) -> re.Match | None:
    """
    Execute regex match with timeout protection.

    Uses threading-based timeout (signal-based doesn't work in threads).

    Args:
        pattern: Compiled regex pattern.
        text: Text to match against.
        timeout_ms: Timeout in milliseconds.

    Returns:
        Match object if matched, None otherwise.

    Raises:
        RegexTimeoutError: If regex execution times out.
    """
    result = [None]
    exception = [None]

    def do_match():
        try:
            result[0] = pattern.search(text)
        except Exception as e:
            exception[0] = e

    thread = threading.Thread(target=do_match)
    thread.start()
    thread.join(timeout=timeout_ms / 1000)

    if thread.is_alive():
        # Thread is still running - timeout
        # Note: We can't actually kill the thread, but we return immediately
        # The thread will eventually complete or be killed when process exits
        logger.warning(f"Regex timeout on pattern: {pattern.pattern[:50]}...")
        raise RegexTimeoutError("Regex execution timed out")

    if exception[0]:
        raise exception[0]

    return result[0]


# ─────────────────────────────────────────────────────────────────────────────
# Rule Data Classes
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class Tier1Rule:
    """Tier 1 blocklist rule (kernel blocking)."""

    path: str
    reason: str
    mitre: str = ""
    inode: int | None = None


@dataclass
class Tier2Rule:
    """Tier 2 detection rule (userspace regex)."""

    id: str
    name: str
    description: str
    mitre: str
    severity: str
    binaries: list[str]
    args_pattern: str | None
    busybox_applets: list[str] = field(default_factory=list)
    enabled: bool = True
    _compiled_pattern: re.Pattern | None = field(default=None, repr=False)
    _compiled_binaries: list[re.Pattern] = field(default_factory=list, repr=False)

    def compile_patterns(self, case_sensitive: bool = False) -> None:
        """Compile regex patterns for efficient matching."""
        flags = 0 if case_sensitive else re.IGNORECASE

        if self.args_pattern:
            try:
                self._compiled_pattern = re.compile(self.args_pattern, flags)
            except re.error as e:
                logger.error(f"Invalid regex in rule {self.id}: {e}")
                self._compiled_pattern = None

        # Compile binary patterns (support wildcards)
        self._compiled_binaries = []
        for binary in self.binaries:
            if "*" in binary:
                # Convert glob to regex
                regex = fnmatch.translate(binary)
                try:
                    self._compiled_binaries.append(re.compile(regex))
                except re.error:
                    pass
            else:
                # Exact match
                self._compiled_binaries.append(re.compile(re.escape(binary) + "$"))


@dataclass
class AncestryRule:
    """Ancestry allowlist rule."""

    id: str
    name: str
    description: str
    ancestors: list[str]
    window_seconds: int
    allowed_descendants: list[str] = field(default_factory=list)
    blocked_descendants: list[str] = field(default_factory=list)
    enabled: bool = True


# ─────────────────────────────────────────────────────────────────────────────
# Rule Engine
# ─────────────────────────────────────────────────────────────────────────────


class RuleEngine:
    """
    Detection rule engine.

    Loads rules from YAML files and evaluates events against them.
    """

    def __init__(self, rules_dir: Path | str | None = None) -> None:
        """
        Initialize rule engine.

        Args:
            rules_dir: Directory containing rule files.
        """
        self.rules_dir = Path(rules_dir) if rules_dir else Path("rules")
        self.tier1_rules: list[Tier1Rule] = []
        self.tier2_rules: list[Tier2Rule] = []
        self.ancestry_rules: list[AncestryRule] = []
        self._loaded = False

    def load_rules(self) -> None:
        """
        Load all rule files.

        Raises:
            RuleEngineError: If rules cannot be loaded.
        """
        self._load_tier1_rules()
        self._load_tier2_rules()
        self._load_ancestry_rules()
        self._loaded = True
        logger.info(
            f"Loaded rules: {len(self.tier1_rules)} tier1, "
            f"{len(self.tier2_rules)} tier2, {len(self.ancestry_rules)} ancestry"
        )

    def _load_yaml_safe(self, filename: str) -> dict[str, Any]:
        """Load YAML file safely."""
        filepath = self.rules_dir / filename
        if not filepath.exists():
            logger.warning(f"Rule file not found: {filepath}")
            return {}

        try:
            with open(filepath, encoding="utf-8") as f:
                # CRITICAL: Use safe_load to prevent code execution
                data = yaml.safe_load(f)
            return data or {}
        except yaml.YAMLError as e:
            logger.error(f"YAML error in {filepath}: {e}")
            return {}
        except OSError as e:
            logger.error(f"Cannot read {filepath}: {e}")
            return {}

    def _load_tier1_rules(self) -> None:
        """Load Tier 1 blocklist rules."""
        data = self._load_yaml_safe("tier1_blocklist.yaml")

        for entry in data.get("blocked_paths", []):
            self.tier1_rules.append(
                Tier1Rule(
                    path=entry.get("path", ""),
                    reason=entry.get("reason", ""),
                    mitre=entry.get("mitre", ""),
                )
            )

    def _load_tier2_rules(self) -> None:
        """Load Tier 2 detection rules."""
        data = self._load_yaml_safe("tier2_patterns.yaml")
        settings = data.get("settings", {})
        case_sensitive = settings.get("case_sensitive", False)

        for entry in data.get("rules", []):
            rule = Tier2Rule(
                id=entry.get("id", ""),
                name=entry.get("name", ""),
                description=entry.get("description", ""),
                mitre=entry.get("mitre", ""),
                severity=entry.get("severity", "medium"),
                binaries=entry.get("binaries", []),
                args_pattern=entry.get("args_pattern"),
                busybox_applets=entry.get("busybox_applets", []),
                enabled=entry.get("enabled", True),
            )
            rule.compile_patterns(case_sensitive)
            self.tier2_rules.append(rule)

    def _load_ancestry_rules(self) -> None:
        """Load ancestry allowlist rules."""
        data = self._load_yaml_safe("ancestry_allowlist.yaml")

        for entry in data.get("rules", []):
            self.ancestry_rules.append(
                AncestryRule(
                    id=entry.get("id", ""),
                    name=entry.get("name", ""),
                    description=entry.get("description", ""),
                    ancestors=entry.get("ancestors", []),
                    window_seconds=entry.get("window_seconds", 300),
                    allowed_descendants=entry.get("allowed_descendants", []),
                    blocked_descendants=entry.get("blocked_descendants", []),
                    enabled=entry.get("enabled", True),
                )
            )

    def reload_rules(self) -> None:
        """Reload all rules from files."""
        self.tier1_rules.clear()
        self.tier2_rules.clear()
        self.ancestry_rules.clear()
        self.load_rules()

    def get_tier1_paths(self) -> list[str]:
        """Get all Tier 1 blocked paths."""
        return [r.path for r in self.tier1_rules if r.path]

    def is_tier1_blocked(self, path: str) -> Tier1Rule | None:
        """
        Check if a path is blocked by Tier 1 rules.

        Args:
            path: Path to check.

        Returns:
            Matching rule if blocked, None otherwise.
        """
        for rule in self.tier1_rules:
            if rule.path == path:
                return rule
        return None

    def evaluate_tier2(self, event: ExecEvent) -> list[AlertEvent]:
        """
        Evaluate event against Tier 2 detection rules.

        Args:
            event: Exec event to evaluate.

        Returns:
            List of alerts for matched rules.
        """
        if not self._loaded:
            self.load_rules()

        alerts = []

        for rule in self.tier2_rules:
            if not rule.enabled:
                continue

            # Check binary match
            binary_match = False
            for pattern in rule._compiled_binaries:
                if pattern.search(event.filename):
                    binary_match = True
                    break

            if not binary_match:
                continue

            # Check busybox applet match
            if rule.busybox_applets and event.is_busybox:
                if event.busybox_applet not in rule.busybox_applets:
                    continue

            # Check args pattern
            if rule._compiled_pattern:
                args_text = " ".join(event.args)
                try:
                    match = safe_regex_match(rule._compiled_pattern, args_text)
                    if not match:
                        continue
                except RegexTimeoutError:
                    logger.warning(f"Regex timeout for rule {rule.id}")
                    continue

            # Rule matched - create alert
            severity = SeverityLevel[rule.severity.upper()]
            alert = AlertEvent(
                timestamp_ns=event.timestamp_ns,
                pid=event.pid,
                uid=event.uid,
                alert_type=AlertType.BLOCKED_EXEC,
                severity=severity,
                target_pid=0,
                comm=event.comm,
                filename=event.filename,
                rule_id=rule.id,
                description=rule.description,
                mitre_technique=rule.mitre,
            )
            alerts.append(alert)

        return alerts

    def get_ancestry_rule(self, ancestor_path: str) -> AncestryRule | None:
        """
        Get ancestry rule for an ancestor path.

        Args:
            ancestor_path: Path of potential ancestor.

        Returns:
            Matching ancestry rule if found.
        """
        for rule in self.ancestry_rules:
            if not rule.enabled:
                continue

            for pattern in rule.ancestors:
                if "*" in pattern:
                    if fnmatch.fnmatch(ancestor_path, pattern):
                        return rule
                elif ancestor_path == pattern:
                    return rule

        return None

    def is_allowed_descendant(
        self, rule: AncestryRule, descendant_path: str
    ) -> bool:
        """
        Check if a descendant is allowed by an ancestry rule.

        Args:
            rule: The ancestry rule.
            descendant_path: Path of the descendant.

        Returns:
            True if allowed, False if blocked.
        """
        # Check blocked list first (takes priority)
        for pattern in rule.blocked_descendants:
            if "*" in pattern:
                if fnmatch.fnmatch(descendant_path, pattern):
                    return False
            elif descendant_path == pattern:
                return False

        # Check allowed list
        if not rule.allowed_descendants:
            return True  # Empty list = allow all

        for pattern in rule.allowed_descendants:
            if "*" in pattern:
                if fnmatch.fnmatch(descendant_path, pattern):
                    return True
            elif descendant_path == pattern:
                return True

        return False

