"""
Ancestry checking for LOTL Detector.

Manages the ancestry allowlist for package managers and
other legitimate processes that spawn children.
"""

from __future__ import annotations

import logging
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any

from lotl_detector.core.database import Database
from lotl_detector.detection.rules.engine import AncestryRule, RuleEngine

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class AncestryConfig:
    """Ancestry checking configuration."""

    # Maximum window for ancestry (hard limit)
    max_window_seconds: int = 600  # 10 minutes

    # Default window if not specified
    default_window_seconds: int = 300  # 5 minutes

    # Maximum depth to traverse process tree
    max_ancestry_depth: int = 10

    # Log when ancestry bypass is used
    log_bypasses: bool = True

    # Maximum size of in-memory LRU cache
    max_cache_size: int = 10000


# ─────────────────────────────────────────────────────────────────────────────
# LRU Cache for Process Tree
# ─────────────────────────────────────────────────────────────────────────────


class LRUCache(OrderedDict):
    """
    LRU cache with size limit.

    Prevents unbounded memory growth in process tree.
    """

    def __init__(self, maxsize: int = 10000) -> None:
        """Initialize with maximum size."""
        super().__init__()
        self.maxsize = maxsize

    def __getitem__(self, key):
        """Get item and move to end (most recently used)."""
        value = super().__getitem__(key)
        self.move_to_end(key)
        return value

    def __setitem__(self, key, value):
        """Set item, evicting oldest if at capacity."""
        if key in self:
            self.move_to_end(key)
        super().__setitem__(key, value)

        while len(self) > self.maxsize:
            oldest = next(iter(self))
            del self[oldest]


# ─────────────────────────────────────────────────────────────────────────────
# Ancestry Checker
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class ProcessInfo:
    """Process information for ancestry checking."""

    pid: int
    ppid: int
    filename: str
    start_time: float
    ancestry_allowed: bool = False
    ancestry_rule_id: str | None = None
    ancestry_expiry: float = 0.0


class AncestryChecker:
    """
    Manages ancestry-based allowlisting.

    Tracks process relationships and determines if a process
    should be allowed based on its ancestry.
    """

    def __init__(
        self,
        database: Database,
        rule_engine: RuleEngine,
        config: AncestryConfig | None = None,
    ) -> None:
        """
        Initialize ancestry checker.

        Args:
            database: Database connection for persistence.
            rule_engine: Rule engine with ancestry rules.
            config: Ancestry configuration.
        """
        self.db = database
        self.rules = rule_engine
        self.config = config or AncestryConfig()

        # In-memory cache with LRU eviction
        self._process_cache: LRUCache = LRUCache(self.config.max_cache_size)

    def record_process(
        self,
        pid: int,
        ppid: int,
        filename: str,
        start_time: float | None = None,
    ) -> None:
        """
        Record a new process.

        Args:
            pid: Process ID.
            ppid: Parent process ID.
            filename: Executable path.
            start_time: Process start time.
        """
        if start_time is None:
            start_time = time.time()

        # Check if this process matches an ancestry rule
        rule = self.rules.get_ancestry_rule(filename)
        ancestry_allowed = False
        ancestry_rule_id = None
        ancestry_expiry = 0.0

        if rule:
            # This is an ancestor process - enable allowance for descendants
            window = min(rule.window_seconds, self.config.max_window_seconds)
            ancestry_allowed = True
            ancestry_rule_id = rule.id
            ancestry_expiry = start_time + window

            if self.config.log_bypasses:
                logger.info(
                    f"Ancestry allowance started: PID {pid} ({filename}) "
                    f"rule={rule.id} window={window}s"
                )

        else:
            # Check if parent has ancestry allowance
            parent_info = self._get_process_info(ppid)
            if parent_info and parent_info.ancestry_allowed:
                now = time.time()
                if parent_info.ancestry_expiry > now:
                    # Inherit ancestry allowance
                    ancestry_allowed = True
                    ancestry_rule_id = parent_info.ancestry_rule_id
                    ancestry_expiry = parent_info.ancestry_expiry

        # Store in cache
        process_info = ProcessInfo(
            pid=pid,
            ppid=ppid,
            filename=filename,
            start_time=start_time,
            ancestry_allowed=ancestry_allowed,
            ancestry_rule_id=ancestry_rule_id,
            ancestry_expiry=ancestry_expiry,
        )
        self._process_cache[pid] = process_info

        # Also persist to database
        self.db.update_process(
            pid=pid,
            ppid=ppid,
            uid=0,  # Will be updated when we have it
            comm=filename.rsplit("/", 1)[-1][:16],
            filename=filename,
            start_time=start_time,
            ancestry_allowed=ancestry_allowed,
            ancestry_expiry=ancestry_expiry,
        )

    def remove_process(self, pid: int) -> None:
        """Remove a process from tracking."""
        if pid in self._process_cache:
            del self._process_cache[pid]
        self.db.remove_process(pid)

    def _get_process_info(self, pid: int) -> ProcessInfo | None:
        """Get process info from cache or database."""
        # Check cache first
        if pid in self._process_cache:
            return self._process_cache[pid]

        # Fall back to database
        db_info = self.db.get_process(pid)
        if db_info:
            process_info = ProcessInfo(
                pid=db_info["pid"],
                ppid=db_info["ppid"],
                filename=db_info["filename"],
                start_time=db_info["start_time"],
                ancestry_allowed=bool(db_info.get("ancestry_allowed", 0)),
                ancestry_expiry=db_info.get("ancestry_expiry", 0),
            )
            self._process_cache[pid] = process_info
            return process_info

        return None

    def is_allowed(
        self,
        pid: int,
        filename: str,
        ppid: int | None = None,
    ) -> tuple[bool, str | None]:
        """
        Check if a process is allowed by ancestry.

        Args:
            pid: Process ID.
            filename: Executable path being executed.
            ppid: Parent process ID (optional, looked up if not provided).

        Returns:
            Tuple of (is_allowed, rule_id or None).
        """
        now = time.time()

        # Get process info
        process_info = self._get_process_info(pid)
        if not process_info:
            # Process not in tree - check parent
            if ppid is not None:
                process_info = self._get_process_info(ppid)
                if not process_info:
                    return (False, None)
            else:
                return (False, None)

        # Check if ancestry allowance is still valid
        if not process_info.ancestry_allowed:
            return (False, None)

        if process_info.ancestry_expiry <= now:
            return (False, None)

        # Get the ancestry rule
        rule_id = process_info.ancestry_rule_id
        if not rule_id:
            return (False, None)

        # Find the rule
        rule = None
        for r in self.rules.ancestry_rules:
            if r.id == rule_id:
                rule = r
                break

        if not rule:
            return (False, None)

        # Check if this filename is allowed/blocked by the rule
        if not self.rules.is_allowed_descendant(rule, filename):
            if self.config.log_bypasses:
                logger.warning(
                    f"Blocked descendant: PID {pid} ({filename}) "
                    f"not allowed by rule {rule_id}"
                )
            return (False, rule_id)

        if self.config.log_bypasses:
            logger.info(
                f"Ancestry bypass: PID {pid} ({filename}) "
                f"allowed by rule {rule_id}"
            )

        return (True, rule_id)

    def get_ancestry_chain(
        self,
        pid: int,
        max_depth: int | None = None,
    ) -> list[ProcessInfo]:
        """
        Get the ancestry chain for a process.

        Args:
            pid: Process ID.
            max_depth: Maximum depth to traverse.

        Returns:
            List of ProcessInfo from process to ancestors.
        """
        max_depth = max_depth or self.config.max_ancestry_depth
        chain = []
        current_pid = pid

        for _ in range(max_depth):
            info = self._get_process_info(current_pid)
            if not info:
                break

            chain.append(info)
            current_pid = info.ppid

            if current_pid <= 1:
                break

        return chain

    def cleanup_expired(self) -> int:
        """
        Clean up expired ancestry entries.

        Returns:
            Number of entries cleaned.
        """
        now = time.time()
        expired = []

        for pid, info in list(self._process_cache.items()):
            if info.ancestry_allowed and info.ancestry_expiry < now:
                info.ancestry_allowed = False
                expired.append(pid)

        logger.debug(f"Cleaned up {len(expired)} expired ancestry entries")
        return len(expired)

