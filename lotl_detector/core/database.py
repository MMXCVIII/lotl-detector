"""
Database management for LOTL Detector.

Handles SQLite database operations with:
- WAL mode for concurrent access
- Parameterized queries for SQL injection prevention
- Automatic schema migrations
- Data cleanup for unbounded growth prevention
"""

from __future__ import annotations

import logging
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Generator, Any

logger = logging.getLogger(__name__)


class DatabaseError(Exception):
    """Raised for database errors."""


# ─────────────────────────────────────────────────────────────────────────────
# Schema Definitions
# ─────────────────────────────────────────────────────────────────────────────

SCHEMA_VERSION = 1

SCHEMA_SQL = """
-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at REAL NOT NULL
);

-- Baseline data: what's normal for this system
CREATE TABLE IF NOT EXISTS baseline (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_type TEXT NOT NULL,           -- 'binary', 'binary_user', 'binary_args_hash'
    key_value TEXT NOT NULL,          -- The key (e.g., '/usr/bin/curl')
    count INTEGER DEFAULT 1,          -- How many times seen
    first_seen REAL NOT NULL,         -- Timestamp
    last_seen REAL NOT NULL,          -- Timestamp
    decay_weight REAL DEFAULT 1.0,    -- For exponential decay
    UNIQUE(key_type, key_value)
);

-- Process tree tracking
CREATE TABLE IF NOT EXISTS process_tree (
    pid INTEGER PRIMARY KEY,
    ppid INTEGER NOT NULL,
    uid INTEGER NOT NULL,
    comm TEXT NOT NULL,
    filename TEXT NOT NULL,
    start_time REAL NOT NULL,
    ancestry_allowed INTEGER DEFAULT 0,
    ancestry_expiry REAL DEFAULT 0
);

-- Alert history (for deduplication)
CREATE TABLE IF NOT EXISTS alert_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT NOT NULL,
    pid INTEGER NOT NULL,
    timestamp REAL NOT NULL,
    hash TEXT NOT NULL,
    UNIQUE(hash)
);

-- Blocked user history
CREATE TABLE IF NOT EXISTS blocked_users (
    uid INTEGER PRIMARY KEY,
    reason TEXT NOT NULL,
    blocked_at REAL NOT NULL,
    expires_at REAL DEFAULT NULL,
    active INTEGER DEFAULT 1
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_baseline_key ON baseline(key_type, key_value);
CREATE INDEX IF NOT EXISTS idx_baseline_last_seen ON baseline(last_seen);
CREATE INDEX IF NOT EXISTS idx_process_tree_ppid ON process_tree(ppid);
CREATE INDEX IF NOT EXISTS idx_process_tree_start ON process_tree(start_time);
CREATE INDEX IF NOT EXISTS idx_alert_history_timestamp ON alert_history(timestamp);
CREATE INDEX IF NOT EXISTS idx_alert_history_rule ON alert_history(rule_id, timestamp);
"""


# ─────────────────────────────────────────────────────────────────────────────
# Database Manager
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class DatabaseConfig:
    """Database configuration."""

    path: str = "/var/lib/lotl/detector.db"
    max_age_days: int = 30
    vacuum_interval_hours: int = 24
    busy_timeout_ms: int = 30000  # 30 seconds


class Database:
    """
    SQLite database manager for LOTL Detector.

    Uses WAL mode for concurrent access and parameterized queries
    for SQL injection prevention.
    """

    def __init__(self, config: DatabaseConfig | None = None) -> None:
        """
        Initialize database manager.

        Args:
            config: Database configuration. Uses defaults if None.
        """
        self.config = config or DatabaseConfig()
        self._conn: sqlite3.Connection | None = None
        self._last_vacuum: float = 0

    @property
    def path(self) -> Path:
        """Get database file path."""
        return Path(self.config.path)

    def connect(self) -> None:
        """
        Connect to database and initialize schema.

        Raises:
            DatabaseError: If connection fails.
        """
        try:
            # Ensure directory exists
            self.path.parent.mkdir(parents=True, exist_ok=True)

            # Connect with WAL mode and busy timeout
            self._conn = sqlite3.connect(
                self.config.path,
                timeout=self.config.busy_timeout_ms / 1000,
                isolation_level=None,  # Autocommit mode
            )
            self._conn.row_factory = sqlite3.Row

            # Enable WAL mode for concurrent access
            self._conn.execute("PRAGMA journal_mode=WAL")

            # Set busy timeout
            self._conn.execute(f"PRAGMA busy_timeout={self.config.busy_timeout_ms}")

            # Enable foreign keys
            self._conn.execute("PRAGMA foreign_keys=ON")

            # Check integrity
            if not self._check_integrity():
                self._recover_corrupted()

            # Initialize schema
            self._init_schema()

            logger.info(f"Connected to database: {self.config.path}")

        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to connect to database: {e}") from e

    def _check_integrity(self) -> bool:
        """Check database integrity."""
        if self._conn is None:
            return False

        try:
            result = self._conn.execute("PRAGMA integrity_check").fetchone()
            return result[0] == "ok"
        except sqlite3.Error:
            return False

    def _recover_corrupted(self) -> None:
        """Attempt to recover from corruption."""
        logger.error("Database corruption detected, creating backup and reinitializing")

        # Close connection
        if self._conn:
            self._conn.close()
            self._conn = None

        # Backup corrupted file
        backup_path = self.path.with_suffix(f".corrupted.{int(time.time())}")
        try:
            self.path.rename(backup_path)
            logger.info(f"Backed up corrupted database to: {backup_path}")
        except OSError as e:
            logger.warning(f"Could not backup corrupted database: {e}")
            # Try to delete instead
            try:
                self.path.unlink()
            except OSError:
                pass

        # Reconnect (will create fresh database)
        self._conn = sqlite3.connect(
            self.config.path,
            timeout=self.config.busy_timeout_ms / 1000,
            isolation_level=None,
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")

    def _init_schema(self) -> None:
        """Initialize database schema."""
        if self._conn is None:
            return

        # Check current version
        try:
            result = self._conn.execute(
                "SELECT version FROM schema_version ORDER BY version DESC LIMIT 1"
            ).fetchone()
            current_version = result[0] if result else 0
        except sqlite3.OperationalError:
            current_version = 0

        if current_version < SCHEMA_VERSION:
            logger.info(f"Upgrading database schema from v{current_version} to v{SCHEMA_VERSION}")
            self._conn.executescript(SCHEMA_SQL)

            # Record version
            self._conn.execute(
                "INSERT OR REPLACE INTO schema_version (version, applied_at) VALUES (?, ?)",
                (SCHEMA_VERSION, time.time()),
            )

    @contextmanager
    def transaction(self) -> Generator[sqlite3.Connection, None, None]:
        """
        Context manager for transactions.

        Yields:
            Database connection within a transaction.
        """
        if self._conn is None:
            raise DatabaseError("Database not connected")

        try:
            self._conn.execute("BEGIN")
            yield self._conn
            self._conn.execute("COMMIT")
        except Exception:
            self._conn.execute("ROLLBACK")
            raise

    def execute(
        self, sql: str, params: tuple[Any, ...] | dict[str, Any] = ()
    ) -> sqlite3.Cursor:
        """
        Execute a parameterized SQL query.

        CRITICAL: Always use parameterized queries to prevent SQL injection.

        Args:
            sql: SQL query with ? placeholders.
            params: Query parameters.

        Returns:
            Cursor with results.
        """
        if self._conn is None:
            raise DatabaseError("Database not connected")

        return self._conn.execute(sql, params)

    def executemany(
        self, sql: str, params_list: list[tuple[Any, ...]]
    ) -> sqlite3.Cursor:
        """Execute a parameterized SQL query with multiple parameter sets."""
        if self._conn is None:
            raise DatabaseError("Database not connected")

        return self._conn.executemany(sql, params_list)

    # ─────────────────────────────────────────────────────────────────────────
    # Baseline Operations
    # ─────────────────────────────────────────────────────────────────────────

    def update_baseline(
        self, key_type: str, key_value: str, decay_weight: float = 1.0
    ) -> None:
        """
        Update baseline entry.

        Args:
            key_type: Type of baseline key (e.g., 'binary', 'binary_user').
            key_value: The key value.
            decay_weight: Current decay weight.
        """
        now = time.time()

        self.execute(
            """
            INSERT INTO baseline (key_type, key_value, count, first_seen, last_seen, decay_weight)
            VALUES (?, ?, 1, ?, ?, ?)
            ON CONFLICT(key_type, key_value) DO UPDATE SET
                count = count + 1,
                last_seen = ?,
                decay_weight = ?
            """,
            (key_type, key_value, now, now, decay_weight, now, decay_weight),
        )

    def get_baseline(self, key_type: str, key_value: str) -> dict[str, Any] | None:
        """
        Get baseline entry.

        Args:
            key_type: Type of baseline key.
            key_value: The key value.

        Returns:
            Baseline entry as dict, or None if not found.
        """
        result = self.execute(
            "SELECT * FROM baseline WHERE key_type = ? AND key_value = ?",
            (key_type, key_value),
        ).fetchone()

        return dict(result) if result else None

    def get_baseline_count(self, key_type: str, key_value: str) -> int:
        """Get count for a baseline entry."""
        result = self.execute(
            "SELECT count FROM baseline WHERE key_type = ? AND key_value = ?",
            (key_type, key_value),
        ).fetchone()

        return result[0] if result else 0

    # ─────────────────────────────────────────────────────────────────────────
    # Process Tree Operations
    # ─────────────────────────────────────────────────────────────────────────

    def update_process(
        self,
        pid: int,
        ppid: int,
        uid: int,
        comm: str,
        filename: str,
        start_time: float,
        ancestry_allowed: bool = False,
        ancestry_expiry: float = 0,
    ) -> None:
        """Update or insert process tree entry."""
        self.execute(
            """
            INSERT OR REPLACE INTO process_tree 
            (pid, ppid, uid, comm, filename, start_time, ancestry_allowed, ancestry_expiry)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (pid, ppid, uid, comm, filename, start_time, 
             1 if ancestry_allowed else 0, ancestry_expiry),
        )

    def get_process(self, pid: int) -> dict[str, Any] | None:
        """Get process entry."""
        result = self.execute(
            "SELECT * FROM process_tree WHERE pid = ?", (pid,)
        ).fetchone()

        return dict(result) if result else None

    def get_ancestors(self, pid: int, max_depth: int = 10) -> list[dict[str, Any]]:
        """
        Get ancestor chain for a process.

        Args:
            pid: Process ID.
            max_depth: Maximum depth to traverse.

        Returns:
            List of ancestor process entries.
        """
        ancestors = []
        current_pid = pid

        for _ in range(max_depth):
            proc = self.get_process(current_pid)
            if not proc:
                break

            ancestors.append(proc)
            current_pid = proc["ppid"]

            if current_pid <= 1:  # Reached init
                break

        return ancestors

    def remove_process(self, pid: int) -> None:
        """Remove process from tree."""
        self.execute("DELETE FROM process_tree WHERE pid = ?", (pid,))

    # ─────────────────────────────────────────────────────────────────────────
    # Alert History Operations
    # ─────────────────────────────────────────────────────────────────────────

    def record_alert(self, rule_id: str, pid: int, alert_hash: str) -> bool:
        """
        Record an alert for deduplication.

        Args:
            rule_id: Rule that triggered the alert.
            pid: Process ID.
            alert_hash: Hash of alert for deduplication.

        Returns:
            True if this is a new alert, False if duplicate.
        """
        try:
            self.execute(
                "INSERT INTO alert_history (rule_id, pid, timestamp, hash) VALUES (?, ?, ?, ?)",
                (rule_id, pid, time.time(), alert_hash),
            )
            return True
        except sqlite3.IntegrityError:
            return False  # Duplicate

    # ─────────────────────────────────────────────────────────────────────────
    # Cleanup Operations
    # ─────────────────────────────────────────────────────────────────────────

    def cleanup_old_data(self) -> int:
        """
        Clean up old data to prevent unbounded growth.

        Returns:
            Number of rows deleted.
        """
        cutoff = time.time() - (self.config.max_age_days * 86400)
        deleted = 0

        # Clean old baseline entries
        cursor = self.execute(
            "DELETE FROM baseline WHERE last_seen < ?", (cutoff,)
        )
        deleted += cursor.rowcount

        # Clean old process tree entries
        cursor = self.execute(
            "DELETE FROM process_tree WHERE start_time < ?", (cutoff,)
        )
        deleted += cursor.rowcount

        # Clean old alert history
        cursor = self.execute(
            "DELETE FROM alert_history WHERE timestamp < ?", (cutoff,)
        )
        deleted += cursor.rowcount

        # Vacuum periodically
        now = time.time()
        vacuum_interval = self.config.vacuum_interval_hours * 3600
        if now - self._last_vacuum > vacuum_interval:
            self._conn.execute("VACUUM")
            self._last_vacuum = now
            logger.info("Database vacuumed")

        if deleted > 0:
            logger.info(f"Cleaned up {deleted} old database entries")

        return deleted

    def close(self) -> None:
        """Close database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None
            logger.debug("Database connection closed")

    def __enter__(self) -> "Database":
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit."""
        self.close()

