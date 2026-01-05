"""
Logging system for LOTL Detector.

Provides:
- JSONL file logging with rotation
- Syslog integration for alerts
- Alert rate limiting/deduplication
- Log injection sanitization
"""

from __future__ import annotations

import hashlib
import json
import logging
import logging.handlers
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# ─────────────────────────────────────────────────────────────────────────────
# Log Injection Prevention
# ─────────────────────────────────────────────────────────────────────────────


def sanitize_string(value: str) -> str:
    """
    Sanitize string to prevent log injection.

    Removes newlines and carriage returns that could inject fake log entries.

    Args:
        value: String to sanitize.

    Returns:
        Sanitized string.
    """
    if not isinstance(value, str):
        return str(value)

    # Replace newlines and carriage returns with escaped versions
    return value.replace("\n", "\\n").replace("\r", "\\r")


def sanitize_dict(data: dict[str, Any]) -> dict[str, Any]:
    """
    Recursively sanitize all strings in a dictionary.

    Args:
        data: Dictionary to sanitize.

    Returns:
        Sanitized dictionary.
    """
    result = {}
    for key, value in data.items():
        if isinstance(value, str):
            result[key] = sanitize_string(value)
        elif isinstance(value, dict):
            result[key] = sanitize_dict(value)
        elif isinstance(value, list):
            result[key] = [
                sanitize_string(v) if isinstance(v, str) else v for v in value
            ]
        else:
            result[key] = value
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Alert Rate Limiting
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class RateLimitConfig:
    """Rate limiting configuration."""

    max_alerts_per_rule_per_minute: int = 10
    max_total_alerts_per_minute: int = 100


class AlertRateLimiter:
    """
    Rate limiter for alerts to prevent floods.

    Limits alerts per rule and total alerts per time window.
    """

    def __init__(self, config: RateLimitConfig | None = None) -> None:
        """Initialize rate limiter."""
        self.config = config or RateLimitConfig()
        self._rule_counts: dict[str, list[float]] = defaultdict(list)
        self._total_count: list[float] = []

    def _cleanup_old(self, timestamps: list[float], window: float = 60.0) -> list[float]:
        """Remove timestamps older than window."""
        cutoff = time.time() - window
        return [t for t in timestamps if t > cutoff]

    def should_allow(self, rule_id: str) -> bool:
        """
        Check if alert should be allowed.

        Args:
            rule_id: ID of the rule generating the alert.

        Returns:
            True if alert should be allowed, False if rate limited.
        """
        now = time.time()

        # Cleanup old entries
        self._total_count = self._cleanup_old(self._total_count)
        self._rule_counts[rule_id] = self._cleanup_old(self._rule_counts[rule_id])

        # Check total rate
        if len(self._total_count) >= self.config.max_total_alerts_per_minute:
            return False

        # Check per-rule rate
        if len(self._rule_counts[rule_id]) >= self.config.max_alerts_per_rule_per_minute:
            return False

        # Allow and record
        self._total_count.append(now)
        self._rule_counts[rule_id].append(now)
        return True

    def get_stats(self) -> dict[str, int]:
        """Get current rate limit stats."""
        return {
            "total_in_window": len(self._cleanup_old(self._total_count)),
            "rules_in_window": {
                k: len(self._cleanup_old(v)) for k, v in self._rule_counts.items()
            },
        }


# ─────────────────────────────────────────────────────────────────────────────
# JSONL Handler
# ─────────────────────────────────────────────────────────────────────────────


class JSONLHandler(logging.Handler):
    """
    Logging handler that writes JSONL format with rotation.

    Each log entry is a single JSON object on its own line.
    """

    def __init__(
        self,
        filename: str | Path,
        max_bytes: int = 100 * 1024 * 1024,  # 100MB
        backup_count: int = 5,
    ) -> None:
        """
        Initialize JSONL handler.

        Args:
            filename: Path to log file.
            max_bytes: Maximum file size before rotation.
            backup_count: Number of backup files to keep.
        """
        super().__init__()

        # Ensure directory exists
        path = Path(filename)
        path.parent.mkdir(parents=True, exist_ok=True)

        # Use RotatingFileHandler for automatic rotation
        self._handler = logging.handlers.RotatingFileHandler(
            filename=str(path),
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )

    def emit(self, record: logging.LogRecord) -> None:
        """Emit a log record as JSONL."""
        try:
            # Build log entry
            entry = {
                "timestamp": record.created,
                "level": record.levelname,
                "logger": record.name,
                "message": sanitize_string(record.getMessage()),
            }

            # Add extra fields if present
            if hasattr(record, "event_data"):
                entry["event"] = sanitize_dict(record.event_data)

            if hasattr(record, "alert_data"):
                entry["alert"] = sanitize_dict(record.alert_data)

            # Write JSON line
            line = json.dumps(entry, default=str) + "\n"
            self._handler.stream.write(line)
            self._handler.stream.flush()

        except Exception:
            self.handleError(record)

    def close(self) -> None:
        """Close the handler."""
        self._handler.close()
        super().close()


# ─────────────────────────────────────────────────────────────────────────────
# Logger Setup
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class LogConfig:
    """Logging configuration."""

    level: str = "INFO"
    directory: str = "/var/log/lotl"
    max_size_mb: int = 100
    backup_count: int = 5
    syslog_enabled: bool = True
    syslog_facility: str = "local0"
    console_enabled: bool = True


def setup_logging(config: LogConfig | None = None) -> logging.Logger:
    """
    Set up logging system.

    Args:
        config: Logging configuration.

    Returns:
        Configured root logger.
    """
    config = config or LogConfig()

    # Create logger
    logger = logging.getLogger("lotl_detector")
    logger.setLevel(getattr(logging, config.level.upper(), logging.INFO))

    # Remove existing handlers
    logger.handlers.clear()

    # Ensure log directory exists
    log_dir = Path(config.directory)
    log_dir.mkdir(parents=True, exist_ok=True)

    # Add JSONL handler for events
    events_handler = JSONLHandler(
        filename=log_dir / "events.jsonl",
        max_bytes=config.max_size_mb * 1024 * 1024,
        backup_count=config.backup_count,
    )
    events_handler.setLevel(logging.DEBUG)
    logger.addHandler(events_handler)

    # Add JSONL handler for alerts
    alerts_handler = JSONLHandler(
        filename=log_dir / "alerts.jsonl",
        max_bytes=config.max_size_mb * 1024 * 1024,
        backup_count=config.backup_count,
    )
    alerts_handler.setLevel(logging.WARNING)
    logger.addHandler(alerts_handler)

    # Add syslog handler for alerts
    if config.syslog_enabled:
        try:
            facility = getattr(
                logging.handlers.SysLogHandler,
                f"LOG_{config.syslog_facility.upper()}",
                logging.handlers.SysLogHandler.LOG_LOCAL0,
            )
            syslog_handler = logging.handlers.SysLogHandler(
                address="/dev/log",
                facility=facility,
            )
            syslog_handler.setLevel(logging.WARNING)
            syslog_handler.setFormatter(
                logging.Formatter("lotl-detector: %(levelname)s - %(message)s")
            )
            logger.addHandler(syslog_handler)
        except Exception as e:
            logger.warning(f"Could not set up syslog handler: {e}")

    # Add console handler for debugging
    if config.console_enabled:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        )
        logger.addHandler(console_handler)

    return logger


# ─────────────────────────────────────────────────────────────────────────────
# Event and Alert Logging
# ─────────────────────────────────────────────────────────────────────────────


class EventLogger:
    """
    Structured event and alert logger.

    Provides methods for logging events and alerts with rate limiting
    and deduplication.
    """

    def __init__(
        self,
        logger: logging.Logger | None = None,
        rate_limiter: AlertRateLimiter | None = None,
    ) -> None:
        """Initialize event logger."""
        self._logger = logger or logging.getLogger("lotl_detector")
        self._rate_limiter = rate_limiter or AlertRateLimiter()
        self._alert_hashes: set[str] = set()
        self._last_cleanup = time.time()

    def _compute_alert_hash(self, alert_data: dict[str, Any]) -> str:
        """Compute hash for alert deduplication."""
        # Include key fields in hash
        key_fields = ["alert_type", "rule_id", "pid", "filename"]
        hash_input = "|".join(str(alert_data.get(f, "")) for f in key_fields)
        return hashlib.sha256(hash_input.encode()).hexdigest()[:16]

    def _cleanup_old_hashes(self) -> None:
        """Periodically cleanup old hashes (keep set bounded)."""
        now = time.time()
        if now - self._last_cleanup > 300:  # Every 5 minutes
            # Keep only last 10000 hashes
            if len(self._alert_hashes) > 10000:
                self._alert_hashes = set(list(self._alert_hashes)[-5000:])
            self._last_cleanup = now

    def log_event(self, event_data: dict[str, Any]) -> None:
        """
        Log an event.

        Args:
            event_data: Event data dictionary.
        """
        # Sanitize data
        event_data = sanitize_dict(event_data)

        # Create log record with event data
        record = self._logger.makeRecord(
            name=self._logger.name,
            level=logging.INFO,
            fn="",
            lno=0,
            msg=f"Event: {event_data.get('event_type', 'unknown')}",
            args=(),
            exc_info=None,
        )
        record.event_data = event_data

        self._logger.handle(record)

    def log_alert(
        self,
        alert_data: dict[str, Any],
        deduplicate: bool = True,
    ) -> bool:
        """
        Log an alert with rate limiting and deduplication.

        Args:
            alert_data: Alert data dictionary.
            deduplicate: Whether to deduplicate alerts.

        Returns:
            True if alert was logged, False if suppressed.
        """
        self._cleanup_old_hashes()

        # Sanitize data
        alert_data = sanitize_dict(alert_data)

        # Check deduplication
        if deduplicate:
            alert_hash = self._compute_alert_hash(alert_data)
            if alert_hash in self._alert_hashes:
                return False
            self._alert_hashes.add(alert_hash)

        # Check rate limiting
        rule_id = alert_data.get("rule_id", "unknown")
        if not self._rate_limiter.should_allow(rule_id):
            return False

        # Create log record with alert data
        severity = alert_data.get("severity", "MEDIUM")
        level = (
            logging.CRITICAL
            if severity == "CRITICAL"
            else logging.WARNING
        )

        record = self._logger.makeRecord(
            name=self._logger.name,
            level=level,
            fn="",
            lno=0,
            msg=f"Alert: {alert_data.get('alert_type', 'unknown')} - {alert_data.get('description', '')}",
            args=(),
            exc_info=None,
        )
        record.alert_data = alert_data

        self._logger.handle(record)
        return True

    def log_block(self, block_data: dict[str, Any]) -> None:
        """Log a blocking action."""
        block_data = sanitize_dict(block_data)
        block_data["action"] = "BLOCKED"

        self._logger.warning(
            f"BLOCKED: {block_data.get('filename', 'unknown')} by {block_data.get('rule_id', 'unknown')}"
        )

