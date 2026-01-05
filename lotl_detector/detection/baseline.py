"""
Baseline detection for LOTL Detector.

Implements rolling baseline with exponential decay for
detecting anomalous behavior.
"""

from __future__ import annotations

import logging
import math
import time
from dataclasses import dataclass
from typing import Any

from lotl_detector.core.database import Database

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class BaselineConfig:
    """Baseline detection configuration."""

    # Decay half-life in days
    decay_half_life_days: float = 7.0

    # Anomaly threshold (standard deviations)
    anomaly_threshold: float = 2.0

    # Minimum observations before considering anomalous
    min_observations: int = 5

    # Key types to track
    track_binary: bool = True
    track_binary_user: bool = True
    track_binary_args_hash: bool = True


# ─────────────────────────────────────────────────────────────────────────────
# Baseline Engine
# ─────────────────────────────────────────────────────────────────────────────


class BaselineEngine:
    """
    Rolling baseline with exponential decay.

    Tracks "normal" behavior and scores new events against it.
    Uses exponential decay so old observations fade over time.
    """

    def __init__(
        self,
        database: Database,
        config: BaselineConfig | None = None,
    ) -> None:
        """
        Initialize baseline engine.

        Args:
            database: Database connection.
            config: Baseline configuration.
        """
        self.db = database
        self.config = config or BaselineConfig()

        # Precompute decay constant
        # decay = 0.5 at half_life, so: 0.5 = e^(-lambda * half_life)
        # lambda = ln(2) / half_life
        half_life_seconds = self.config.decay_half_life_days * 86400
        self._decay_lambda = math.log(2) / half_life_seconds

    def _compute_decay_weight(self, last_seen: float, now: float | None = None) -> float:
        """
        Compute decay weight based on time since last observation.

        Args:
            last_seen: Timestamp of last observation.
            now: Current timestamp (defaults to current time).

        Returns:
            Decay weight between 0 and 1.
        """
        if now is None:
            now = time.time()

        age = now - last_seen
        if age <= 0:
            return 1.0

        # Exponential decay: weight = e^(-lambda * age)
        return math.exp(-self._decay_lambda * age)

    def observe(
        self,
        key_type: str,
        key_value: str,
        timestamp: float | None = None,
    ) -> None:
        """
        Record an observation in the baseline.

        Args:
            key_type: Type of observation (e.g., 'binary', 'binary_user').
            key_value: The observed value.
            timestamp: Observation timestamp (defaults to now).
        """
        if timestamp is None:
            timestamp = time.time()

        # Get existing entry
        existing = self.db.get_baseline(key_type, key_value)

        if existing:
            # Update with decayed weight
            old_weight = self._compute_decay_weight(existing["last_seen"], timestamp)
            new_weight = existing["decay_weight"] * old_weight + 1.0
        else:
            new_weight = 1.0

        self.db.update_baseline(key_type, key_value, new_weight)

    def observe_exec_event(self, event: Any) -> None:
        """
        Record observations from an exec event.

        Args:
            event: ExecEvent to observe.
        """
        now = event.timestamp_ns / 1e9 if event.timestamp_ns > 1e12 else time.time()

        # Track binary
        if self.config.track_binary and event.filename:
            self.observe("binary", event.filename, now)

        # Track binary + user combination
        if self.config.track_binary_user and event.filename:
            key = f"{event.filename}:{event.uid}"
            self.observe("binary_user", key, now)

        # Track binary + args hash
        if self.config.track_binary_args_hash and event.filename and event.args:
            import hashlib
            args_hash = hashlib.sha256(
                " ".join(event.args).encode()
            ).hexdigest()[:16]
            key = f"{event.filename}:{args_hash}"
            self.observe("binary_args_hash", key, now)

    def get_score(self, key_type: str, key_value: str) -> float:
        """
        Get the baseline score for an observation.

        Higher scores indicate more commonly seen behavior.

        Args:
            key_type: Type of observation.
            key_value: The observed value.

        Returns:
            Score (decayed count). 0 if never seen.
        """
        entry = self.db.get_baseline(key_type, key_value)
        if not entry:
            return 0.0

        # Apply decay to the stored weight
        weight = entry["decay_weight"]
        decayed = weight * self._compute_decay_weight(entry["last_seen"])
        return decayed

    def is_anomalous(
        self,
        key_type: str,
        key_value: str,
        threshold: float | None = None,
    ) -> tuple[bool, float]:
        """
        Check if an observation is anomalous.

        Args:
            key_type: Type of observation.
            key_value: The observed value.
            threshold: Anomaly threshold (uses config default if None).

        Returns:
            Tuple of (is_anomalous, score).
        """
        score = self.get_score(key_type, key_value)
        threshold = threshold or self.config.anomaly_threshold

        # Never seen before = anomalous if we have enough baseline data
        if score == 0:
            # Check if we have enough observations of this type
            total_obs = self._get_total_observations(key_type)
            if total_obs >= self.config.min_observations:
                return (True, 0.0)
            else:
                # Not enough baseline data yet
                return (False, 0.0)

        # Get average score for this key type
        avg_score = self._get_average_score(key_type)
        if avg_score == 0:
            return (False, score)

        # Score significantly below average = anomalous
        if score < avg_score / threshold:
            return (True, score)

        return (False, score)

    def _get_total_observations(self, key_type: str) -> int:
        """Get total number of unique observations of a type."""
        result = self.db.execute(
            "SELECT COUNT(*) FROM baseline WHERE key_type = ?",
            (key_type,),
        ).fetchone()
        return result[0] if result else 0

    def _get_average_score(self, key_type: str) -> float:
        """Get average decay weight for a key type."""
        result = self.db.execute(
            "SELECT AVG(decay_weight) FROM baseline WHERE key_type = ?",
            (key_type,),
        ).fetchone()
        return result[0] if result and result[0] else 0.0

    def score_event(self, event: Any) -> dict[str, Any]:
        """
        Score an exec event against the baseline.

        Args:
            event: ExecEvent to score.

        Returns:
            Dictionary with scores and anomaly flags.
        """
        now = event.timestamp_ns / 1e9 if event.timestamp_ns > 1e12 else time.time()
        results = {
            "binary": {"score": 0.0, "anomalous": False},
            "binary_user": {"score": 0.0, "anomalous": False},
            "binary_args_hash": {"score": 0.0, "anomalous": False},
            "total_anomaly_score": 0.0,
        }

        # Score binary
        if self.config.track_binary and event.filename:
            is_anom, score = self.is_anomalous("binary", event.filename)
            results["binary"] = {"score": score, "anomalous": is_anom}
            if is_anom:
                results["total_anomaly_score"] += 1.0

        # Score binary + user
        if self.config.track_binary_user and event.filename:
            key = f"{event.filename}:{event.uid}"
            is_anom, score = self.is_anomalous("binary_user", key)
            results["binary_user"] = {"score": score, "anomalous": is_anom}
            if is_anom:
                results["total_anomaly_score"] += 0.5

        # Score binary + args
        if self.config.track_binary_args_hash and event.filename and event.args:
            import hashlib
            args_hash = hashlib.sha256(
                " ".join(event.args).encode()
            ).hexdigest()[:16]
            key = f"{event.filename}:{args_hash}"
            is_anom, score = self.is_anomalous("binary_args_hash", key)
            results["binary_args_hash"] = {"score": score, "anomalous": is_anom}
            if is_anom:
                results["total_anomaly_score"] += 0.25

        return results

    def apply_decay(self) -> int:
        """
        Apply decay to all baseline entries.

        Should be called periodically (e.g., daily).

        Returns:
            Number of entries updated.
        """
        now = time.time()
        cutoff = now - (self.config.decay_half_life_days * 86400 * 4)

        # Remove entries that have decayed below threshold
        cursor = self.db.execute(
            """
            DELETE FROM baseline 
            WHERE last_seen < ? AND decay_weight < 0.1
            """,
            (cutoff,),
        )

        deleted = cursor.rowcount
        if deleted > 0:
            logger.info(f"Removed {deleted} decayed baseline entries")

        return deleted

