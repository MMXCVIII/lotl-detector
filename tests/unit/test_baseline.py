"""Unit tests for baseline detection."""

import tempfile
import time
from pathlib import Path

import pytest

from lotl_detector.core.database import Database, DatabaseConfig
from lotl_detector.detection.baseline import BaselineConfig, BaselineEngine


class TestBaselineEngine:
    """Tests for baseline detection engine."""

    @pytest.fixture
    def database(self, tmp_path: Path) -> Database:
        """Create a temporary database."""
        db_path = tmp_path / "test.db"
        db = Database(DatabaseConfig(path=str(db_path)))
        db.connect()
        yield db
        db.close()

    @pytest.fixture
    def engine(self, database: Database) -> BaselineEngine:
        """Create a baseline engine."""
        config = BaselineConfig(
            decay_half_life_days=7.0,
            anomaly_threshold=2.0,
            min_observations=3,
        )
        return BaselineEngine(database, config)

    def test_observe(self, engine: BaselineEngine) -> None:
        """Test recording observations."""
        engine.observe("binary", "/usr/bin/ls")
        engine.observe("binary", "/usr/bin/ls")
        engine.observe("binary", "/usr/bin/ls")

        score = engine.get_score("binary", "/usr/bin/ls")
        assert score > 0

    def test_get_score_unknown(self, engine: BaselineEngine) -> None:
        """Test score for unknown binary is 0."""
        score = engine.get_score("binary", "/usr/bin/unknown")
        assert score == 0

    def test_is_anomalous_known(self, engine: BaselineEngine) -> None:
        """Test that known binaries are not anomalous."""
        # Add observations
        for _ in range(10):
            engine.observe("binary", "/usr/bin/ls")

        is_anom, score = engine.is_anomalous("binary", "/usr/bin/ls")
        assert not is_anom
        assert score > 0

    def test_is_anomalous_unknown(self, engine: BaselineEngine) -> None:
        """Test that unknown binaries are anomalous after baseline."""
        # Build baseline with known binaries
        for _ in range(5):
            engine.observe("binary", "/usr/bin/ls")
            engine.observe("binary", "/usr/bin/cat")
            engine.observe("binary", "/usr/bin/grep")

        # Now check unknown binary
        is_anom, score = engine.is_anomalous("binary", "/usr/bin/suspicious")
        assert is_anom
        assert score == 0

    def test_decay_weight(self, engine: BaselineEngine) -> None:
        """Test that decay weight decreases over time."""
        now = time.time()

        # Simulate observation 1 day ago
        old_time = now - 86400

        engine.observe("binary", "/usr/bin/old", old_time)
        engine.observe("binary", "/usr/bin/new", now)

        old_score = engine.get_score("binary", "/usr/bin/old")
        new_score = engine.get_score("binary", "/usr/bin/new")

        # New observation should have higher score
        assert new_score > old_score

