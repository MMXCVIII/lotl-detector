"""
Event Analyzer for LOTL Detector.

Analyzes events using detection rules, baseline, and ancestry.
"""

from __future__ import annotations

import logging
import signal
import time
from multiprocessing import Queue
from pathlib import Path
from typing import Any

from lotl_detector.core.database import Database, DatabaseConfig
from lotl_detector.core.models import (
    AlertEvent,
    AlertType,
    Decision,
    ExecEvent,
    OperationalMode,
    SeverityLevel,
)
from lotl_detector.detection.ancestry import AncestryChecker, AncestryConfig
from lotl_detector.detection.baseline import BaselineConfig, BaselineEngine
from lotl_detector.detection.busybox import BusyboxDetector
from lotl_detector.detection.rules.engine import RuleEngine

logger = logging.getLogger(__name__)


class Analyzer:
    """
    Analyzes events and generates detection decisions.

    Combines multiple detection methods:
    - Rule matching (Tier 2 patterns)
    - Baseline anomaly detection
    - Ancestry checking
    - Busybox applet detection
    """

    def __init__(
        self,
        events_queue: Queue,
        decisions_queue: Queue,
        logs_queue: Queue,
        rules_dir: Path,
        db_path: str,
        mode: OperationalMode = OperationalMode.LEARN,
    ) -> None:
        """
        Initialize analyzer.

        Args:
            events_queue: Queue to receive events from.
            decisions_queue: Queue to send decisions to enforcer.
            logs_queue: Queue to send logs.
            rules_dir: Path to rules directory.
            db_path: Path to database file.
            mode: Operational mode.
        """
        self.events_queue = events_queue
        self.decisions_queue = decisions_queue
        self.logs_queue = logs_queue
        self.rules_dir = rules_dir
        self.db_path = db_path
        self.mode = mode
        self._running = False

        # Detection components (initialized in run)
        self.rule_engine: RuleEngine | None = None
        self.baseline: BaselineEngine | None = None
        self.ancestry: AncestryChecker | None = None
        self.busybox: BusyboxDetector | None = None
        self.database: Database | None = None

    def _handle_shutdown(self, signum, frame):
        """Handle shutdown signal."""
        logger.info("Analyzer received shutdown signal")
        self._running = False

    def _init_components(self) -> None:
        """Initialize detection components."""
        # Database
        self.database = Database(DatabaseConfig(path=self.db_path))
        self.database.connect()

        # Rule engine
        self.rule_engine = RuleEngine(self.rules_dir)
        self.rule_engine.load_rules()

        # Baseline
        self.baseline = BaselineEngine(self.database)

        # Ancestry
        self.ancestry = AncestryChecker(
            self.database,
            self.rule_engine,
        )

        # Busybox
        self.busybox = BusyboxDetector()

        logger.info("Analyzer components initialized")

    def analyze_event(self, event_dict: dict[str, Any]) -> Decision:
        """
        Analyze a single event.

        Args:
            event_dict: Event dictionary from collector.

        Returns:
            Detection decision.
        """
        # Reconstruct event object
        from lotl_detector.core.models import EventType

        event = ExecEvent(
            timestamp_ns=event_dict.get("timestamp_ns", 0),
            pid=event_dict.get("pid", 0),
            ppid=event_dict.get("ppid", 0),
            uid=event_dict.get("uid", 0),
            gid=event_dict.get("gid", 0),
            start_time_ns=event_dict.get("start_time_ns", 0),
            inode=event_dict.get("inode", 0),
            event_type=EventType[event_dict.get("event_type", "EXECVE")],
            blocked=event_dict.get("blocked", False),
            is_memfd=event_dict.get("is_memfd", False),
            is_busybox=event_dict.get("is_busybox", False),
            is_stdin_exec=event_dict.get("is_stdin_exec", False),
            args_truncated=event_dict.get("args_truncated", False),
            args_count_exceeded=event_dict.get("args_count_exceeded", False),
            env_truncated=event_dict.get("env_truncated", False),
            rate_limited=event_dict.get("rate_limited", False),
            comm=event_dict.get("comm", ""),
            filename=event_dict.get("filename", ""),
            args=event_dict.get("args", []),
            busybox_applet=event_dict.get("busybox_applet", ""),
            env_ld_preload=event_dict.get("env_ld_preload", ""),
            env_ld_library_path=event_dict.get("env_ld_library_path", ""),
        )

        decision = Decision(event=event)
        alerts = []

        # Record in process tree
        if self.ancestry:
            self.ancestry.record_process(
                pid=event.pid,
                ppid=event.ppid,
                filename=event.filename,
                start_time=event.timestamp_ns / 1e9,
            )

        # Check ancestry allowance
        if self.ancestry:
            allowed, rule_id = self.ancestry.is_allowed(
                event.pid,
                event.filename,
                event.ppid,
            )
            if allowed:
                decision.ancestry_allowed = True
                # Still log but don't alert
                if self.mode == OperationalMode.BOOTSTRAP:
                    pass  # No logging in bootstrap
                return decision

        # Rule matching (Tier 2)
        if self.rule_engine:
            rule_alerts = self.rule_engine.evaluate_tier2(event)
            for alert in rule_alerts:
                alerts.append(alert)
                decision.matched_rules.append(alert.rule_id)

        # Busybox detection
        if self.busybox and (event.is_busybox or self.busybox.is_busybox(event.filename)):
            bb_alerts, should_block = self.busybox.analyze(event)
            alerts.extend(bb_alerts)
            if should_block and self.mode >= OperationalMode.ENFORCE:
                decision.should_block = True

        # Baseline scoring (only in learn/enforce modes)
        if self.baseline and self.mode >= OperationalMode.LEARN:
            baseline_result = self.baseline.score_event(event)
            decision.anomaly_score = baseline_result.get("total_anomaly_score", 0)

            # Generate anomaly alert if score is high
            if decision.anomaly_score >= 2.0:
                anomaly_alert = AlertEvent(
                    timestamp_ns=event.timestamp_ns,
                    pid=event.pid,
                    uid=event.uid,
                    alert_type=AlertType.BLOCKED_EXEC,
                    severity=SeverityLevel.MEDIUM,
                    target_pid=0,
                    comm=event.comm,
                    filename=event.filename,
                    rule_id="baseline-anomaly",
                    description=f"Anomalous behavior (score: {decision.anomaly_score:.2f})",
                )
                alerts.append(anomaly_alert)

        # Update baseline with observation
        if self.baseline and self.mode in (OperationalMode.BOOTSTRAP, OperationalMode.LEARN):
            self.baseline.observe_exec_event(event)

        # Determine if we should block
        if self.mode >= OperationalMode.ENFORCE:
            for alert in alerts:
                if alert.severity >= SeverityLevel.HIGH:
                    decision.should_block = True
                    break

        decision.alerts = alerts
        return decision

    def run(self) -> None:
        """Run the analyzer loop."""
        signal.signal(signal.SIGTERM, self._handle_shutdown)
        signal.signal(signal.SIGINT, self._handle_shutdown)

        self._init_components()
        self._running = True

        logger.info(f"Analyzer started in {self.mode.name} mode")

        while self._running:
            try:
                # Get event from queue (with timeout)
                try:
                    event_dict = self.events_queue.get(timeout=0.1)
                except:
                    continue

                # Analyze event
                decision = self.analyze_event(event_dict)

                # Send decision to enforcer if blocking
                if decision.should_block:
                    try:
                        self.decisions_queue.put_nowait(decision.to_dict())
                    except:
                        logger.warning("Decisions queue full")

                # Send alerts to logger
                for alert in decision.alerts:
                    try:
                        self.logs_queue.put_nowait({
                            "type": "alert",
                            "data": alert.to_dict(),
                        })
                    except:
                        pass

                # Log event (except in bootstrap mode to reduce noise)
                if self.mode != OperationalMode.BOOTSTRAP:
                    try:
                        self.logs_queue.put_nowait({
                            "type": "event",
                            "data": event_dict,
                        })
                    except:
                        pass

            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"Error analyzing event: {e}")

        # Cleanup
        if self.database:
            self.database.close()

        logger.info("Analyzer stopped")


def analyzer_process(
    events_queue: Queue,
    decisions_queue: Queue,
    logs_queue: Queue,
    rules_dir: str,
    db_path: str,
    mode: str = "learn",
) -> None:
    """
    Entry point for analyzer process.

    Args:
        events_queue: Queue for receiving events.
        decisions_queue: Queue for sending decisions.
        logs_queue: Queue for sending logs.
        rules_dir: Path to rules directory.
        db_path: Path to database.
        mode: Operational mode string.
    """
    try:
        mode_enum = OperationalMode[mode.upper()]

        analyzer = Analyzer(
            events_queue=events_queue,
            decisions_queue=decisions_queue,
            logs_queue=logs_queue,
            rules_dir=Path(rules_dir),
            db_path=db_path,
            mode=mode_enum,
        )
        analyzer.run()

    except Exception as e:
        logger.error(f"Analyzer process failed: {e}")
        raise

