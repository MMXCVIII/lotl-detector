"""
Logger Process for LOTL Detector.

Handles all logging in a dedicated process to avoid blocking.
"""

from __future__ import annotations

import logging
import signal
from multiprocessing import Queue
from pathlib import Path
from typing import Any

from lotl_detector.core.logger import (
    EventLogger,
    LogConfig,
    setup_logging,
    AlertRateLimiter,
)

logger = logging.getLogger(__name__)


class LoggerProcess:
    """
    Dedicated logging process.

    Receives log entries from other processes and writes them
    to JSONL files and syslog.
    """

    def __init__(
        self,
        logs_queue: Queue,
        log_dir: Path,
        log_config: LogConfig | None = None,
    ) -> None:
        """
        Initialize logger process.

        Args:
            logs_queue: Queue to receive log entries from.
            log_dir: Directory for log files.
            log_config: Logging configuration.
        """
        self.logs_queue = logs_queue
        self.log_dir = log_dir
        self.log_config = log_config or LogConfig(directory=str(log_dir))
        self._running = False
        self._event_logger: EventLogger | None = None

    def _handle_shutdown(self, signum, frame):
        """Handle shutdown signal."""
        logger.info("Logger received shutdown signal")
        self._running = False

    def run(self) -> None:
        """Run the logger loop."""
        signal.signal(signal.SIGTERM, self._handle_shutdown)
        signal.signal(signal.SIGINT, self._handle_shutdown)

        # Set up logging
        self.log_config.directory = str(self.log_dir)
        main_logger = setup_logging(self.log_config)
        self._event_logger = EventLogger(
            logger=main_logger,
            rate_limiter=AlertRateLimiter(),
        )

        self._running = True
        logger.info(f"Logger started, writing to {self.log_dir}")

        while self._running:
            try:
                # Get log entry from queue
                try:
                    entry = self.logs_queue.get(timeout=0.1)
                except:
                    continue

                self._process_entry(entry)

            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"Error processing log entry: {e}")

        logger.info("Logger stopped")

    def _process_entry(self, entry: dict[str, Any]) -> None:
        """
        Process a single log entry.

        Args:
            entry: Log entry dictionary.
        """
        if not self._event_logger:
            return

        entry_type = entry.get("type", "event")
        data = entry.get("data", {})

        if entry_type == "alert":
            self._event_logger.log_alert(data)
        elif entry_type == "event":
            self._event_logger.log_event(data)
        elif entry_type == "block":
            self._event_logger.log_block(data)
        else:
            # Generic log
            self._event_logger.log_event(data)


def logger_process(
    logs_queue: Queue,
    log_dir: str,
    log_level: str = "INFO",
    syslog_enabled: bool = True,
) -> None:
    """
    Entry point for logger process.

    Args:
        logs_queue: Queue for log entries.
        log_dir: Directory for log files.
        log_level: Logging level.
        syslog_enabled: Whether to enable syslog.
    """
    try:
        config = LogConfig(
            level=log_level,
            directory=log_dir,
            syslog_enabled=syslog_enabled,
        )

        log_proc = LoggerProcess(
            logs_queue=logs_queue,
            log_dir=Path(log_dir),
            log_config=config,
        )
        log_proc.run()

    except Exception as e:
        logger.error(f"Logger process failed: {e}")
        raise

