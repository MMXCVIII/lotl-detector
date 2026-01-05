"""
Event Collector for LOTL Detector.

Polls BPF ring buffers and collects events for processing.
"""

from __future__ import annotations

import ctypes
import logging
import signal
import time
from multiprocessing import Queue
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lotl_detector.bpf.loader import BPFLoader

logger = logging.getLogger(__name__)


class Collector:
    """
    Collects events from BPF ring buffers.

    Runs in a separate process and forwards events to the analyzer.
    """

    def __init__(
        self,
        events_queue: Queue,
        alerts_queue: Queue,
        poll_timeout_ms: int = 100,
    ) -> None:
        """
        Initialize collector.

        Args:
            events_queue: Queue for sending events to analyzer.
            alerts_queue: Queue for sending alerts directly.
            poll_timeout_ms: Timeout for ring buffer polling.
        """
        self.events_queue = events_queue
        self.alerts_queue = alerts_queue
        self.poll_timeout_ms = poll_timeout_ms
        self._running = False
        self._bpf: BPFLoader | None = None

    def _handle_shutdown(self, signum, frame):
        """Handle shutdown signal."""
        logger.info("Collector received shutdown signal")
        self._running = False

    def run(self, bpf_loader: "BPFLoader") -> None:
        """
        Run the collector loop.

        Args:
            bpf_loader: Loaded BPF programs.
        """
        # Set up signal handlers
        signal.signal(signal.SIGTERM, self._handle_shutdown)
        signal.signal(signal.SIGINT, self._handle_shutdown)

        self._bpf = bpf_loader
        self._running = True

        logger.info("Collector started")

        # Import here to avoid circular imports
        from lotl_detector.core.models import ExecEvent, ExecEventCType, AlertEvent, AlertEventCType

        # Set up ring buffer callbacks
        def handle_exec_event(cpu, data, size):
            """Handle execve event from ring buffer."""
            try:
                event = ctypes.cast(data, ctypes.POINTER(ExecEventCType)).contents
                parsed = ExecEvent.from_ctype(event)

                # Validate event
                errors = parsed.validate()
                if errors:
                    logger.warning(f"Invalid event: {errors}")
                    return

                # Queue for processing
                if not self.events_queue.full():
                    self.events_queue.put_nowait(parsed.to_dict())
                else:
                    logger.debug("Events queue full, dropping event")

            except Exception as e:
                logger.error(f"Error handling exec event: {e}")

        def handle_alert_event(cpu, data, size):
            """Handle alert from ring buffer."""
            try:
                event = ctypes.cast(data, ctypes.POINTER(AlertEventCType)).contents
                parsed = AlertEvent.from_ctype(event)

                # Queue alert
                if not self.alerts_queue.full():
                    self.alerts_queue.put_nowait(parsed.to_dict())
                else:
                    logger.debug("Alerts queue full, dropping alert")

            except Exception as e:
                logger.error(f"Error handling alert: {e}")

        # Open ring buffers
        try:
            events_rb = self._bpf.get_events_buffer()
            events_rb.open_ring_buffer(handle_exec_event)

            alerts_rb = self._bpf.get_alerts_buffer()
            alerts_rb.open_ring_buffer(handle_alert_event)

            # Also handle block events if available
            block_rb = self._bpf.get_block_events_buffer()
            if block_rb:
                block_rb.open_ring_buffer(handle_alert_event)

        except Exception as e:
            logger.error(f"Failed to open ring buffers: {e}")
            return

        # Main polling loop
        while self._running:
            try:
                self._bpf.poll_events(self.poll_timeout_ms)
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"Error polling events: {e}")
                time.sleep(0.1)

        logger.info("Collector stopped")


def collector_process(
    events_queue: Queue,
    alerts_queue: Queue,
    probes_dir: str,
    enable_lsm: bool = True,
) -> None:
    """
    Entry point for collector process.

    Args:
        events_queue: Queue for events.
        alerts_queue: Queue for alerts.
        probes_dir: Path to BPF probes directory.
        enable_lsm: Whether to enable LSM hooks.
    """
    from pathlib import Path
    from lotl_detector.bpf.loader import BPFLoader

    try:
        # Load BPF programs
        loader = BPFLoader(
            probes_dir=Path(probes_dir),
            enable_lsm=enable_lsm,
        )
        loader.load()

        # Set detector PID for self-protection
        import os
        loader.set_detector_pid(os.getpid())

        # Run collector
        collector = Collector(events_queue, alerts_queue)
        collector.run(loader)

    except Exception as e:
        logger.error(f"Collector process failed: {e}")
        raise

    finally:
        if "loader" in locals():
            loader.cleanup()

