"""
Graceful Shutdown for LOTL Detector.

Handles clean shutdown with:
- Queue draining
- Log flushing
- Resource cleanup
"""

from __future__ import annotations

import logging
import signal
import time
from typing import Callable

logger = logging.getLogger(__name__)


class ShutdownHandler:
    """
    Manages graceful shutdown.

    Coordinates shutdown across multiple components with
    proper ordering and timeouts.
    """

    def __init__(
        self,
        timeout_seconds: float = 10.0,
    ) -> None:
        """
        Initialize shutdown handler.

        Args:
            timeout_seconds: Maximum time to wait for shutdown.
        """
        self.timeout = timeout_seconds
        self._shutdown_requested = False
        self._shutdown_complete = False
        self._callbacks: list[tuple[str, Callable[[], None], int]] = []

    def register_callback(
        self,
        name: str,
        callback: Callable[[], None],
        priority: int = 50,
    ) -> None:
        """
        Register a shutdown callback.

        Callbacks are called in priority order (lower first).

        Args:
            name: Name for logging.
            callback: Function to call during shutdown.
            priority: Execution priority (0 = first, 100 = last).
        """
        self._callbacks.append((name, callback, priority))
        self._callbacks.sort(key=lambda x: x[2])

    def request_shutdown(self, reason: str = "Unknown") -> None:
        """
        Request graceful shutdown.

        Args:
            reason: Reason for shutdown.
        """
        if self._shutdown_requested:
            logger.warning("Shutdown already in progress")
            return

        logger.info(f"Shutdown requested: {reason}")
        self._shutdown_requested = True

    @property
    def shutdown_requested(self) -> bool:
        """Check if shutdown has been requested."""
        return self._shutdown_requested

    def execute_shutdown(self) -> bool:
        """
        Execute shutdown sequence.

        Returns:
            True if shutdown completed cleanly.
        """
        if self._shutdown_complete:
            return True

        logger.info("Executing shutdown sequence")
        start_time = time.time()
        success = True

        for name, callback, priority in self._callbacks:
            remaining = self.timeout - (time.time() - start_time)
            if remaining <= 0:
                logger.error(f"Shutdown timeout, skipping remaining callbacks")
                success = False
                break

            logger.debug(f"Shutdown callback: {name} (priority {priority})")
            try:
                callback()
            except Exception as e:
                logger.error(f"Shutdown callback {name} failed: {e}")
                success = False

        elapsed = time.time() - start_time
        self._shutdown_complete = True

        if success:
            logger.info(f"Shutdown completed in {elapsed:.2f}s")
        else:
            logger.warning(f"Shutdown completed with errors in {elapsed:.2f}s")

        return success


def install_signal_handlers(shutdown_handler: ShutdownHandler) -> None:
    """
    Install signal handlers for graceful shutdown.

    Args:
        shutdown_handler: Shutdown handler instance.
    """

    def signal_handler(signum, frame):
        sig_name = signal.Signals(signum).name
        shutdown_handler.request_shutdown(f"Signal {sig_name}")

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    logger.debug("Installed shutdown signal handlers")


def create_queue_drain_callback(
    queues: list,
    timeout: float = 5.0,
) -> Callable[[], None]:
    """
    Create a callback that drains queues.

    Args:
        queues: List of queues to drain.
        timeout: Timeout for draining.

    Returns:
        Callback function.
    """

    def callback() -> None:
        logger.debug("Draining queues")
        deadline = time.time() + timeout

        for q in queues:
            while not q.empty() and time.time() < deadline:
                try:
                    q.get_nowait()
                except Exception:
                    break

    return callback


def create_bpf_cleanup_callback(
    loader,
) -> Callable[[], None]:
    """
    Create a callback that cleans up BPF resources.

    Args:
        loader: BPF loader instance.

    Returns:
        Callback function.
    """

    def callback() -> None:
        logger.debug("Cleaning up BPF resources")
        # Note: BPF programs may stay loaded after process exit
        # This is documented behavior - they'll be removed on reboot
        # or when explicitly unloaded
        try:
            loader.cleanup()
        except Exception as e:
            logger.warning(f"BPF cleanup error: {e}")

    return callback

