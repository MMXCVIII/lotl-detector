"""
Process Supervisor for LOTL Detector.

Manages worker processes with:
- Automatic restart on crash
- Health monitoring
- Graceful shutdown coordination
"""

from __future__ import annotations

import logging
import multiprocessing
import os
import signal
import time
from dataclasses import dataclass, field
from enum import Enum
from multiprocessing import Process, Queue
from typing import Callable

logger = logging.getLogger(__name__)


class ProcessState(Enum):
    """Process lifecycle states."""

    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    CRASHED = "crashed"
    FAILED = "failed"  # Too many crashes


@dataclass
class ProcessInfo:
    """Information about a managed process."""

    name: str
    target: Callable
    args: tuple = ()
    kwargs: dict = field(default_factory=dict)
    process: Process | None = None
    state: ProcessState = ProcessState.STOPPED
    start_count: int = 0
    crash_count: int = 0
    last_start: float = 0.0
    last_crash: float = 0.0


@dataclass
class SupervisorConfig:
    """Supervisor configuration."""

    # Maximum restarts within window before marking as failed
    max_restarts: int = 5
    restart_window_seconds: float = 60.0

    # Delay between restart attempts
    restart_delay_seconds: float = 1.0

    # Health check interval
    health_check_interval: float = 5.0

    # Graceful shutdown timeout
    shutdown_timeout_seconds: float = 10.0


class Supervisor:
    """
    Process supervisor with automatic restart.

    Manages multiple worker processes and ensures they stay running.
    """

    def __init__(self, config: SupervisorConfig | None = None) -> None:
        """
        Initialize supervisor.

        Args:
            config: Supervisor configuration.
        """
        self.config = config or SupervisorConfig()
        self._processes: dict[str, ProcessInfo] = {}
        self._running = False
        self._shutdown_requested = False

    def register(
        self,
        name: str,
        target: Callable,
        *args,
        **kwargs,
    ) -> None:
        """
        Register a process to be supervised.

        Args:
            name: Unique name for the process.
            target: Function to run in the process.
            *args: Arguments to pass to the function.
            **kwargs: Keyword arguments to pass to the function.
        """
        if name in self._processes:
            raise ValueError(f"Process already registered: {name}")

        self._processes[name] = ProcessInfo(
            name=name,
            target=target,
            args=args,
            kwargs=kwargs,
        )
        logger.debug(f"Registered process: {name}")

    def start_all(self) -> None:
        """Start all registered processes."""
        logger.info("Starting all supervised processes")
        self._running = True

        for name in self._processes:
            self._start_process(name)

    def _start_process(self, name: str) -> bool:
        """
        Start a single process.

        Args:
            name: Name of the process to start.

        Returns:
            True if started successfully.
        """
        info = self._processes.get(name)
        if not info:
            return False

        # Check if we've exceeded restart limit
        now = time.time()
        if info.crash_count >= self.config.max_restarts:
            if now - info.last_crash < self.config.restart_window_seconds:
                logger.error(f"Process {name} exceeded restart limit, marking as failed")
                info.state = ProcessState.FAILED
                return False
            else:
                # Reset crash count after window
                info.crash_count = 0

        # Create and start process
        info.state = ProcessState.STARTING
        info.process = Process(
            target=info.target,
            args=info.args,
            kwargs=info.kwargs,
            name=name,
            daemon=True,
        )
        info.process.start()
        info.start_count += 1
        info.last_start = now
        info.state = ProcessState.RUNNING

        logger.info(f"Started process: {name} (PID {info.process.pid})")
        return True

    def stop_all(self, timeout: float | None = None) -> None:
        """
        Stop all processes gracefully.

        Args:
            timeout: Maximum time to wait for processes to stop.
        """
        timeout = timeout or self.config.shutdown_timeout_seconds
        self._shutdown_requested = True
        self._running = False

        logger.info("Stopping all supervised processes")

        # Request graceful shutdown
        for name, info in self._processes.items():
            if info.process and info.process.is_alive():
                info.state = ProcessState.STOPPING
                # Send SIGTERM
                try:
                    os.kill(info.process.pid, signal.SIGTERM)
                except (OSError, ProcessLookupError):
                    pass

        # Wait for processes to exit
        deadline = time.time() + timeout
        for name, info in self._processes.items():
            if info.process:
                remaining = max(0, deadline - time.time())
                info.process.join(timeout=remaining)

                if info.process.is_alive():
                    logger.warning(f"Process {name} did not exit gracefully, killing")
                    info.process.kill()
                    info.process.join(timeout=1)

                info.state = ProcessState.STOPPED
                info.process = None

        logger.info("All processes stopped")

    def check_health(self) -> dict[str, ProcessState]:
        """
        Check health of all processes.

        Returns:
            Dictionary of process names to their states.
        """
        health = {}

        for name, info in self._processes.items():
            if info.process is None:
                health[name] = info.state
            elif info.process.is_alive():
                health[name] = ProcessState.RUNNING
            else:
                # Process died
                exit_code = info.process.exitcode
                info.crash_count += 1
                info.last_crash = time.time()
                info.state = ProcessState.CRASHED
                health[name] = ProcessState.CRASHED

                logger.warning(
                    f"Process {name} crashed with exit code {exit_code} "
                    f"(crash #{info.crash_count})"
                )

                # Restart if running and not shutting down
                if self._running and not self._shutdown_requested:
                    time.sleep(self.config.restart_delay_seconds)
                    self._start_process(name)

        return health

    def run_forever(self) -> None:
        """
        Run the supervisor loop forever.

        Monitors processes and restarts them as needed.
        """
        self.start_all()

        try:
            while self._running and not self._shutdown_requested:
                self.check_health()
                time.sleep(self.config.health_check_interval)

        except KeyboardInterrupt:
            logger.info("Supervisor interrupted")

        finally:
            self.stop_all()

    def get_process_info(self, name: str) -> ProcessInfo | None:
        """Get information about a process."""
        return self._processes.get(name)

    def get_all_pids(self) -> list[int]:
        """Get PIDs of all running processes."""
        pids = []
        for info in self._processes.values():
            if info.process and info.process.is_alive():
                pids.append(info.process.pid)
        return pids

    def is_healthy(self) -> bool:
        """Check if all processes are healthy."""
        for info in self._processes.values():
            if info.state in (ProcessState.CRASHED, ProcessState.FAILED):
                return False
            if info.process and not info.process.is_alive():
                return False
        return True


# ─────────────────────────────────────────────────────────────────────────────
# Queue Manager
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class QueueConfig:
    """Queue configuration."""

    events_size: int = 10000
    decisions_size: int = 1000
    logs_size: int = 5000


class QueueManager:
    """
    Manages bounded queues for inter-process communication.

    Provides backpressure handling when queues are full.
    """

    def __init__(self, config: QueueConfig | None = None) -> None:
        """
        Initialize queue manager.

        Args:
            config: Queue configuration.
        """
        self.config = config or QueueConfig()

        # Create bounded queues
        self.events: Queue = Queue(maxsize=self.config.events_size)
        self.decisions: Queue = Queue(maxsize=self.config.decisions_size)
        self.logs: Queue = Queue(maxsize=self.config.logs_size)

        # Backpressure statistics
        self._dropped_events = multiprocessing.Value("i", 0)
        self._dropped_decisions = multiprocessing.Value("i", 0)
        self._dropped_logs = multiprocessing.Value("i", 0)

    def put_event(self, event, block: bool = False, timeout: float = 0.1) -> bool:
        """
        Put an event on the queue.

        Args:
            event: Event to queue.
            block: Whether to block if queue is full.
            timeout: Timeout for blocking.

        Returns:
            True if queued, False if dropped.
        """
        try:
            self.events.put(event, block=block, timeout=timeout)
            return True
        except:
            with self._dropped_events.get_lock():
                self._dropped_events.value += 1
            return False

    def put_decision(self, decision, block: bool = False, timeout: float = 0.1) -> bool:
        """Put a decision on the queue."""
        try:
            self.decisions.put(decision, block=block, timeout=timeout)
            return True
        except:
            with self._dropped_decisions.get_lock():
                self._dropped_decisions.value += 1
            return False

    def put_log(self, log_entry, block: bool = False, timeout: float = 0.1) -> bool:
        """Put a log entry on the queue."""
        try:
            self.logs.put(log_entry, block=block, timeout=timeout)
            return True
        except:
            with self._dropped_logs.get_lock():
                self._dropped_logs.value += 1
            return False

    def get_stats(self) -> dict:
        """Get queue statistics."""
        return {
            "events_size": self.events.qsize(),
            "decisions_size": self.decisions.qsize(),
            "logs_size": self.logs.qsize(),
            "dropped_events": self._dropped_events.value,
            "dropped_decisions": self._dropped_decisions.value,
            "dropped_logs": self._dropped_logs.value,
        }

    def drain_all(self, timeout: float = 5.0) -> None:
        """
        Drain all queues.

        Args:
            timeout: Maximum time to wait for draining.
        """
        deadline = time.time() + timeout

        for queue in [self.events, self.decisions, self.logs]:
            while not queue.empty() and time.time() < deadline:
                try:
                    queue.get_nowait()
                except:
                    break

