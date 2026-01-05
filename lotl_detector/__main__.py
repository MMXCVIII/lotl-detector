"""
LOTL Detector - Main Entry Point.

Usage:
    sudo python -m lotl_detector [--config CONFIG] [--mode MODE]
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path

from lotl_detector.core.config import Config, load_config, ensure_directories
from lotl_detector.core.logger import setup_logging, LogConfig
from lotl_detector.core.models import OperationalMode
from lotl_detector.core.panic import PanicButton, create_panic_callback
from lotl_detector.core.shutdown import (
    ShutdownHandler,
    install_signal_handlers,
    create_queue_drain_callback,
)
from lotl_detector.processes.supervisor import Supervisor, SupervisorConfig, QueueManager
from lotl_detector.processes.collector import collector_process
from lotl_detector.processes.analyzer import analyzer_process
from lotl_detector.processes.logger_proc import logger_process

logger = logging.getLogger(__name__)

# Project root for finding probes
PROJECT_ROOT = Path(__file__).parent.parent


def write_health_metrics(
    path: Path,
    supervisor: Supervisor,
    queues: QueueManager,
    mode: OperationalMode,
) -> None:
    """Write health metrics to file."""
    try:
        health = supervisor.check_health()
        queue_stats = queues.get_stats()

        metrics = {
            "timestamp": time.time(),
            "mode": mode.name,
            "healthy": supervisor.is_healthy(),
            "processes": {name: state.value for name, state in health.items()},
            "queues": queue_stats,
            "pids": supervisor.get_all_pids(),
        }

        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(metrics, f, indent=2)

    except Exception as e:
        logger.error(f"Failed to write health metrics: {e}")


def main() -> int:
    """Main entry point."""
    # Parse arguments
    parser = argparse.ArgumentParser(
        description="LOTL Detector - Living off the Land detection and prevention"
    )
    parser.add_argument(
        "--config",
        "-c",
        type=Path,
        help="Path to configuration file",
    )
    parser.add_argument(
        "--mode",
        "-m",
        choices=["bootstrap", "learn", "enforce", "paranoid"],
        help="Operational mode (overrides config)",
    )
    parser.add_argument(
        "--probes-dir",
        type=Path,
        default=PROJECT_ROOT / "probes",
        help="Path to BPF probes directory",
    )
    parser.add_argument(
        "--rules-dir",
        type=Path,
        default=PROJECT_ROOT / "rules",
        help="Path to rules directory",
    )
    parser.add_argument(
        "--no-lsm",
        action="store_true",
        help="Disable LSM hooks (for testing without BPF LSM)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )

    args = parser.parse_args()

    # Check root
    if os.geteuid() != 0:
        print("Error: LOTL Detector requires root privileges", file=sys.stderr)
        print("Run with: sudo python -m lotl_detector", file=sys.stderr)
        return 1

    # Load configuration
    try:
        config = load_config(args.config)
    except Exception as e:
        print(f"Error loading configuration: {e}", file=sys.stderr)
        return 1

    # Override mode if specified
    if args.mode:
        config.mode = args.mode

    # Ensure directories exist
    ensure_directories(config)

    # Set up logging
    log_config = LogConfig(
        level="DEBUG" if args.debug else config.logging.level,
        directory=config.logging.directory,
        max_size_mb=config.logging.max_size_mb,
        backup_count=config.logging.backup_count,
        syslog_enabled=config.logging.syslog_enabled,
    )
    setup_logging(log_config)

    # Get operational mode
    mode = OperationalMode[config.mode.upper()]

    logger.info("=" * 60)
    logger.info("LOTL Detector starting")
    logger.info(f"Mode: {mode.name}")
    logger.info(f"Probes: {args.probes_dir}")
    logger.info(f"Rules: {args.rules_dir}")
    logger.info(f"LSM: {'disabled' if args.no_lsm else 'enabled'}")
    logger.info("=" * 60)

    # Initialize components
    shutdown = ShutdownHandler(timeout_seconds=10.0)
    install_signal_handlers(shutdown)

    queues = QueueManager()
    supervisor = Supervisor(SupervisorConfig(
        max_restarts=5,
        restart_window_seconds=60.0,
        health_check_interval=5.0,
    ))

    # Set up panic button
    panic = PanicButton(
        run_dir=Path(config.run_dir),
        panic_file=config.panic_file,
    )

    # Check if panic is already active
    if panic.is_triggered():
        logger.warning("Panic mode is active - running in observe-only mode")
        mode = OperationalMode.LEARN

    # Database path
    db_path = config.database.path

    # Register processes
    # Note: In production, collector and enforcer would share BPF loader
    # For now, they're separate processes that each load BPF

    supervisor.register(
        "logger",
        logger_process,
        queues.logs,
        config.logging.directory,
        config.logging.level,
        config.logging.syslog_enabled,
    )

    supervisor.register(
        "analyzer",
        analyzer_process,
        queues.events,
        queues.decisions,
        queues.logs,
        str(args.rules_dir),
        db_path,
        mode.name.lower(),
    )

    # Note: collector and enforcer need BPF and must run as root
    # They're implemented but would need the actual BPF loader in prod

    # Register shutdown callbacks
    shutdown.register_callback(
        "drain_queues",
        create_queue_drain_callback([queues.events, queues.decisions, queues.logs]),
        priority=10,
    )

    shutdown.register_callback(
        "stop_supervisor",
        lambda: supervisor.stop_all(timeout=5.0),
        priority=50,
    )

    # Main loop
    try:
        supervisor.start_all()
        logger.info("All processes started")

        health_path = Path(config.health.metrics_path)
        health_interval = config.health.check_interval_seconds

        last_health = 0.0
        last_panic_check = 0.0

        while not shutdown.shutdown_requested:
            now = time.time()

            # Check panic button
            if now - last_panic_check >= 5.0:
                if panic.check_and_handle():
                    # Panic triggered - switch to learn mode
                    mode = OperationalMode.LEARN
                    logger.warning("Panic mode active - observe only")
                last_panic_check = now

            # Write health metrics
            if now - last_health >= health_interval:
                write_health_metrics(health_path, supervisor, queues, mode)
                last_health = now

            # Check supervisor health
            health = supervisor.check_health()
            if not supervisor.is_healthy():
                logger.warning(f"Unhealthy processes: {health}")

            time.sleep(1.0)

    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        shutdown.request_shutdown("Keyboard interrupt")

    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        shutdown.request_shutdown(f"Error: {e}")

    finally:
        # Execute shutdown
        shutdown.execute_shutdown()

    logger.info("LOTL Detector stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())

