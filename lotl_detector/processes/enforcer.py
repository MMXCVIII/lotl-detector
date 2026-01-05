"""
Map Enforcer for LOTL Detector.

Synchronizes BPF map updates based on analyzer decisions.
"""

from __future__ import annotations

import logging
import os
import signal
import stat
import time
from multiprocessing import Queue
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

if TYPE_CHECKING:
    from lotl_detector.bpf.loader import BPFLoader

logger = logging.getLogger(__name__)


class Enforcer:
    """
    Enforces detection decisions by updating BPF maps.

    Handles:
    - User blocklist updates
    - Mode switching
    - Inode blocklist population
    """

    def __init__(
        self,
        decisions_queue: Queue,
        rules_dir: Path,
    ) -> None:
        """
        Initialize enforcer.

        Args:
            decisions_queue: Queue to receive decisions from.
            rules_dir: Path to rules directory.
        """
        self.decisions_queue = decisions_queue
        self.rules_dir = rules_dir
        self._running = False
        self._bpf: BPFLoader | None = None

    def _handle_shutdown(self, signum, frame):
        """Handle shutdown signal."""
        logger.info("Enforcer received shutdown signal")
        self._running = False

    def populate_blocklists(self, bpf_loader: "BPFLoader") -> None:
        """
        Populate blocklists from rule files.

        Args:
            bpf_loader: BPF loader instance.
        """
        # Load tier1 rules
        tier1_path = self.rules_dir / "tier1_blocklist.yaml"
        if tier1_path.exists():
            with open(tier1_path) as f:
                data = yaml.safe_load(f)

            # Add paths to blocklist
            for entry in data.get("blocked_paths", []):
                path = entry.get("path")
                if path:
                    bpf_loader.add_to_blocklist(path)

                    # Also add inode
                    try:
                        inode = os.stat(path).st_ino
                        bpf_loader.add_inode_to_blocklist(inode)
                        logger.debug(f"Blocked path and inode: {path} ({inode})")
                    except OSError:
                        logger.debug(f"Path not found, blocking path only: {path}")

            # Add explicit inodes
            for inode in data.get("blocked_inodes", []):
                if isinstance(inode, int):
                    bpf_loader.add_inode_to_blocklist(inode)

            # Add blocked users
            for entry in data.get("blocked_users", []):
                uid = entry.get("uid")
                if uid is not None:
                    bpf_loader.add_user_to_blocklist(uid)
                    logger.info(f"Blocked user: {uid}")

        logger.info("Blocklists populated from rules")

    def handle_decision(self, decision: dict[str, Any]) -> None:
        """
        Handle a detection decision.

        Args:
            decision: Decision dictionary from analyzer.
        """
        if not self._bpf:
            return

        event = decision.get("event", {})
        should_block = decision.get("should_block", False)
        matched_rules = decision.get("matched_rules", [])

        if not should_block:
            return

        # Log blocking action
        logger.warning(
            f"Blocking action: PID {event.get('pid')} "
            f"({event.get('filename')}) rules={matched_rules}"
        )

        # For user-based blocking (after first offense)
        # This is commented out as it's aggressive - enable with care
        # uid = event.get("uid")
        # if uid and uid != 0:  # Don't block root
        #     self._bpf.add_user_to_blocklist(uid)
        #     logger.warning(f"Added user {uid} to blocklist")

    def run(self, bpf_loader: "BPFLoader") -> None:
        """
        Run the enforcer loop.

        Args:
            bpf_loader: BPF loader instance.
        """
        signal.signal(signal.SIGTERM, self._handle_shutdown)
        signal.signal(signal.SIGINT, self._handle_shutdown)

        self._bpf = bpf_loader
        self._running = True

        # Initial blocklist population
        self.populate_blocklists(bpf_loader)

        logger.info("Enforcer started")

        while self._running:
            try:
                # Get decision from queue
                try:
                    decision = self.decisions_queue.get(timeout=0.1)
                    self.handle_decision(decision)
                except:
                    continue

            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"Error handling decision: {e}")

        logger.info("Enforcer stopped")


def enforcer_process(
    decisions_queue: Queue,
    rules_dir: str,
    probes_dir: str,
    enable_lsm: bool = True,
) -> None:
    """
    Entry point for enforcer process.

    Args:
        decisions_queue: Queue for decisions.
        rules_dir: Path to rules directory.
        probes_dir: Path to BPF probes directory.
        enable_lsm: Whether to enable LSM hooks.
    """
    from lotl_detector.bpf.loader import BPFLoader

    try:
        # Load BPF programs
        loader = BPFLoader(
            probes_dir=Path(probes_dir),
            enable_lsm=enable_lsm,
        )
        loader.load()

        # Run enforcer
        enforcer = Enforcer(
            decisions_queue=decisions_queue,
            rules_dir=Path(rules_dir),
        )
        enforcer.run(loader)

    except Exception as e:
        logger.error(f"Enforcer process failed: {e}")
        raise

    finally:
        if "loader" in locals():
            loader.cleanup()

