"""
BPF Program Loader using bcc.

This module provides a standardized interface for loading and managing
all eBPF programs used by the LOTL detector.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from bcc import BPF

logger = logging.getLogger(__name__)


class BPFLoadError(Exception):
    """Raised when BPF program fails to load."""


class BPFLoader:
    """
    Manages loading and lifecycle of eBPF programs.

    Uses bcc for runtime compilation and loading of BPF programs.
    Handles combining source files and attaching probes.
    """

    # Directory containing BPF source files
    PROBES_DIR = Path(__file__).parent.parent.parent / "probes"

    # Source files in load order
    SOURCE_FILES = [
        "common.h",
        "execve_trace.c",
        "lsm_enforce.c",
    ]

    # Optional Phase 2 source files
    PHASE2_SOURCE_FILES = [
        "memfd_trace.c",
        "module_trace.c",
        "ptrace_trace.c",
        "lsm_self_protect.c",
    ]

    def __init__(
        self,
        probes_dir: Path | None = None,
        enable_lsm: bool = True,
        enable_phase2: bool = True,
    ) -> None:
        """
        Initialize the BPF loader.

        Args:
            probes_dir: Directory containing BPF source files.
            enable_lsm: Whether to load LSM hooks (requires BPF LSM enabled).
            enable_phase2: Whether to load Phase 2 programs.
        """
        self.probes_dir = probes_dir or self.PROBES_DIR
        self.enable_lsm = enable_lsm
        self.enable_phase2 = enable_phase2
        self._bpf: BPF | None = None
        self._loaded = False

    @property
    def bpf(self) -> BPF:
        """Get the loaded BPF object."""
        if self._bpf is None:
            raise BPFLoadError("BPF programs not loaded. Call load() first.")
        return self._bpf

    def _check_lsm_enabled(self) -> bool:
        """Check if BPF LSM is enabled in the kernel."""
        try:
            with open("/sys/kernel/security/lsm") as f:
                lsm_list = f.read().strip()
            return "bpf" in lsm_list.split(",")
        except OSError:
            logger.warning("Could not read LSM list, assuming BPF LSM disabled")
            return False

    def _read_source(self, filename: str) -> str:
        """Read a BPF source file."""
        filepath = self.probes_dir / filename
        if not filepath.exists():
            raise BPFLoadError(f"Source file not found: {filepath}")

        with open(filepath, encoding="utf-8") as f:
            return f.read()

    def _combine_sources(self) -> str:
        """
        Combine all BPF source files into a single program.

        Returns:
            Combined BPF C source code.
        """
        sources = []

        # Always include common.h first
        sources.append(self._read_source("common.h"))

        # Add core source files
        for filename in self.SOURCE_FILES:
            if filename == "common.h":
                continue  # Already added
            if filename == "lsm_enforce.c" and not self.enable_lsm:
                logger.info("Skipping LSM program (BPF LSM not enabled)")
                continue

            try:
                sources.append(f"\n/* ─── {filename} ─── */\n")
                sources.append(self._read_source(filename))
            except BPFLoadError as e:
                logger.warning(f"Could not load {filename}: {e}")

        # Add Phase 2 sources if enabled
        if self.enable_phase2:
            for filename in self.PHASE2_SOURCE_FILES:
                if "lsm" in filename and not self.enable_lsm:
                    continue

                try:
                    filepath = self.probes_dir / filename
                    if filepath.exists():
                        sources.append(f"\n/* ─── {filename} ─── */\n")
                        sources.append(self._read_source(filename))
                except BPFLoadError as e:
                    logger.debug(f"Phase 2 source not found: {filename}")

        return "\n".join(sources)

    def load(self) -> None:
        """
        Load and compile the BPF programs.

        Raises:
            BPFLoadError: If loading fails.
        """
        # Import bcc here to allow module to be imported without bcc
        try:
            from bcc import BPF
        except ImportError as e:
            raise BPFLoadError(
                "bcc module not installed. Install with: sudo apt install python3-bpfcc"
            ) from e

        # Check root
        if os.geteuid() != 0:
            raise BPFLoadError("Root privileges required to load BPF programs")

        # Check LSM availability
        if self.enable_lsm and not self._check_lsm_enabled():
            logger.warning(
                "BPF LSM not enabled. LSM hooks will be skipped. "
                "To enable, add 'bpf' to kernel lsm= parameter and reboot."
            )
            self.enable_lsm = False

        # Combine source files
        try:
            combined_source = self._combine_sources()
        except Exception as e:
            raise BPFLoadError(f"Failed to read BPF sources: {e}") from e

        logger.info("Compiling BPF programs...")

        # Load BPF program
        try:
            self._bpf = BPF(text=combined_source)
            self._loaded = True
            logger.info("BPF programs loaded successfully")
        except Exception as e:
            raise BPFLoadError(f"Failed to compile BPF program: {e}") from e

        # Attach probes
        self._attach_probes()

    def _attach_probes(self) -> None:
        """Attach BPF programs to their hooks."""
        if not self._loaded:
            return

        logger.info("Attaching BPF probes...")

        # Tracepoints are automatically attached by bcc when using
        # TRACEPOINT_PROBE macro

        # LSM hooks are automatically attached by bcc when using
        # LSM_PROBE macro (if LSM is enabled)

        logger.info("BPF probes attached")

    def get_events_buffer(self):
        """Get the events ring buffer."""
        return self.bpf["events"]

    def get_alerts_buffer(self):
        """Get the alerts ring buffer."""
        return self.bpf["alerts"]

    def get_block_events_buffer(self):
        """Get the block events ring buffer."""
        try:
            return self.bpf["block_events"]
        except KeyError:
            return None

    def get_stats_map(self):
        """Get the statistics map."""
        return self.bpf["stats"]

    def get_config_map(self):
        """Get the configuration map."""
        return self.bpf["config"]

    def get_blocklist_map(self):
        """Get the path blocklist map."""
        return self.bpf["blocklist"]

    def get_inode_blocklist_map(self):
        """Get the inode blocklist map."""
        return self.bpf["inode_blocklist"]

    def get_user_blocklist_map(self):
        """Get the user blocklist map."""
        return self.bpf["user_blocklist"]

    def get_allowlist_map(self):
        """Get the allowlist map."""
        return self.bpf["allowlist"]

    def get_ancestry_map(self):
        """Get the ancestry allowlist map."""
        return self.bpf["ancestry_allow"]

    def set_mode(self, mode: int) -> None:
        """
        Set the operational mode.

        Args:
            mode: One of MODE_BOOTSTRAP (0), MODE_LEARN (1),
                  MODE_ENFORCE (2), MODE_PARANOID (3)
        """
        config = self.get_config_map()
        config[0] = mode  # CONFIG_MODE = 0
        logger.info(f"Set operational mode to {mode}")

    def set_detector_pid(self, pid: int) -> None:
        """Set the detector's PID for self-protection."""
        config = self.get_config_map()
        config[1] = pid  # CONFIG_DETECTOR_PID = 1
        logger.debug(f"Set detector PID to {pid}")

    def add_to_blocklist(self, path: str) -> None:
        """Add a path to the blocklist."""
        blocklist = self.get_blocklist_map()
        key = path.encode("utf-8").ljust(256, b"\x00")[:256]
        blocklist[key] = 1
        logger.debug(f"Added to blocklist: {path}")

    def add_inode_to_blocklist(self, inode: int) -> None:
        """Add an inode to the blocklist."""
        inode_blocklist = self.get_inode_blocklist_map()
        inode_blocklist[inode] = 1
        logger.debug(f"Added inode to blocklist: {inode}")

    def add_user_to_blocklist(self, uid: int) -> None:
        """Add a user to the blocklist."""
        user_blocklist = self.get_user_blocklist_map()
        user_blocklist[uid] = 1
        logger.debug(f"Added user to blocklist: {uid}")

    def add_to_allowlist(self, path: str) -> None:
        """Add a path to the allowlist."""
        allowlist = self.get_allowlist_map()
        key = path.encode("utf-8").ljust(256, b"\x00")[:256]
        allowlist[key] = 1
        logger.debug(f"Added to allowlist: {path}")

    def cleanup(self) -> None:
        """Clean up BPF resources."""
        if self._bpf is not None:
            logger.info("Cleaning up BPF resources")
            # Note: bcc handles cleanup when object is garbage collected
            # but we explicitly clear our reference
            self._bpf = None
            self._loaded = False

    def poll_events(self, timeout_ms: int = 100):
        """
        Poll for events from ring buffers.

        Args:
            timeout_ms: Timeout in milliseconds.

        This is a generator that yields events from the ring buffers.
        """
        if not self._loaded:
            return

        self.bpf.ring_buffer_poll(timeout_ms)

    def __enter__(self) -> "BPFLoader":
        """Context manager entry."""
        self.load()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit."""
        self.cleanup()

