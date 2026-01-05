"""
BPF Map Helpers for LOTL Detector.

Provides Python wrappers for interacting with BPF maps.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from bcc import BPF

logger = logging.getLogger(__name__)


# Map key constants (must match common.h)
CONFIG_MODE = 0
CONFIG_DETECTOR_PID = 1

# Mode constants
MODE_BOOTSTRAP = 0
MODE_LEARN = 1
MODE_ENFORCE = 2
MODE_PARANOID = 3


class MapHelper:
    """
    Helper for interacting with BPF maps.

    Provides typed access to common operations.
    """

    def __init__(self, bpf: "BPF") -> None:
        """
        Initialize map helper.

        Args:
            bpf: BPF object with loaded programs.
        """
        self._bpf = bpf

    def set_mode(self, mode: int) -> None:
        """
        Set operational mode.

        Args:
            mode: One of MODE_BOOTSTRAP, MODE_LEARN, MODE_ENFORCE, MODE_PARANOID.
        """
        config = self._bpf["config"]
        config[CONFIG_MODE] = mode
        logger.info(f"Set BPF mode to {mode}")

    def get_mode(self) -> int:
        """Get current operational mode."""
        config = self._bpf["config"]
        try:
            return config[CONFIG_MODE].value
        except (KeyError, AttributeError):
            return MODE_BOOTSTRAP

    def set_detector_pid(self, pid: int) -> None:
        """
        Set detector PID for self-protection.

        Args:
            pid: Process ID of the detector.
        """
        config = self._bpf["config"]
        config[CONFIG_DETECTOR_PID] = pid
        logger.debug(f"Set detector PID to {pid}")

    def add_blocked_path(self, path: str) -> None:
        """
        Add a path to the blocklist.

        Args:
            path: Absolute path to block.
        """
        blocklist = self._bpf["blocklist"]
        key = path.encode("utf-8").ljust(256, b"\x00")[:256]
        blocklist[key] = 1
        logger.debug(f"Added blocked path: {path}")

    def remove_blocked_path(self, path: str) -> None:
        """Remove a path from the blocklist."""
        blocklist = self._bpf["blocklist"]
        key = path.encode("utf-8").ljust(256, b"\x00")[:256]
        try:
            del blocklist[key]
            logger.debug(f"Removed blocked path: {path}")
        except KeyError:
            pass

    def add_blocked_inode(self, inode: int) -> None:
        """
        Add an inode to the blocklist.

        Args:
            inode: Inode number to block.
        """
        inode_blocklist = self._bpf["inode_blocklist"]
        inode_blocklist[inode] = 1
        logger.debug(f"Added blocked inode: {inode}")

    def remove_blocked_inode(self, inode: int) -> None:
        """Remove an inode from the blocklist."""
        inode_blocklist = self._bpf["inode_blocklist"]
        try:
            del inode_blocklist[inode]
            logger.debug(f"Removed blocked inode: {inode}")
        except KeyError:
            pass

    def add_blocked_user(self, uid: int) -> None:
        """
        Add a user to the blocklist.

        Args:
            uid: User ID to block.
        """
        user_blocklist = self._bpf["user_blocklist"]
        user_blocklist[uid] = 1
        logger.info(f"Added blocked user: {uid}")

    def remove_blocked_user(self, uid: int) -> None:
        """Remove a user from the blocklist."""
        user_blocklist = self._bpf["user_blocklist"]
        try:
            del user_blocklist[uid]
            logger.info(f"Removed blocked user: {uid}")
        except KeyError:
            pass

    def add_allowed_path(self, path: str) -> None:
        """
        Add a path to the allowlist.

        Args:
            path: Absolute path to allow.
        """
        allowlist = self._bpf["allowlist"]
        key = path.encode("utf-8").ljust(256, b"\x00")[:256]
        allowlist[key] = 1
        logger.debug(f"Added allowed path: {path}")

    def get_stats(self) -> dict[str, int]:
        """Get statistics from BPF maps."""
        stats = self._bpf["stats"]
        result = {}

        try:
            for key, values in stats.items():
                total = sum(v.value for v in values)
                result[f"stat_{key.value}"] = total
        except Exception as e:
            logger.warning(f"Could not read stats: {e}")

        return result

