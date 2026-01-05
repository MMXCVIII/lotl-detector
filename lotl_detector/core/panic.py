"""
Panic Button for LOTL Detector.

Provides emergency disable functionality via:
- File-based trigger (/var/run/lotl/DISABLE)
- Kernel command line (lotl.disable=1)

When activated, switches detector to observe-only mode.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Callable

logger = logging.getLogger(__name__)


class PanicButton:
    """
    Emergency disable mechanism.

    Monitors for panic triggers and calls the provided callback
    when activated.
    """

    def __init__(
        self,
        run_dir: Path | str = "/var/run/lotl",
        panic_file: str = "DISABLE",
        callback: Callable[[], None] | None = None,
    ) -> None:
        """
        Initialize panic button.

        Args:
            run_dir: Runtime directory.
            panic_file: Name of panic trigger file.
            callback: Function to call when panic is triggered.
        """
        self.run_dir = Path(run_dir)
        self.panic_file = panic_file
        self.callback = callback
        self._last_check_result = False

    @property
    def panic_path(self) -> Path:
        """Get full path to panic file."""
        return self.run_dir / self.panic_file

    def check_file_trigger(self) -> bool:
        """
        Check if panic file exists.

        Returns:
            True if panic file exists.
        """
        return self.panic_path.exists()

    def check_cmdline_trigger(self) -> bool:
        """
        Check kernel command line for panic trigger.

        Returns:
            True if lotl.disable=1 is in command line.
        """
        try:
            with open("/proc/cmdline") as f:
                cmdline = f.read()
            return "lotl.disable=1" in cmdline
        except OSError:
            return False

    def is_triggered(self) -> bool:
        """
        Check if any panic trigger is active.

        Returns:
            True if panic is triggered.
        """
        return self.check_file_trigger() or self.check_cmdline_trigger()

    def check_and_handle(self) -> bool:
        """
        Check for panic triggers and handle if found.

        Returns:
            True if panic was triggered and handled.
        """
        triggered = self.is_triggered()

        if triggered and not self._last_check_result:
            # Newly triggered
            logger.critical("PANIC TRIGGERED - Switching to observe-only mode")

            if self.check_file_trigger():
                logger.info(f"Trigger: panic file ({self.panic_path})")
            if self.check_cmdline_trigger():
                logger.info("Trigger: kernel command line (lotl.disable=1)")

            if self.callback:
                try:
                    self.callback()
                except Exception as e:
                    logger.error(f"Panic callback failed: {e}")

        elif not triggered and self._last_check_result:
            # Panic cleared
            logger.info("Panic condition cleared")

        self._last_check_result = triggered
        return triggered

    def activate(self, reason: str = "Manual activation") -> None:
        """
        Manually activate panic mode.

        Args:
            reason: Reason for activation.
        """
        logger.critical(f"Panic manually activated: {reason}")

        # Create panic file
        try:
            self.run_dir.mkdir(parents=True, exist_ok=True)
            with open(self.panic_path, "w") as f:
                f.write(f"Activated: {reason}\n")
        except OSError as e:
            logger.error(f"Could not create panic file: {e}")

        if self.callback:
            self.callback()

    def deactivate(self) -> None:
        """
        Deactivate panic mode.

        Note: Cannot clear kernel command line - requires reboot.
        """
        if self.check_cmdline_trigger():
            logger.warning(
                "Panic deactivated but kernel cmdline still has lotl.disable=1. "
                "Reboot required to fully clear."
            )

        # Remove panic file
        try:
            if self.panic_path.exists():
                self.panic_path.unlink()
                logger.info("Panic file removed")
        except OSError as e:
            logger.error(f"Could not remove panic file: {e}")

        self._last_check_result = False


def create_panic_callback(
    set_mode_func: Callable[[int], None],
    learn_mode: int = 1,
) -> Callable[[], None]:
    """
    Create a panic callback that switches to learn mode.

    Args:
        set_mode_func: Function to set operational mode.
        learn_mode: Mode value for learn/observe-only.

    Returns:
        Callback function.
    """

    def callback() -> None:
        logger.info("Panic callback: switching to learn mode")
        set_mode_func(learn_mode)

    return callback

