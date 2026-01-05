"""
Busybox detection for LOTL Detector.

Detects when busybox is being used to invoke dangerous applets,
which is a common technique to evade detection.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from lotl_detector.core.models import AlertEvent, AlertType, ExecEvent, SeverityLevel

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Dangerous Applets
# ─────────────────────────────────────────────────────────────────────────────

# Applets that are dangerous and should be monitored
DANGEROUS_APPLETS = {
    # Network tools
    "nc": ("critical", "T1059.004", "Network connection tool"),
    "netcat": ("critical", "T1059.004", "Network connection tool"),
    "wget": ("high", "T1105", "File download tool"),
    "telnet": ("high", "T1059.004", "Remote access tool"),
    "tftp": ("high", "T1105", "File transfer tool"),
    "ftpget": ("high", "T1105", "FTP download tool"),
    "ftpput": ("high", "T1041", "FTP upload tool"),
    "httpd": ("medium", "T1071.001", "HTTP server"),
    
    # Shell access
    "sh": ("medium", "T1059.004", "Shell interpreter"),
    "ash": ("medium", "T1059.004", "Shell interpreter"),
    "bash": ("medium", "T1059.004", "Shell interpreter"),
    
    # File operations (can be used for exfil/staging)
    "dd": ("medium", "T1005", "Data copy tool"),
    "tar": ("medium", "T1560.001", "Archive creation tool"),
    "gzip": ("low", "T1560.001", "Compression tool"),
    "gunzip": ("low", "T1560.001", "Decompression tool"),
    "unzip": ("low", "T1560.001", "Decompression tool"),
    
    # Crypto
    "cryptpw": ("high", "T1552", "Password hashing tool"),
    "ssl_client": ("high", "T1573.002", "SSL client"),
    
    # System modification
    "mount": ("high", "T1059.004", "Filesystem mount"),
    "umount": ("medium", "T1059.004", "Filesystem unmount"),
    "insmod": ("critical", "T1547.006", "Kernel module insertion"),
    "rmmod": ("high", "T1547.006", "Kernel module removal"),
    "modprobe": ("critical", "T1547.006", "Kernel module management"),
    
    # User management
    "adduser": ("critical", "T1136.001", "User creation"),
    "addgroup": ("high", "T1136.001", "Group creation"),
    "passwd": ("high", "T1098", "Password change"),
    "su": ("high", "T1548.003", "Switch user"),
    
    # Process management
    "nohup": ("medium", "T1059.004", "Persistent execution"),
    "start-stop-daemon": ("medium", "T1543", "Service management"),
}

# Applets that are always blocked in enforce mode
BLOCKED_APPLETS = {"nc", "netcat", "telnet"}


# ─────────────────────────────────────────────────────────────────────────────
# Busybox Detector
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class BusyboxConfig:
    """Busybox detection configuration."""

    # Block dangerous applets in enforce mode
    block_dangerous: bool = True

    # Log all busybox usage
    log_all_usage: bool = True

    # Additional applets to block
    additional_blocked: list[str] = None

    def __post_init__(self):
        if self.additional_blocked is None:
            self.additional_blocked = []


class BusyboxDetector:
    """
    Detects and alerts on busybox applet usage.

    Busybox is a single binary containing many Unix utilities.
    Attackers use it to evade detection since the binary name
    is always "busybox" regardless of which tool is invoked.
    """

    # Known busybox paths
    BUSYBOX_PATHS = {
        "/bin/busybox",
        "/usr/bin/busybox",
        "/sbin/busybox",
        "/usr/sbin/busybox",
    }

    def __init__(self, config: BusyboxConfig | None = None) -> None:
        """
        Initialize busybox detector.

        Args:
            config: Detection configuration.
        """
        self.config = config or BusyboxConfig()

        # Build blocked set
        self.blocked_applets = BLOCKED_APPLETS.copy()
        self.blocked_applets.update(self.config.additional_blocked or [])

    def is_busybox(self, filename: str) -> bool:
        """
        Check if a filename is busybox.

        Args:
            filename: Path to check.

        Returns:
            True if this is busybox.
        """
        # Direct path match
        if filename in self.BUSYBOX_PATHS:
            return True

        # Check if ends with /busybox
        return filename.endswith("/busybox")

    def extract_applet(self, event: ExecEvent) -> str | None:
        """
        Extract the applet name from a busybox invocation.

        Busybox can be invoked as:
        - busybox <applet> [args]
        - <symlink-to-busybox> [args]

        Args:
            event: Exec event.

        Returns:
            Applet name, or None if not detectable.
        """
        if not self.is_busybox(event.filename):
            return None

        # If invoked as "busybox <applet>", argv[1] is the applet
        if event.args and len(event.args) >= 2:
            # argv[0] is "busybox", argv[1] is applet
            applet = event.args[1] if event.args[0].endswith("busybox") else event.args[0]
            # Remove any path prefix
            if "/" in applet:
                applet = applet.rsplit("/", 1)[-1]
            return applet

        # If invoked via symlink, argv[0] is the applet name
        if event.args:
            applet = event.args[0]
            if "/" in applet:
                applet = applet.rsplit("/", 1)[-1]
            if applet != "busybox":
                return applet

        # Check if the event already has applet extracted by BPF
        if event.busybox_applet:
            return event.busybox_applet

        return None

    def analyze(self, event: ExecEvent) -> tuple[list[AlertEvent], bool]:
        """
        Analyze a busybox event.

        Args:
            event: Exec event to analyze.

        Returns:
            Tuple of (alerts, should_block).
        """
        alerts = []
        should_block = False

        if not event.is_busybox and not self.is_busybox(event.filename):
            return (alerts, should_block)

        applet = self.extract_applet(event)
        if not applet:
            # Can't determine applet - log generic busybox usage
            if self.config.log_all_usage:
                logger.info(f"Busybox invocation detected: PID {event.pid}")
            return (alerts, should_block)

        # Check if applet is blocked
        if applet in self.blocked_applets:
            should_block = self.config.block_dangerous
            severity = SeverityLevel.CRITICAL
            description = f"Blocked busybox applet: {applet}"
        elif applet in DANGEROUS_APPLETS:
            severity_str, mitre, desc = DANGEROUS_APPLETS[applet]
            severity = SeverityLevel[severity_str.upper()]
            description = f"Busybox {applet}: {desc}"
        else:
            # Unknown or benign applet
            if self.config.log_all_usage:
                logger.debug(f"Busybox applet: {applet} (PID {event.pid})")
            return (alerts, should_block)

        # Create alert
        alert = AlertEvent(
            timestamp_ns=event.timestamp_ns,
            pid=event.pid,
            uid=event.uid,
            alert_type=AlertType.BLOCKED_EXEC if should_block else AlertType.MEMFD_EXEC,
            severity=severity,
            target_pid=0,
            comm=event.comm,
            filename=event.filename,
            rule_id=f"busybox-{applet}",
            description=description,
            mitre_technique=DANGEROUS_APPLETS.get(applet, ("", "", ""))[1],
        )
        alerts.append(alert)

        if self.config.log_all_usage:
            logger.warning(
                f"Busybox applet detected: {applet} "
                f"(PID {event.pid}, UID {event.uid}, block={should_block})"
            )

        return (alerts, should_block)

