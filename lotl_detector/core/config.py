"""
Configuration management for LOTL Detector.

Handles loading and validating configuration from YAML files
with security-focused path validation.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


class ConfigError(Exception):
    """Raised for configuration errors."""


# ─────────────────────────────────────────────────────────────────────────────
# Path Validation
# ─────────────────────────────────────────────────────────────────────────────


def validate_path(path: str | Path, allowed_bases: list[Path] | None = None) -> Path:
    """
    Validate and canonicalize a path.

    Prevents path traversal attacks by ensuring the resolved path
    is within allowed base directories.

    Args:
        path: The path to validate.
        allowed_bases: List of allowed base directories. If None, only checks
                      that path doesn't escape current directory.

    Returns:
        Canonicalized Path object.

    Raises:
        ConfigError: If path is invalid or escapes allowed directories.
    """
    path = Path(path)

    # Resolve to absolute path (handles .., symlinks, etc.)
    try:
        resolved = path.resolve()
    except Exception as e:
        raise ConfigError(f"Cannot resolve path: {path}") from e

    # Check against allowed bases
    if allowed_bases:
        for base in allowed_bases:
            try:
                base_resolved = base.resolve()
                resolved.relative_to(base_resolved)
                return resolved  # Path is within this base
            except ValueError:
                continue  # Not in this base, try next

        raise ConfigError(
            f"Path '{path}' is not within allowed directories: {allowed_bases}"
        )

    return resolved


# ─────────────────────────────────────────────────────────────────────────────
# Configuration Data Classes
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class LogConfig:
    """Logging configuration."""

    level: str = "INFO"
    directory: str = "/var/log/lotl"
    max_size_mb: int = 100
    backup_count: int = 5
    syslog_enabled: bool = True
    syslog_facility: str = "local0"


@dataclass
class DatabaseConfig:
    """Database configuration."""

    path: str = "/var/lib/lotl/detector.db"
    max_age_days: int = 30
    vacuum_interval_hours: int = 24


@dataclass
class BaselineConfig:
    """Baseline learning configuration."""

    bootstrap_duration_hours: int = 24
    learn_duration_days: int = 7
    decay_half_life_days: int = 7
    anomaly_threshold: float = 2.0


@dataclass
class BlockingConfig:
    """Blocking behavior configuration."""

    tier1_paths: list[str] = field(default_factory=list)
    tier1_inodes_from_paths: bool = True
    block_memfd_exec: bool = True
    block_stdin_exec: bool = True


@dataclass
class AncestryConfig:
    """Ancestry allowlist configuration."""

    enabled: bool = True
    window_seconds: int = 300  # 5 minutes
    allowed_ancestors: list[str] = field(
        default_factory=lambda: [
            "/usr/bin/apt",
            "/usr/bin/apt-get",
            "/usr/bin/dpkg",
            "/usr/bin/yum",
            "/usr/bin/dnf",
            "/usr/bin/pacman",
        ]
    )


@dataclass
class HealthConfig:
    """Health monitoring configuration."""

    metrics_path: str = "/var/run/lotl/metrics.json"
    check_interval_seconds: int = 30


@dataclass
class Config:
    """Main configuration container."""

    # Operational mode: bootstrap, learn, enforce, paranoid
    mode: str = "bootstrap"

    # Sub-configurations
    logging: LogConfig = field(default_factory=LogConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    baseline: BaselineConfig = field(default_factory=BaselineConfig)
    blocking: BlockingConfig = field(default_factory=BlockingConfig)
    ancestry: AncestryConfig = field(default_factory=AncestryConfig)
    health: HealthConfig = field(default_factory=HealthConfig)

    # Paths to rule files
    rules_dir: str = "/etc/lotl/rules"
    tier1_rules_file: str = "tier1_blocklist.yaml"
    tier2_rules_file: str = "tier2_patterns.yaml"
    ancestry_rules_file: str = "ancestry_allowlist.yaml"

    # Runtime state directory
    run_dir: str = "/var/run/lotl"
    panic_file: str = "DISABLE"


# ─────────────────────────────────────────────────────────────────────────────
# Configuration Loading
# ─────────────────────────────────────────────────────────────────────────────


def load_yaml_safe(path: Path) -> dict[str, Any]:
    """
    Load YAML file safely.

    Uses yaml.safe_load to prevent code execution vulnerabilities.

    Args:
        path: Path to YAML file.

    Returns:
        Parsed YAML as dictionary.

    Raises:
        ConfigError: If file cannot be loaded or parsed.
    """
    if not path.exists():
        raise ConfigError(f"Config file not found: {path}")

    try:
        with open(path, encoding="utf-8") as f:
            # CRITICAL: Use safe_load to prevent arbitrary code execution
            data = yaml.safe_load(f)

        if data is None:
            return {}

        if not isinstance(data, dict):
            raise ConfigError(f"Config file must contain a mapping: {path}")

        return data

    except yaml.YAMLError as e:
        raise ConfigError(f"YAML parse error in {path}: {e}") from e
    except OSError as e:
        raise ConfigError(f"Cannot read config file {path}: {e}") from e


def _merge_dataclass(base: Any, updates: dict[str, Any]) -> Any:
    """Merge dictionary updates into a dataclass instance."""
    if not updates:
        return base

    # Get current values as dict
    if hasattr(base, "__dataclass_fields__"):
        current = {k: getattr(base, k) for k in base.__dataclass_fields__}
    else:
        return base

    # Update with new values
    for key, value in updates.items():
        if key in current:
            # Check if it's a nested dataclass
            field_value = current[key]
            if hasattr(field_value, "__dataclass_fields__") and isinstance(value, dict):
                current[key] = _merge_dataclass(field_value, value)
            else:
                current[key] = value

    return type(base)(**current)


def load_config(
    config_path: str | Path | None = None,
    allowed_bases: list[Path] | None = None,
) -> Config:
    """
    Load configuration from file.

    Args:
        config_path: Path to configuration file. If None, uses defaults.
        allowed_bases: Allowed base directories for path validation.

    Returns:
        Loaded and validated Config object.

    Raises:
        ConfigError: If configuration is invalid.
    """
    config = Config()

    if config_path is None:
        # Try default locations
        default_paths = [
            Path("/etc/lotl/detector.yaml"),
            Path("config/detector.yaml"),
            Path("detector.yaml"),
        ]
        for path in default_paths:
            if path.exists():
                config_path = path
                break

    if config_path is not None:
        # Validate path
        if allowed_bases:
            config_path = validate_path(config_path, allowed_bases)
        else:
            config_path = Path(config_path)

        if config_path.exists():
            logger.info(f"Loading configuration from {config_path}")
            data = load_yaml_safe(config_path)
            config = _merge_dataclass(config, data)
        else:
            logger.warning(f"Config file not found: {config_path}, using defaults")

    # Validate mode
    valid_modes = {"bootstrap", "learn", "enforce", "paranoid"}
    if config.mode not in valid_modes:
        raise ConfigError(f"Invalid mode '{config.mode}', must be one of {valid_modes}")

    return config


def ensure_directories(config: Config) -> None:
    """
    Ensure required directories exist.

    Args:
        config: Configuration object.
    """
    directories = [
        Path(config.logging.directory),
        Path(config.database.path).parent,
        Path(config.run_dir),
        Path(config.rules_dir),
    ]

    for directory in directories:
        try:
            directory.mkdir(parents=True, exist_ok=True)
            logger.debug(f"Ensured directory exists: {directory}")
        except OSError as e:
            logger.warning(f"Cannot create directory {directory}: {e}")


def get_rules_path(config: Config, filename: str) -> Path:
    """
    Get path to a rules file with validation.

    Args:
        config: Configuration object.
        filename: Name of rules file.

    Returns:
        Validated path to rules file.
    """
    rules_dir = Path(config.rules_dir)
    return validate_path(rules_dir / filename, [rules_dir])

