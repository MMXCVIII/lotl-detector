"""Unit tests for configuration module."""

import tempfile
from pathlib import Path

import pytest

from lotl_detector.core.config import (
    Config,
    ConfigError,
    load_config,
    load_yaml_safe,
    validate_path,
)


class TestValidatePath:
    """Tests for path validation."""

    def test_validate_simple_path(self, tmp_path: Path) -> None:
        """Test validation of a simple existing path."""
        test_file = tmp_path / "test.txt"
        test_file.touch()

        result = validate_path(test_file, [tmp_path])
        assert result == test_file.resolve()

    def test_validate_path_traversal_blocked(self, tmp_path: Path) -> None:
        """Test that path traversal is blocked."""
        # Create a file outside the allowed base
        outside = tmp_path.parent / "outside.txt"

        with pytest.raises(ConfigError, match="not within allowed directories"):
            validate_path(outside, [tmp_path])

    def test_validate_path_with_dotdot(self, tmp_path: Path) -> None:
        """Test that .. is resolved and checked."""
        subdir = tmp_path / "subdir"
        subdir.mkdir()

        # Try to escape via ..
        escape_path = subdir / ".." / ".." / "etc" / "passwd"

        with pytest.raises(ConfigError, match="not within allowed directories"):
            validate_path(escape_path, [tmp_path])


class TestLoadYamlSafe:
    """Tests for safe YAML loading."""

    def test_load_valid_yaml(self, tmp_path: Path) -> None:
        """Test loading valid YAML."""
        yaml_file = tmp_path / "test.yaml"
        yaml_file.write_text("key: value\nlist:\n  - item1\n  - item2")

        result = load_yaml_safe(yaml_file)
        assert result == {"key": "value", "list": ["item1", "item2"]}

    def test_load_empty_yaml(self, tmp_path: Path) -> None:
        """Test loading empty YAML returns empty dict."""
        yaml_file = tmp_path / "empty.yaml"
        yaml_file.write_text("")

        result = load_yaml_safe(yaml_file)
        assert result == {}

    def test_load_nonexistent_file(self, tmp_path: Path) -> None:
        """Test loading nonexistent file raises error."""
        with pytest.raises(ConfigError, match="not found"):
            load_yaml_safe(tmp_path / "nonexistent.yaml")

    def test_load_invalid_yaml(self, tmp_path: Path) -> None:
        """Test loading invalid YAML raises error."""
        yaml_file = tmp_path / "invalid.yaml"
        yaml_file.write_text("key: [unclosed")

        with pytest.raises(ConfigError, match="YAML parse error"):
            load_yaml_safe(yaml_file)


class TestConfig:
    """Tests for configuration loading."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = Config()

        assert config.mode == "bootstrap"
        assert config.logging.level == "INFO"
        assert config.database.max_age_days == 30

    def test_load_config_from_file(self, tmp_path: Path) -> None:
        """Test loading configuration from file."""
        config_file = tmp_path / "detector.yaml"
        config_file.write_text("""
mode: enforce
logging:
  level: DEBUG
database:
  max_age_days: 60
""")

        config = load_config(config_file)

        assert config.mode == "enforce"
        assert config.logging.level == "DEBUG"
        assert config.database.max_age_days == 60

    def test_load_config_invalid_mode(self, tmp_path: Path) -> None:
        """Test that invalid mode raises error."""
        config_file = tmp_path / "detector.yaml"
        config_file.write_text("mode: invalid_mode")

        with pytest.raises(ConfigError, match="Invalid mode"):
            load_config(config_file)

    def test_load_config_defaults_for_missing(self, tmp_path: Path) -> None:
        """Test that missing values get defaults."""
        config_file = tmp_path / "detector.yaml"
        config_file.write_text("mode: learn")

        config = load_config(config_file)

        assert config.logging.level == "INFO"  # Default
        assert config.mode == "learn"  # From file

