"""Tests for configuration management."""

from actions_scanner.config import Settings, get_settings


class TestSettings:
    """Tests for Settings class."""

    def test_default_settings(self) -> None:
        """Test that default settings are created correctly."""
        settings = Settings()

        assert settings.scan.workers == 10
        assert settings.scan.max_branches_per_repo == 100
        assert settings.github.concurrency == 50
        assert settings.validation.enabled is False
        assert settings.output.format == "csv"

    def test_settings_from_dict(self) -> None:
        """Test creating settings from a dictionary."""
        settings = Settings(
            scan={"workers": 20, "max_branches_per_repo": 50},
            github={"concurrency": 100},
        )

        assert settings.scan.workers == 20
        assert settings.scan.max_branches_per_repo == 50
        assert settings.github.concurrency == 100

    def test_validation_command_template(self) -> None:
        """Test validation command template formatting."""
        settings = Settings()
        cmd = settings.get_validation_command("Test prompt")

        assert "Test prompt" in cmd
        assert settings.validation.command_template.split()[0] in cmd

    def test_settings_load_with_overrides(self) -> None:
        """Test loading settings with overrides."""
        settings = Settings.load(scan={"workers": 25})

        assert settings.scan.workers == 25


class TestGetSettings:
    """Tests for get_settings function."""

    def test_get_settings_default(self) -> None:
        """Test getting settings with no config file."""
        settings = get_settings()

        assert settings is not None
        assert isinstance(settings, Settings)

    def test_get_settings_with_overrides(self) -> None:
        """Test getting settings with overrides."""
        settings = get_settings(scan={"workers": 15})

        assert settings.scan.workers == 15
