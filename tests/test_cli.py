"""Tests for CLI commands."""

from pathlib import Path

import pytest
from click.testing import CliRunner

from actions_scanner.cli import cli


class TestCLI:
    """Tests for CLI commands."""

    @pytest.fixture
    def runner(self) -> CliRunner:
        """Create a CLI test runner."""
        return CliRunner()

    def test_cli_help(self, runner: CliRunner) -> None:
        """Test that --help works."""
        result = runner.invoke(cli, ["--help"])

        assert result.exit_code == 0
        assert "GitHub Actions vulnerability scanner" in result.output

    def test_cli_version(self, runner: CliRunner) -> None:
        """Test that --version works."""
        result = runner.invoke(cli, ["--version"])

        assert result.exit_code == 0
        assert "1.0.0" in result.output

    def test_scan_command_help(self, runner: CliRunner) -> None:
        """Test scan command help."""
        result = runner.invoke(cli, ["scan", "--help"])

        assert result.exit_code == 0
        assert "Scan repositories" in result.output

    def test_clone_command_help(self, runner: CliRunner) -> None:
        """Test clone command help."""
        result = runner.invoke(cli, ["clone", "--help"])

        assert result.exit_code == 0
        assert "Clone repositories" in result.output

    def test_report_command_help(self, runner: CliRunner) -> None:
        """Test report command help."""
        result = runner.invoke(cli, ["report", "--help"])

        assert result.exit_code == 0
        assert "Generate reports" in result.output

    def test_scan_directory(self, runner: CliRunner, workflows_dir: Path, tmp_path: Path) -> None:
        """Test scanning a directory."""
        output_file = tmp_path / "vulnerabilities.csv"

        result = runner.invoke(
            cli,
            [
                "--no-banner",
                "scan",
                str(workflows_dir),
                "-o",
                str(output_file),
            ],
        )

        assert result.exit_code == 0
        assert output_file.exists()
