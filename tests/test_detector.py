"""Tests for the PwnRequest vulnerability detector."""

from pathlib import Path

import pytest

from actions_scanner.core import PwnRequestDetector, VulnerableJob
from actions_scanner.core.models import ProtectionLevel


class TestPwnRequestDetector:
    """Tests for PwnRequestDetector class."""

    @pytest.fixture
    def detector(self) -> PwnRequestDetector:
        """Create a detector instance."""
        return PwnRequestDetector()

    def test_detect_vulnerable_workflow(
        self, detector: PwnRequestDetector, vulnerable_workflow_path: Path
    ) -> None:
        """Test detection of a vulnerable workflow."""
        vulns = detector.analyze_workflow(vulnerable_workflow_path)

        assert len(vulns) > 0
        vuln = vulns[0]
        assert vuln.job_name == "build"
        assert "head.sha" in vuln.checkout_ref
        assert vuln.exec_type == "build_command"
        assert vuln.protection == "none"
        assert vuln.is_exploitable()

    def test_detect_protected_workflow(
        self, detector: PwnRequestDetector, protected_workflow_path: Path
    ) -> None:
        """Test detection of a permission-gated workflow."""
        vulns = detector.analyze_workflow(protected_workflow_path)

        # Should still detect the pattern, but mark as protected
        assert len(vulns) > 0
        vuln = vulns[0]
        assert vuln.protection == "permission"
        assert not vuln.is_exploitable()

    def test_no_detection_safe_workflow(
        self, detector: PwnRequestDetector, safe_workflow_path: Path
    ) -> None:
        """Test that safe workflows are not flagged."""
        vulns = detector.analyze_workflow(safe_workflow_path)

        # No dangerous checkout + execution pattern
        assert len(vulns) == 0

    def test_scan_directory(self, detector: PwnRequestDetector, workflows_dir: Path) -> None:
        """Test scanning a directory of workflows."""
        result = detector.scan_directory(workflows_dir)

        assert result.files_scanned >= 3
        assert len(result.vulnerabilities) >= 2  # vulnerable + protected

    def test_protection_levels(self) -> None:
        """Test that protection levels are correctly enumerated."""
        assert ProtectionLevel.NONE.value == "none"
        assert ProtectionLevel.LABEL.value == "label"
        assert ProtectionLevel.PERMISSION.value == "permission"
        assert ProtectionLevel.SAME_REPO.value == "same_repo"


class TestVulnerableJob:
    """Tests for VulnerableJob model."""

    def test_is_exploitable_none(self) -> None:
        """Test that no-protection vulns are exploitable."""
        vuln = VulnerableJob(
            workflow_path=Path("test.yml"),
            job_name="test",
            checkout_line=10,
            checkout_ref="${{ github.head_ref }}",
            exec_line=15,
            exec_type="build_command",
            exec_value="npm install",
            protection="none",
        )
        assert vuln.is_exploitable()

    def test_is_exploitable_label(self) -> None:
        """Test that label-gated vulns are exploitable (via social engineering)."""
        vuln = VulnerableJob(
            workflow_path=Path("test.yml"),
            job_name="test",
            checkout_line=10,
            checkout_ref="${{ github.head_ref }}",
            exec_line=15,
            exec_type="build_command",
            exec_value="npm install",
            protection="label",
        )
        assert vuln.is_exploitable()

    def test_not_exploitable_permission(self) -> None:
        """Test that permission-gated vulns are not exploitable."""
        vuln = VulnerableJob(
            workflow_path=Path("test.yml"),
            job_name="test",
            checkout_line=10,
            checkout_ref="${{ github.head_ref }}",
            exec_line=15,
            exec_type="build_command",
            exec_value="npm install",
            protection="permission",
        )
        assert not vuln.is_exploitable()

    def test_to_dict(self) -> None:
        """Test serialization to dictionary."""
        vuln = VulnerableJob(
            workflow_path=Path("test.yml"),
            job_name="test",
            checkout_line=10,
            checkout_ref="${{ github.head_ref }}",
            exec_line=15,
            exec_type="build_command",
            exec_value="npm install",
            branch="main",
        )
        d = vuln.to_dict()

        assert d["workflow_path"] == "test.yml"
        assert d["job_name"] == "test"
        assert d["branch"] == "main"
