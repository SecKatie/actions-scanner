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

    def test_scan_directory(self, detector: PwnRequestDetector, fake_repo_dir: Path) -> None:
        """Test scanning a directory of workflows (requires .github/workflows structure)."""
        result = detector.scan_directory(fake_repo_dir)

        assert result.files_scanned >= 3
        assert len(result.vulnerabilities) >= 2  # vulnerable + protected

    def test_protection_levels(self) -> None:
        """Test that protection levels are correctly enumerated."""
        assert ProtectionLevel.NONE.value == "none"
        assert ProtectionLevel.LABEL.value == "label"
        assert ProtectionLevel.PERMISSION.value == "permission"
        assert ProtectionLevel.SAME_REPO.value == "same_repo"
        assert ProtectionLevel.ACTOR.value == "actor"
        assert ProtectionLevel.MERGED.value == "merged"

    def test_detect_actor_gated_workflow(
        self, detector: PwnRequestDetector, actor_gated_workflow_path: Path
    ) -> None:
        """Test detection of actor-gated workflow (only bot can trigger)."""
        vulns = detector.analyze_workflow(actor_gated_workflow_path)

        # Should detect the pattern, but mark as actor-gated (not exploitable)
        assert len(vulns) > 0
        vuln = vulns[0]
        assert vuln.protection == "actor"
        assert "bot actor" in vuln.protection_detail.lower()
        assert not vuln.is_exploitable()

    def test_detect_merged_pr_gated_workflow(
        self, detector: PwnRequestDetector, merged_pr_gated_workflow_path: Path
    ) -> None:
        """Test detection of merged-PR-gated workflow (only runs after merge)."""
        vulns = detector.analyze_workflow(merged_pr_gated_workflow_path)

        # Should detect the pattern, but mark as merged-gated (not exploitable)
        assert len(vulns) > 0
        vuln = vulns[0]
        assert vuln.protection == "merged"
        assert "merged" in vuln.protection_detail.lower()
        assert not vuln.is_exploitable()

    def test_detect_same_repo_gated_workflow(
        self, detector: PwnRequestDetector, same_repo_gated_workflow_path: Path
    ) -> None:
        """Test detection of same-repo-gated workflow."""
        vulns = detector.analyze_workflow(same_repo_gated_workflow_path)

        # Should detect the pattern, but mark as same_repo-gated (not exploitable)
        assert len(vulns) > 0
        vuln = vulns[0]
        assert vuln.protection == "same_repo"
        assert not vuln.is_exploitable()

    def test_detect_label_gated_workflow(
        self, detector: PwnRequestDetector, label_gated_workflow_path: Path
    ) -> None:
        """Test detection of label-gated workflow."""
        vulns = detector.analyze_workflow(label_gated_workflow_path)

        # Should detect the pattern, marked as label-gated (exploitable via social engineering)
        assert len(vulns) > 0
        vuln = vulns[0]
        assert vuln.protection == "label"
        assert vuln.is_exploitable()  # Label-gated is still exploitable

    def test_detect_local_action_vulnerability(
        self, detector: PwnRequestDetector, local_action_workflow_path: Path
    ) -> None:
        """Test detection of local action execution vulnerability."""
        vulns = detector.analyze_workflow(local_action_workflow_path)

        assert len(vulns) > 0
        vuln = vulns[0]
        assert vuln.exec_type == "local_action"
        assert "./actions/my-action" in vuln.exec_value
        assert vuln.protection == "none"
        assert vuln.is_exploitable()

    def test_detect_refs_pull_merge_vulnerability(
        self, detector: PwnRequestDetector, refs_pull_merge_workflow_path: Path
    ) -> None:
        """Test detection of refs/pull/N/merge checkout pattern."""
        vulns = detector.analyze_workflow(refs_pull_merge_workflow_path)

        assert len(vulns) > 0
        vuln = vulns[0]
        assert (
            "refs/pull" in vuln.checkout_ref
            or "github.event.pull_request.number" in vuln.checkout_ref
        )
        assert vuln.exec_type == "build_command"
        assert "make" in vuln.exec_value
        assert vuln.is_exploitable()

    def test_detect_git_fetch_pr_vulnerability(
        self, detector: PwnRequestDetector, git_fetch_pr_workflow_path: Path
    ) -> None:
        """Test detection of git fetch PR checkout pattern."""
        vulns = detector.analyze_workflow(git_fetch_pr_workflow_path)

        assert len(vulns) > 0
        vuln = vulns[0]
        assert "git checkout PR code" in vuln.checkout_ref
        assert vuln.exec_type == "build_command"
        assert vuln.is_exploitable()

    def test_detect_pip_install_vulnerability(
        self, detector: PwnRequestDetector, pip_install_workflow_path: Path
    ) -> None:
        """Test detection of pip install vulnerability."""
        vulns = detector.analyze_workflow(pip_install_workflow_path)

        assert len(vulns) > 0
        vuln = vulns[0]
        assert "head_ref" in vuln.checkout_ref
        assert vuln.exec_type == "build_command"
        assert "pip" in vuln.exec_value
        assert vuln.is_exploitable()

    def test_safe_base_branch_checkout(
        self, detector: PwnRequestDetector, base_branch_checkout_workflow_path: Path
    ) -> None:
        """Test that base branch checkout is not flagged as vulnerable."""
        vulns = detector.analyze_workflow(base_branch_checkout_workflow_path)

        # Base branch checkout should not be flagged
        assert len(vulns) == 0

    def test_safe_no_dangerous_exec(
        self, detector: PwnRequestDetector, no_dangerous_exec_workflow_path: Path
    ) -> None:
        """Test that checkout without dangerous exec is not flagged."""
        vulns = detector.analyze_workflow(no_dangerous_exec_workflow_path)

        # No dangerous execution after checkout
        assert len(vulns) == 0


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

    def test_not_exploitable_actor(self) -> None:
        """Test that actor-gated vulns are not exploitable."""
        vuln = VulnerableJob(
            workflow_path=Path("test.yml"),
            job_name="test",
            checkout_line=10,
            checkout_ref="${{ github.head_ref }}",
            exec_line=15,
            exec_type="build_command",
            exec_value="npm install",
            protection="actor",
        )
        assert not vuln.is_exploitable()

    def test_not_exploitable_merged(self) -> None:
        """Test that merged-PR-gated vulns are not exploitable."""
        vuln = VulnerableJob(
            workflow_path=Path("test.yml"),
            job_name="test",
            checkout_line=10,
            checkout_ref="${{ github.head_ref }}",
            exec_line=15,
            exec_type="build_command",
            exec_value="npm install",
            protection="merged",
        )
        assert not vuln.is_exploitable()

    def test_not_exploitable_same_repo(self) -> None:
        """Test that same-repo-gated vulns are not exploitable."""
        vuln = VulnerableJob(
            workflow_path=Path("test.yml"),
            job_name="test",
            checkout_line=10,
            checkout_ref="${{ github.head_ref }}",
            exec_line=15,
            exec_type="build_command",
            exec_value="npm install",
            protection="same_repo",
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
