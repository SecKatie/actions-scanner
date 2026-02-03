"""Tests for the PwnRequest, WorkflowRun, ContextInjection, and other vulnerability detectors."""

from pathlib import Path

import pytest

from actions_scanner.core import (
    ArtifactInjectionDetector,
    ContextInjectionDetector,
    DispatchCheckoutDetector,
    PwnRequestDetector,
    VulnerableJob,
    WorkflowRunDetector,
)
from actions_scanner.core.models import ProtectionLevel, VulnerabilityType


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
        assert "specific actor" in vuln.protection_detail.lower()
        assert not vuln.is_exploitable()

    def test_detect_sender_login_gated_workflow(
        self,
        sender_login_gated_workflow_path: Path,
    ) -> None:
        """Test detection of sender.login-gated workflow.

        Regression test: workflows gated by github.event.sender.login should be
        detected as actor-gated, not reported as exploitable.
        """
        context_detector = ContextInjectionDetector()
        vulns = context_detector.analyze_workflow(sender_login_gated_workflow_path)

        # Should detect the context injection, but mark as actor-gated
        assert len(vulns) > 0
        vuln = vulns[0]
        assert vuln.protection == "actor"
        assert "specific actor" in vuln.protection_detail.lower()
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

    def test_detect_label_gated_github_script_toctou(
        self,
        detector: PwnRequestDetector,
        label_gated_github_script_workflow_path: Path,
    ) -> None:
        """Test detection of TOCTOU in github-script label gating.

        When a workflow triggers on both 'labeled' AND 'synchronize', the label
        check can be bypassed: attacker gets benign code labeled, then pushes
        malicious code. The workflow re-runs due to 'synchronize', label is still
        present, malicious code executes.

        Regression test for openshift/linuxptp-daemon aws-ci.yaml pattern.
        """
        vulns = detector.analyze_workflow(label_gated_github_script_workflow_path)

        assert len(vulns) > 0
        vuln = vulns[0]
        # TOCTOU detected - label gating is ineffective
        assert vuln.protection == "none"
        assert "TOCTOU" in vuln.protection_detail
        assert "synchronize" in vuln.protection_detail
        assert vuln.is_exploitable()

    def test_detect_label_gated_no_toctou(
        self,
        detector: PwnRequestDetector,
        label_gated_no_toctou_workflow_path: Path,
    ) -> None:
        """Test detection of effective label gating (no TOCTOU).

        When a workflow only triggers on 'labeled' (not 'synchronize'), the label
        check IS effective because pushing new code won't re-trigger the workflow.
        """
        vulns = detector.analyze_workflow(label_gated_no_toctou_workflow_path)

        assert len(vulns) > 0
        vuln = vulns[0]
        # Effective label gating - no TOCTOU
        assert vuln.protection == "label"
        assert vuln.is_exploitable()  # Label-gated is still exploitable via social engineering

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
        assert d["vulnerability_type"] == VulnerabilityType.PWNREQUEST.value


class TestWorkflowRunDetector:
    """Tests for WorkflowRunDetector class."""

    @pytest.fixture
    def detector(self) -> WorkflowRunDetector:
        """Create a detector instance."""
        return WorkflowRunDetector()

    def test_detect_workflow_run_vulnerability(
        self, detector: WorkflowRunDetector, workflow_run_vulnerability_path: Path
    ) -> None:
        """Test detection of a workflow_run vulnerability."""
        vulns = detector.analyze_workflow(workflow_run_vulnerability_path)

        assert len(vulns) > 0
        vuln = vulns[0]
        assert vuln.job_name == "build"
        assert "git checkout workflow_run code" in vuln.checkout_ref
        assert vuln.exec_type == "build_command"
        assert vuln.protection == "none"
        assert vuln.vulnerability_type == VulnerabilityType.WORKFLOW_RUN.value
        assert vuln.is_exploitable()

    def test_safe_workflow_run_default_checkout(
        self, detector: WorkflowRunDetector, workflow_run_safe_path: Path
    ) -> None:
        """Test that workflow_run with default checkout is not flagged."""
        vulns = detector.analyze_workflow(workflow_run_safe_path)

        # No dangerous checkout of workflow_run code
        assert len(vulns) == 0

    def test_workflow_run_not_triggered_by_pull_request_target(
        self, detector: WorkflowRunDetector, vulnerable_workflow_path: Path
    ) -> None:
        """Test that pull_request_target workflows are not flagged by WorkflowRunDetector."""
        vulns = detector.analyze_workflow(vulnerable_workflow_path)

        # WorkflowRunDetector should not detect pull_request_target workflows
        assert len(vulns) == 0

    def test_vulnerability_type_field(self) -> None:
        """Test that WorkflowRunDetector sets the correct vulnerability type."""
        vuln = VulnerableJob(
            workflow_path=Path("test.yml"),
            job_name="test",
            checkout_line=10,
            checkout_ref="git checkout workflow_run code",
            exec_line=15,
            exec_type="build_command",
            exec_value="make build",
            vulnerability_type=VulnerabilityType.WORKFLOW_RUN.value,
        )
        assert vuln.vulnerability_type == "workflow_run"
        assert vuln.to_dict()["vulnerability_type"] == "workflow_run"


class TestWorkflowRunRepoValidation:
    """Tests for workflow_run repository validation detection."""

    @pytest.fixture
    def detector(self) -> WorkflowRunDetector:
        """Create a detector instance."""
        return WorkflowRunDetector()

    def test_detect_workflow_run_repo_validation(
        self, detector: WorkflowRunDetector, workflow_run_repo_validated_path: Path
    ) -> None:
        """Test detection of workflow_run with step-level repo validation.

        Regression test: workflow_run workflows that validate
        head_repository.full_name against github.repository should be
        detected as same_repo-gated (not exploitable from forks).
        """
        vulns = detector.analyze_workflow(workflow_run_repo_validated_path)

        assert len(vulns) > 0
        vuln = vulns[0]
        assert vuln.protection == "same_repo"
        assert "validates" in vuln.protection_detail.lower()
        assert not vuln.is_exploitable()


class TestContextInjectionDetector:
    """Tests for ContextInjectionDetector class."""

    @pytest.fixture
    def detector(self) -> ContextInjectionDetector:
        """Create a detector instance."""
        return ContextInjectionDetector()

    def test_detect_pr_target_context_injection(
        self, detector: ContextInjectionDetector, context_injection_pr_target_path: Path
    ) -> None:
        """Test detection of context injection in pull_request_target."""
        vulns = detector.analyze_workflow(context_injection_pr_target_path)

        assert len(vulns) > 0
        vuln = vulns[0]
        assert vuln.vulnerability_type == VulnerabilityType.CONTEXT_INJECTION.value
        assert "github.head_ref" in vuln.checkout_ref
        assert vuln.exec_type == "context_injection"
        assert vuln.is_exploitable()

    def test_detect_workflow_run_context_injection(
        self, detector: ContextInjectionDetector, context_injection_workflow_run_path: Path
    ) -> None:
        """Test detection of context injection in workflow_run."""
        vulns = detector.analyze_workflow(context_injection_workflow_run_path)

        assert len(vulns) > 0
        vuln = vulns[0]
        assert vuln.vulnerability_type == VulnerabilityType.CONTEXT_INJECTION.value
        assert "head_branch" in vuln.checkout_ref or "head_repository" in vuln.checkout_ref
        assert vuln.exec_type == "context_injection"
        assert vuln.is_exploitable()

    def test_safe_env_context_usage(
        self, detector: ContextInjectionDetector, context_injection_safe_path: Path
    ) -> None:
        """Test that env: usage of context is not flagged.

        Using context in env: then referencing as $VAR in run is safe because
        the shell doesn't interpret the variable content as code.
        """
        vulns = detector.analyze_workflow(context_injection_safe_path)

        # Safe pattern - context is in env:, not directly in run: block
        assert len(vulns) == 0

    def test_no_detection_without_dangerous_trigger(
        self, detector: ContextInjectionDetector, tmp_path: Path
    ) -> None:
        """Test that regular pull_request trigger is not flagged."""
        workflow = tmp_path / "safe.yml"
        workflow.write_text("""
name: Safe
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.head_ref }}"
""")
        vulns = detector.analyze_workflow(workflow)

        # Regular pull_request is safe - attacker code has limited privileges
        assert len(vulns) == 0

    def test_vulnerability_type_field(self) -> None:
        """Test that ContextInjectionDetector sets the correct vulnerability type."""
        vuln = VulnerableJob(
            workflow_path=Path("test.yml"),
            job_name="test",
            checkout_line=0,
            checkout_ref="${{ github.head_ref }}",
            exec_line=15,
            exec_type="context_injection",
            exec_value='echo "Branch: ${{ github.head_ref }}"',
            vulnerability_type=VulnerabilityType.CONTEXT_INJECTION.value,
        )
        assert vuln.vulnerability_type == "context_injection"
        assert vuln.to_dict()["vulnerability_type"] == "context_injection"

    def test_pr_target_not_flagged_by_workflow_run_detector(
        self, context_injection_pr_target_path: Path
    ) -> None:
        """Test that PR target context injection is not caught by WorkflowRunDetector."""
        detector = WorkflowRunDetector()
        vulns = detector.analyze_workflow(context_injection_pr_target_path)

        # WorkflowRunDetector should not detect pull_request_target workflows
        assert len(vulns) == 0

    def test_workflow_run_not_flagged_by_pwnrequest_detector(
        self, context_injection_workflow_run_path: Path
    ) -> None:
        """Test that workflow_run context injection is not caught by PwnRequestDetector."""
        detector = PwnRequestDetector()
        vulns = detector.analyze_workflow(context_injection_workflow_run_path)

        # PwnRequestDetector should not detect workflow_run workflows
        assert len(vulns) == 0

    def test_detect_issues_context_injection(
        self, detector: ContextInjectionDetector, context_injection_issues_path: Path
    ) -> None:
        """Test detection of context injection in issues trigger workflow.

        Anyone can create an issue with a malicious title to achieve command injection.
        The issue title is attacker-controlled and can contain shell metacharacters.
        """
        vulns = detector.analyze_workflow(context_injection_issues_path)

        assert len(vulns) > 0
        vuln = vulns[0]
        assert vuln.vulnerability_type == VulnerabilityType.CONTEXT_INJECTION.value
        assert "issue.title" in vuln.checkout_ref.lower()
        assert vuln.exec_type == "context_injection"
        assert vuln.is_exploitable()

    def test_safe_user_login_not_flagged_issues(
        self, detector: ContextInjectionDetector, safe_user_login_issues_path: Path
    ) -> None:
        """Test that .user.login is NOT flagged as context injection for issues trigger.

        Regression test: GitHub usernames are constrained to [a-zA-Z0-9-] and cannot
        contain shell metacharacters, so they are not injectable.
        """
        vulns = detector.analyze_workflow(safe_user_login_issues_path)

        assert len(vulns) == 0

    def test_safe_user_login_not_flagged_issue_comment(
        self, detector: ContextInjectionDetector, safe_user_login_issue_comment_path: Path
    ) -> None:
        """Test that .user.login is NOT flagged as context injection for issue_comment trigger.

        Regression test: GitHub usernames are constrained to [a-zA-Z0-9-] and cannot
        contain shell metacharacters, so they are not injectable.
        """
        vulns = detector.analyze_workflow(safe_user_login_issue_comment_path)

        assert len(vulns) == 0


class TestArtifactInjectionDetector:
    """Tests for ArtifactInjectionDetector class."""

    @pytest.fixture
    def detector(self) -> ArtifactInjectionDetector:
        """Create a detector instance."""
        return ArtifactInjectionDetector()

    def test_detect_artifact_injection(
        self, detector: ArtifactInjectionDetector, artifact_injection_path: Path
    ) -> None:
        """Test detection of artifact injection in workflow_run workflow.

        An attacker can control artifact content via a malicious PR, then the workflow_run
        reads that content into shell commands.
        """
        vulns = detector.analyze_workflow(artifact_injection_path)

        assert len(vulns) > 0
        vuln = vulns[0]
        assert vuln.vulnerability_type == VulnerabilityType.ARTIFACT_INJECTION.value
        assert "artifact" in vuln.checkout_ref.lower()
        assert vuln.exec_type == "artifact_read"
        assert vuln.is_exploitable()

    def test_no_detection_without_workflow_run(
        self, detector: ArtifactInjectionDetector, vulnerable_workflow_path: Path
    ) -> None:
        """Test that non-workflow_run workflows are not flagged."""
        vulns = detector.analyze_workflow(vulnerable_workflow_path)

        # ArtifactInjectionDetector should not detect pull_request_target workflows
        assert len(vulns) == 0

    def test_vulnerability_type_field(self) -> None:
        """Test that ArtifactInjectionDetector sets the correct vulnerability type."""
        vuln = VulnerableJob(
            workflow_path=Path("test.yml"),
            job_name="test",
            checkout_line=10,
            checkout_ref="artifact from workflow_run",
            exec_line=15,
            exec_type="artifact_read",
            exec_value="$(<prInfo/branch)",
            vulnerability_type=VulnerabilityType.ARTIFACT_INJECTION.value,
        )
        assert vuln.vulnerability_type == "artifact_injection"
        assert vuln.to_dict()["vulnerability_type"] == "artifact_injection"

    def test_safe_sonarcloud_workflow_not_flagged(
        self, detector: ArtifactInjectionDetector, safe_workflow_run_sonar_path: Path
    ) -> None:
        """Test that SonarCloud-style workflows are not flagged as vulnerable.

        Regression test for ansible/galaxy_ng sonar-pr.yaml false positive.
        This workflow downloads artifacts and uses gh pr checkout, but only for
        static analysis - no dangerous artifact content reading into shell commands.
        """
        vulns = detector.analyze_workflow(safe_workflow_run_sonar_path)

        # Should not detect any vulnerabilities - no dangerous artifact read patterns
        assert len(vulns) == 0


class TestDispatchCheckoutDetector:
    """Tests for DispatchCheckoutDetector class (confused deputy via issue_comment)."""

    @pytest.fixture
    def detector(self) -> DispatchCheckoutDetector:
        """Create a detector instance."""
        return DispatchCheckoutDetector()

    def test_detect_dispatch_checkout_vulnerability(
        self, detector: DispatchCheckoutDetector, dispatch_checkout_vulnerable_path: Path
    ) -> None:
        """Test detection of confused deputy vulnerability via issue_comment.

        Regression test for containers/kubernetes-mcp-server gevals.yaml pattern.
        This workflow:
        1. Triggered by issue_comment
        2. Permission check validates the COMMENTER (confused deputy!)
        3. Checks out PR code via job outputs
        4. Executes make commands on attacker's code
        """
        vulns = detector.analyze_workflow(dispatch_checkout_vulnerable_path)

        assert len(vulns) > 0
        vuln = vulns[0]
        assert vuln.vulnerability_type == VulnerabilityType.DISPATCH_CHECKOUT.value
        assert vuln.exec_type == "build_command"
        assert vuln.is_exploitable()

    def test_safe_issue_comment_not_flagged(
        self, detector: DispatchCheckoutDetector, dispatch_checkout_safe_path: Path
    ) -> None:
        """Test that issue_comment workflows without PR checkout are not flagged.

        This workflow responds to comments but only checks out the base branch,
        never executing untrusted PR code.
        """
        vulns = detector.analyze_workflow(dispatch_checkout_safe_path)

        # Should not detect any vulnerabilities - no PR code checkout
        assert len(vulns) == 0

    def test_no_detection_without_issue_comment_trigger(
        self, detector: DispatchCheckoutDetector, vulnerable_workflow_path: Path
    ) -> None:
        """Test that non-issue_comment workflows are not flagged."""
        vulns = detector.analyze_workflow(vulnerable_workflow_path)

        # DispatchCheckoutDetector should only detect issue_comment workflows
        assert len(vulns) == 0

    def test_vulnerability_type_field(self) -> None:
        """Test that DispatchCheckoutDetector sets the correct vulnerability type."""
        vuln = VulnerableJob(
            workflow_path=Path("test.yml"),
            job_name="test",
            checkout_line=10,
            checkout_ref="refs/pull/${{ needs.check.outputs.pr-ref }}/head",
            exec_line=15,
            exec_type="build_command",
            exec_value="make test",
            vulnerability_type=VulnerabilityType.DISPATCH_CHECKOUT.value,
        )
        assert vuln.vulnerability_type == "dispatch_checkout"
        assert vuln.to_dict()["vulnerability_type"] == "dispatch_checkout"


class TestScanDirectory:
    """Tests for the module-level scan_directory function.

    Regression tests to ensure all vulnerability types are detected.
    """

    def test_scan_directory_detects_all_vulnerability_types(
        self, workflow_run_combined_path: Path, tmp_path: Path
    ) -> None:
        """Regression test: scan_directory must detect workflow_run and context_injection.

        This test ensures the CLI uses all detectors, not just PwnRequestDetector.
        Regression for: stolostron/gatekeeper-operator-fbc pattern.
        """
        from actions_scanner.core import scan_directory

        # Create a temp repo structure with the combined workflow
        workflows_dir = tmp_path / ".github" / "workflows"
        workflows_dir.mkdir(parents=True)

        # Copy the combined workflow
        import shutil

        shutil.copy(workflow_run_combined_path, workflows_dir / "generate.yml")

        # Scan the directory
        result = scan_directory(tmp_path)

        # Must detect both vulnerability types
        vuln_types = {v.vulnerability_type for v in result.vulnerabilities}
        assert "workflow_run" in vuln_types, (
            "scan_directory must detect workflow_run vulnerabilities"
        )
        assert "context_injection" in vuln_types, (
            "scan_directory must detect context_injection vulnerabilities"
        )
        assert len(result.vulnerabilities) >= 2

    def test_scan_directory_detects_pwnrequest(self, fake_repo_dir: Path) -> None:
        """Test that scan_directory also detects pwnrequest vulnerabilities."""
        from actions_scanner.core import scan_directory

        result = scan_directory(fake_repo_dir)

        # fake_repo_dir should have pwnrequest vulnerabilities
        vuln_types = {v.vulnerability_type for v in result.vulnerabilities}
        assert "pwnrequest" in vuln_types, "scan_directory must detect pwnrequest vulnerabilities"
