"""Pytest configuration and fixtures."""

from pathlib import Path

import pytest

# Test fixtures directory
FIXTURES_DIR = Path(__file__).parent / "fixtures"
WORKFLOWS_DIR = FIXTURES_DIR / "workflows"
FAKE_REPO_DIR = FIXTURES_DIR / "fake_repo"


@pytest.fixture
def fixtures_dir() -> Path:
    """Return the fixtures directory path."""
    return FIXTURES_DIR


@pytest.fixture
def workflows_dir() -> Path:
    """Return the workflows fixtures directory path."""
    return WORKFLOWS_DIR


@pytest.fixture
def vulnerable_workflow_path(workflows_dir: Path) -> Path:
    """Return path to a vulnerable workflow."""
    return workflows_dir / "vulnerable" / "pwn_request.yml"


@pytest.fixture
def protected_workflow_path(workflows_dir: Path) -> Path:
    """Return path to a protected workflow."""
    return workflows_dir / "protected" / "permission_gated.yml"


@pytest.fixture
def safe_workflow_path(workflows_dir: Path) -> Path:
    """Return path to a safe workflow."""
    return workflows_dir / "safe" / "no_checkout.yml"


@pytest.fixture
def actor_gated_workflow_path(workflows_dir: Path) -> Path:
    """Return path to an actor-gated workflow."""
    return workflows_dir / "protected" / "actor_gated.yml"


@pytest.fixture
def merged_pr_gated_workflow_path(workflows_dir: Path) -> Path:
    """Return path to a merged-PR-gated workflow."""
    return workflows_dir / "protected" / "merged_pr_gated.yml"


@pytest.fixture
def same_repo_gated_workflow_path(workflows_dir: Path) -> Path:
    """Return path to a same-repo-gated workflow."""
    return workflows_dir / "protected" / "same_repo_gated.yml"


@pytest.fixture
def label_gated_workflow_path(workflows_dir: Path) -> Path:
    """Return path to a label-gated workflow."""
    return workflows_dir / "protected" / "label_gated.yml"


@pytest.fixture
def local_action_workflow_path(workflows_dir: Path) -> Path:
    """Return path to a vulnerable local action workflow."""
    return workflows_dir / "vulnerable" / "local_action.yml"


@pytest.fixture
def refs_pull_merge_workflow_path(workflows_dir: Path) -> Path:
    """Return path to a vulnerable refs/pull/N/merge workflow."""
    return workflows_dir / "vulnerable" / "refs_pull_merge.yml"


@pytest.fixture
def git_fetch_pr_workflow_path(workflows_dir: Path) -> Path:
    """Return path to a vulnerable git fetch PR workflow."""
    return workflows_dir / "vulnerable" / "git_fetch_pr.yml"


@pytest.fixture
def pip_install_workflow_path(workflows_dir: Path) -> Path:
    """Return path to a vulnerable pip install workflow."""
    return workflows_dir / "vulnerable" / "pip_install.yml"


@pytest.fixture
def base_branch_checkout_workflow_path(workflows_dir: Path) -> Path:
    """Return path to a safe base branch checkout workflow."""
    return workflows_dir / "safe" / "base_branch_checkout.yml"


@pytest.fixture
def no_dangerous_exec_workflow_path(workflows_dir: Path) -> Path:
    """Return path to a safe no dangerous exec workflow."""
    return workflows_dir / "safe" / "no_dangerous_exec.yml"


@pytest.fixture
def fake_repo_dir() -> Path:
    """Return the fake repo fixtures directory (has .github/workflows structure)."""
    return FAKE_REPO_DIR


@pytest.fixture
def workflow_run_vulnerability_path(workflows_dir: Path) -> Path:
    """Return path to a vulnerable workflow_run workflow."""
    return workflows_dir / "vulnerable" / "workflow_run.yml"


@pytest.fixture
def workflow_run_safe_path(workflows_dir: Path) -> Path:
    """Return path to a safe workflow_run workflow."""
    return workflows_dir / "safe" / "workflow_run_safe.yml"


@pytest.fixture
def temp_repo(tmp_path: Path) -> Path:
    """Create a temporary repository structure."""
    github_dir = tmp_path / ".github" / "workflows"
    github_dir.mkdir(parents=True)
    return tmp_path


@pytest.fixture
def context_injection_pr_target_path(workflows_dir: Path) -> Path:
    """Return path to a context injection PR target workflow."""
    return workflows_dir / "vulnerable" / "context_injection_pr_target.yml"


@pytest.fixture
def context_injection_workflow_run_path(workflows_dir: Path) -> Path:
    """Return path to a context injection workflow_run workflow."""
    return workflows_dir / "vulnerable" / "context_injection_workflow_run.yml"


@pytest.fixture
def context_injection_safe_path(workflows_dir: Path) -> Path:
    """Return path to a safe context usage workflow."""
    return workflows_dir / "safe" / "context_injection_safe.yml"


@pytest.fixture
def workflow_run_combined_path(workflows_dir: Path) -> Path:
    """Return path to a workflow_run workflow with both checkout and context injection.

    Regression test fixture for stolostron/gatekeeper-operator-fbc pattern.
    """
    return workflows_dir / "vulnerable" / "workflow_run_combined.yml"
