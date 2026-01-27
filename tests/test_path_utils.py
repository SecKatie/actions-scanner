"""Tests for path helper utilities."""

from pathlib import Path

from actions_scanner.utils.path import extract_org_repo_from_path, resolve_repo_dir


def test_extract_org_repo_double_underscore() -> None:
    org, repo = extract_org_repo_from_path("repos/anthropics__claude/.github/workflows/ci.yml")
    assert org == "anthropics"
    assert repo == "claude"


def test_extract_org_repo_nested() -> None:
    org, repo = extract_org_repo_from_path("repos/anthropics/claude/.github/workflows/ci.yml")
    assert org == "anthropics"
    assert repo == "claude"


def test_extract_org_repo_branch_layout() -> None:
    org, repo = extract_org_repo_from_path(
        "scan-output.txt/anthropics/claude/main/.github/workflows/ci.yml"
    )
    assert org == "anthropics"
    assert repo == "claude"


def test_extract_org_repo_legacy_dash() -> None:
    org, repo = extract_org_repo_from_path("repos/anthropics-claude/.github/workflows/ci.yml")
    assert org == "anthropics"
    assert repo == "claude"


def test_resolve_repo_dir_sparse_cloner_structure(tmp_path: Path) -> None:
    """Test resolve_repo_dir with SparseCloner's branch/code structure.

    Regression test for bug where scanner couldn't find repos cloned by
    SparseCloner because it looked at base_dir/org/repo instead of
    base_dir/org/repo/branch/code.

    SparseCloner creates: base_dir / org / repo / branch_encoded / code
    """
    base_dir = tmp_path
    org, repo = "ansible", "example-repo"

    # Create the directory structure that SparseCloner makes
    # base_dir / org / repo / "main" / "code" / .github / workflows
    repo_base = base_dir / org / repo
    code_dir = repo_base / "main" / "code"
    code_dir.mkdir(parents=True)
    (code_dir / ".github" / "workflows").mkdir(parents=True)
    (code_dir / ".github" / "workflows" / "test.yml").write_text("# test workflow")

    # resolve_repo_dir should find the code directory
    resolved, found = resolve_repo_dir(base_dir, org, repo)

    assert found
    assert resolved == code_dir
    assert (resolved / ".github" / "workflows").exists()


def test_resolve_repo_dir_sparse_cloner_master_branch(tmp_path: Path) -> None:
    """Test resolve_repo_dir handles 'master' as default branch."""
    base_dir = tmp_path / "master-test"
    org, repo = "myorg", "test-repo"

    repo_base = base_dir / org / repo
    code_dir = repo_base / "master" / "code"
    code_dir.mkdir(parents=True)
    (code_dir / ".github" / "workflows").mkdir(parents=True)

    resolved, found = resolve_repo_dir(base_dir, org, repo)

    assert found
    assert resolved == code_dir


def test_resolve_repo_dir_fallback_to_any_branch_with_github(tmp_path: Path) -> None:
    """Test resolve_repo_dir falls back to finding any branch with .github folder."""
    base_dir = tmp_path / "fallback-test"
    org, repo = "myorg", "myrepo"

    repo_base = base_dir / org / repo
    # Use a non-standard branch name
    branch_dir = repo_base / "feature-branch-123"
    code_dir = branch_dir / "code"
    code_dir.mkdir(parents=True)
    (code_dir / ".github" / "workflows").mkdir(parents=True)

    resolved, found = resolve_repo_dir(base_dir, org, repo)

    assert found
    assert resolved == code_dir
