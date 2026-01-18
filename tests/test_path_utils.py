"""Tests for path helper utilities."""

from actions_scanner.utils.path import extract_org_repo_from_path


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
