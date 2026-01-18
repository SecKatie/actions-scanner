"""Pytest configuration and fixtures."""

from pathlib import Path

import pytest

# Test fixtures directory
FIXTURES_DIR = Path(__file__).parent / "fixtures"
WORKFLOWS_DIR = FIXTURES_DIR / "workflows"


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
def temp_repo(tmp_path: Path) -> Path:
    """Create a temporary repository structure."""
    github_dir = tmp_path / ".github" / "workflows"
    github_dir.mkdir(parents=True)
    return tmp_path
