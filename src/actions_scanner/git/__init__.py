"""Git operations for sparse cloning and worktree management."""

from .branch import BranchInfo, BranchSelector
from .clone import CloneResult, CloneStats, SparseCloner, parse_repo_url, read_repos_file
from .multibranch import MultiBranchScanSetup, MultiBranchScanner
from .worktree import WorktreeInfo, WorktreeManager, WorktreeTask

__all__ = [
    "BranchInfo",
    "BranchSelector",
    "CloneResult",
    "CloneStats",
    "MultiBranchScanSetup",
    "MultiBranchScanner",
    "SparseCloner",
    "WorktreeInfo",
    "WorktreeManager",
    "WorktreeTask",
    "parse_repo_url",
    "read_repos_file",
]
