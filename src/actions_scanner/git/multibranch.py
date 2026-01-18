"""Multi-branch scanning support using worktrees."""

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .branch import BranchSelector
from .worktree import WorktreeManager, WorktreeTask


@dataclass
class MultiBranchScanSetup:
    """Result of setting up multi-branch scanning for a directory."""

    worktrees_created: int
    worktrees_failed: int
    branches_by_repo: dict[str, list[str]]
    scan_paths: list[Path]


class MultiBranchScanner:
    """Sets up and manages multi-branch scanning using git worktrees.

    This creates lightweight worktrees for each selected branch,
    allowing scanning across multiple branches without full clones.
    """

    def __init__(
        self,
        max_branches_per_repo: int = 10,
        sparse_paths: list[str] | None = None,
        concurrency: int = 10,
    ):
        """Initialize the multi-branch scanner.

        Args:
            max_branches_per_repo: Maximum branches to scan per repo.
                Uses smart sampling: default + oldest + newest + random.
            sparse_paths: Paths to include in sparse checkout.
            concurrency: Maximum concurrent git operations.
        """
        self.max_branches = max_branches_per_repo
        self.sparse_paths = sparse_paths or [".github/"]
        self.concurrency = concurrency
        self.branch_selector = BranchSelector(concurrency=concurrency)
        self.worktree_manager = WorktreeManager(
            sparse_paths=self.sparse_paths,
            concurrency=concurrency,
        )

    def _find_repos(self, base_dir: Path) -> list[Path]:
        """Find all git repositories in a directory.

        Args:
            base_dir: Directory to search

        Returns:
            List of paths to git repositories
        """
        repos = []
        for item in base_dir.iterdir():
            if item.is_dir():
                # Check if it's a git repo
                if (item / ".git").exists():
                    repos.append(item)
                elif (item / ".git").is_file():
                    # Worktree - .git is a file pointing to main repo
                    repos.append(item)
        return repos

    async def setup_worktrees(
        self,
        repos_dir: Path,
        worktrees_dir: Path | None = None,
        on_progress: Callable[..., Any] | None = None,
    ) -> MultiBranchScanSetup:
        """Set up worktrees for multi-branch scanning.

        Args:
            repos_dir: Directory containing cloned repositories
            worktrees_dir: Directory to create worktrees in.
                          Defaults to repos_dir/.worktrees
            on_progress: Optional callback(phase, completed, total, detail)

        Returns:
            MultiBranchScanSetup with scan paths and stats
        """
        if worktrees_dir is None:
            worktrees_dir = repos_dir / ".worktrees"

        worktrees_dir.mkdir(parents=True, exist_ok=True)

        # Find all repos
        repos = self._find_repos(repos_dir)

        if on_progress:
            on_progress("discover", 0, len(repos), "Finding repositories")

        # Select branches for each repo
        branches_by_repo: dict[str, list[str]] = {}
        tasks: list[WorktreeTask] = []

        for i, repo_path in enumerate(repos):
            repo_name = repo_path.name

            if on_progress:
                on_progress("branches", i + 1, len(repos), repo_name)

            try:
                branches = await self.branch_selector.select_branches(
                    repo_path, self.max_branches
                )
                branches_by_repo[repo_name] = branches

                # Create worktree tasks for non-default branches
                # (default branch is already checked out in the main repo)
                default_branch = await self.branch_selector.get_default_branch(repo_path)

                for branch in branches:
                    if branch == default_branch:
                        continue  # Skip default, it's in main repo

                    # Sanitize branch name for directory
                    safe_branch = branch.replace("/", "-")
                    worktree_path = worktrees_dir / repo_name / safe_branch

                    tasks.append(
                        WorktreeTask(
                            repo_path=repo_path,
                            repo_name=repo_name,
                            branch=branch,
                            worktree_path=worktree_path,
                        )
                    )
            except Exception:
                # Skip repos that fail branch discovery
                branches_by_repo[repo_name] = []

        if on_progress:
            on_progress("worktrees", 0, len(tasks), "Creating worktrees")

        # Create worktrees
        worktree_progress_count = 0

        def worktree_progress(completed: int, total: int, info: Any) -> None:
            nonlocal worktree_progress_count
            worktree_progress_count = completed
            if on_progress:
                detail = info.branch if info else "failed"
                on_progress("worktrees", completed, total, detail)

        worktrees, failed = await self.worktree_manager.create_worktrees(
            tasks, on_progress=worktree_progress
        )

        # Build list of all paths to scan
        scan_paths: list[Path] = []

        # Add main repo paths (default branches)
        for repo_path in repos:
            scan_paths.append(repo_path)

        # Add worktree paths
        for wt in worktrees:
            scan_paths.append(wt.path)

        return MultiBranchScanSetup(
            worktrees_created=len(worktrees),
            worktrees_failed=failed,
            branches_by_repo=branches_by_repo,
            scan_paths=scan_paths,
        )

    async def cleanup_worktrees(self, worktrees_dir: Path) -> int:
        """Remove all worktrees in a directory.

        Args:
            worktrees_dir: Directory containing worktrees

        Returns:
            Number of worktrees removed
        """
        import shutil

        removed = 0
        if worktrees_dir.exists():
            for repo_dir in worktrees_dir.iterdir():
                if repo_dir.is_dir():
                    shutil.rmtree(repo_dir, ignore_errors=True)
                    removed += 1
        return removed
