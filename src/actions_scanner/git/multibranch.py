"""Multi-branch scanning support using worktrees."""

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from actions_scanner.utils.path import encode_branch, extract_org_repo_branch_from_path

from .branch import BranchSelector
from .worktree import WorktreeManager, WorktreeTask


@dataclass
class MultiBranchScanSetup:
    """Result of setting up multi-branch scanning for a directory."""

    worktrees_created: int
    worktrees_failed: int
    branches_by_repo: dict[str, list[str]]
    scan_paths: list[Path]


@dataclass
class RepoTarget:
    """Repo metadata for worktree creation."""

    path: Path
    org: str
    repo: str
    branch: str


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
        repos: list[Path] = []
        if (base_dir / ".git").exists():
            repos.append(base_dir)

        for git_dir in base_dir.rglob(".git"):
            repo_path = git_dir.parent
            if repo_path == base_dir:
                continue
            if ".worktrees" in repo_path.parts:
                continue
            repos.append(repo_path)
        return repos

    def _build_repo_targets(self, base_dir: Path) -> list[RepoTarget]:
        """Build repo targets from discovered git dirs."""
        targets: list[RepoTarget] = []
        for repo_path in self._find_repos(base_dir):
            org, repo, branch = extract_org_repo_branch_from_path(str(repo_path))
            targets.append(
                RepoTarget(
                    path=repo_path,
                    org=org,
                    repo=repo,
                    branch=branch,
                )
            )
        return targets

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
        repo_targets = self._build_repo_targets(repos_dir)

        if on_progress:
            on_progress("discover", 0, len(repo_targets), "Finding repositories")

        # Select branches for each repo
        branches_by_repo: dict[str, list[str]] = {}
        tasks: list[WorktreeTask] = []

        for i, target in enumerate(repo_targets):
            repo_label = f"{target.org}/{target.repo}".strip("/")
            if not repo_label:
                repo_label = target.path.name

            if on_progress:
                on_progress("branches", i + 1, len(repo_targets), repo_label)

            try:
                branches = await self.branch_selector.select_branches(
                    target.path, self.max_branches
                )
                branches_by_repo[repo_label] = branches

                # Create worktree tasks for non-default branches
                # (default branch is already checked out in the main repo)
                default_branch = await self.branch_selector.get_default_branch(target.path)

                for branch in branches:
                    if branch == default_branch:
                        continue  # Skip default, it's in main repo

                    # Sanitize branch name for directory
                    safe_branch = encode_branch(branch)
                    if target.org and target.repo:
                        worktree_path = worktrees_dir / target.org / target.repo / safe_branch
                        repo_name = f"{target.org}/{target.repo}"
                    else:
                        worktree_path = worktrees_dir / target.path.name / safe_branch
                        repo_name = target.path.name

                    tasks.append(
                        WorktreeTask(
                            repo_path=target.path,
                            repo_name=repo_name,
                            branch=branch,
                            worktree_path=worktree_path,
                        )
                    )
            except Exception:
                # Skip repos that fail branch discovery
                branches_by_repo[repo_label] = []

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
        for target in repo_targets:
            scan_paths.append(target.path)

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
