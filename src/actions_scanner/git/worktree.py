"""Git worktree management for multi-branch scanning."""

import asyncio
import contextlib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class WorktreeInfo:
    """Information about a worktree."""

    repo_name: str
    branch: str
    path: Path


@dataclass
class WorktreeTask:
    """A pending worktree creation task."""

    repo_path: Path
    repo_name: str
    branch: str
    worktree_path: Path


class WorktreeManager:
    """Manages git worktrees with sparse checkout for multi-branch scanning.

    Creates lightweight worktrees that only contain specified paths
    (default: .github/) for efficient scanning across multiple branches.
    """

    def __init__(self, sparse_paths: list[str] | None = None, concurrency: int = 10):
        """Initialize the worktree manager.

        Args:
            sparse_paths: Paths to include in sparse checkout. Defaults to [".github/"].
            concurrency: Maximum concurrent worktree operations.
        """
        self.sparse_paths = sparse_paths or [".github/"]
        self.concurrency = concurrency

    async def _run_git_command(
        self, args: list[str], cwd: Path, check: bool = True
    ) -> tuple[int, str, str]:
        """Run a git command asynchronously."""
        proc = await asyncio.create_subprocess_exec(
            *args,
            cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        # returncode is guaranteed to be set after communicate() completes
        assert proc.returncode is not None
        if check and proc.returncode != 0:
            raise RuntimeError(f"Git command failed: {stderr.decode()}")
        return proc.returncode, stdout.decode(), stderr.decode()

    def _resolve_worktree_git_dir(self, worktree_path: Path) -> Path:
        """Resolve the actual git dir for a worktree."""
        git_path = worktree_path / ".git"
        if git_path.is_file():
            content = git_path.read_text().strip()
            if content.startswith("gitdir:"):
                git_dir = content.split(":", 1)[1].strip()
                return Path(git_dir)
        return git_path

    async def prune_worktrees(self, repo_path: Path) -> None:
        """Prune stale worktree registrations."""
        with contextlib.suppress(RuntimeError):
            await self._run_git_command(
                ["git", "worktree", "prune"],
                cwd=repo_path,
            )

    async def create_worktree(
        self,
        task: WorktreeTask,
        semaphore: asyncio.Semaphore | None = None,
    ) -> WorktreeInfo | None:
        """Create a single worktree with sparse checkout.

        Args:
            task: WorktreeTask describing the worktree to create
            semaphore: Optional semaphore for concurrency control

        Returns:
            WorktreeInfo if successful, None otherwise
        """

        async def _create():
            try:
                task.worktree_path.parent.mkdir(parents=True, exist_ok=True)
                # Create worktree without checking out files
                await self._run_git_command(
                    [
                        "git",
                        "worktree",
                        "add",
                        "-f",
                        "--detach",
                        "--no-checkout",
                        str(task.worktree_path),
                        f"origin/{task.branch}",
                    ],
                    cwd=task.repo_path,
                )

                # Resolve worktree git dir (handles nested paths)
                git_dir = self._resolve_worktree_git_dir(task.worktree_path)

                # Write sparse-checkout config directly (faster than git commands)
                config_file = git_dir / "config"
                with config_file.open("a") as f:
                    f.write("[core]\n\tsparseCheckout = true\n\tsparseCheckoutCone = true\n")

                sparse_checkout_file = git_dir / "info" / "sparse-checkout"
                sparse_checkout_file.parent.mkdir(parents=True, exist_ok=True)
                sparse_checkout_file.write_text("\n".join(self.sparse_paths) + "\n")

                # Checkout the files
                await self._run_git_command(
                    ["git", "checkout"],
                    cwd=task.worktree_path,
                )

                return WorktreeInfo(
                    repo_name=task.repo_name,
                    branch=task.branch,
                    path=task.worktree_path,
                )
            except (RuntimeError, OSError):
                return None

        if semaphore:
            async with semaphore:
                return await _create()
        return await _create()

    async def create_worktrees(
        self,
        tasks: list[WorktreeTask],
        on_progress: Callable[..., Any] | None = None,
    ) -> tuple[list[WorktreeInfo], int]:
        """Create all worktrees concurrently.

        Args:
            tasks: List of WorktreeTask objects
            on_progress: Optional callback(completed, total, worktree_info)

        Returns:
            Tuple of (list of successful WorktreeInfo, failure count)
        """
        semaphore = asyncio.Semaphore(self.concurrency)
        worktrees: list[WorktreeInfo] = []
        failed = 0
        lock = asyncio.Lock()
        completed = 0
        total = len(tasks)

        async def create_with_progress(task: WorktreeTask) -> WorktreeInfo | None:
            nonlocal completed, failed
            result = await self.create_worktree(task, semaphore)
            async with lock:
                completed += 1
                if result:
                    worktrees.append(result)
                else:
                    failed += 1
                if on_progress:
                    on_progress(completed, total, result)
            return result

        await asyncio.gather(
            *[create_with_progress(task) for task in tasks],
            return_exceptions=True,
        )

        return worktrees, failed

    async def remove_worktree(self, repo_path: Path, worktree_path: Path) -> bool:
        """Remove a worktree.

        Args:
            repo_path: Path to the main repository
            worktree_path: Path to the worktree to remove

        Returns:
            True if successful
        """
        try:
            await self._run_git_command(
                ["git", "worktree", "remove", "-f", str(worktree_path)],
                cwd=repo_path,
            )
            return True
        except RuntimeError:
            return False

    def load_cached_worktrees(self, worktrees_base: Path) -> list[WorktreeInfo]:
        """Load existing worktrees from a cache directory.

        Args:
            worktrees_base: Base directory containing worktree directories

        Returns:
            List of WorktreeInfo for existing worktrees
        """
        worktrees: list[WorktreeInfo] = []

        if not worktrees_base.exists():
            return worktrees

        for git_dir in worktrees_base.rglob(".git"):
            branch_dir = git_dir.parent
            repo_name = branch_dir.parent.name
            worktrees.append(
                WorktreeInfo(
                    repo_name=repo_name,
                    branch=branch_dir.name,
                    path=branch_dir,
                )
            )

        return worktrees
