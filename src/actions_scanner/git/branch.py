"""Branch selection with smart sampling for multi-branch scanning."""

import asyncio
import random
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class BranchInfo:
    """Information about a branch including commit date."""

    name: str
    commit_timestamp: int  # Unix timestamp of the branch tip commit


class BranchSelector:
    """Selects branches for scanning using smart sampling.

    Prioritizes:
    1. Default branch (main/master)
    2. Oldest branch (historical context)
    3. Newest branch (most recent changes)
    4. Random sample of remaining branches
    """

    def __init__(self, concurrency: int = 10):
        """Initialize the branch selector.

        Args:
            concurrency: Maximum concurrent git operations.
        """
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

    async def get_default_branch(self, repo_path: Path) -> str | None:
        """Get the default branch name for a repository.

        Args:
            repo_path: Path to the repository

        Returns:
            Default branch name (e.g., 'main', 'master') or None
        """
        try:
            _, stdout, _ = await self._run_git_command(
                ["git", "symbolic-ref", "refs/remotes/origin/HEAD"],
                cwd=repo_path,
            )
            ref = stdout.strip()
            if ref.startswith("refs/remotes/origin/"):
                return ref.replace("refs/remotes/origin/", "")
        except RuntimeError:
            pass

        # Fallback: check common default branch names
        for name in ["main", "master", "develop", "trunk"]:
            try:
                await self._run_git_command(
                    ["git", "rev-parse", f"origin/{name}"],
                    cwd=repo_path,
                )
                return name
            except RuntimeError:
                continue

        return None

    async def get_branches_with_dates(self, repo_path: Path) -> list[BranchInfo]:
        """Get all remote branches with their commit timestamps.

        Args:
            repo_path: Path to the repository

        Returns:
            List of BranchInfo sorted by commit timestamp
        """
        try:
            _, stdout, _ = await self._run_git_command(
                [
                    "git",
                    "for-each-ref",
                    "--format=%(refname:short) %(committerdate:unix)",
                    "refs/remotes/origin/",
                ],
                cwd=repo_path,
            )

            branches = []
            for line in stdout.splitlines():
                line = line.strip()
                if not line or "HEAD" in line:
                    continue

                parts = line.rsplit(" ", 1)
                if len(parts) != 2:
                    continue

                ref, timestamp_str = parts
                if ref.startswith("origin/"):
                    branch_name = ref.replace("origin/", "", 1)
                    try:
                        timestamp = int(timestamp_str)
                        branches.append(BranchInfo(name=branch_name, commit_timestamp=timestamp))
                    except ValueError:
                        continue

            return branches
        except RuntimeError:
            return []

    async def select_branches(self, repo_path: Path, max_branches: int | None = None) -> list[str]:
        """Select branches to scan using smart sampling.

        Selection strategy:
        1. Always include default branch
        2. Always include oldest branch (historical)
        3. Always include newest branch (recent)
        4. Randomly sample remaining slots

        Args:
            repo_path: Path to the repository
            max_branches: Maximum number of branches to select.
                         None means all branches.

        Returns:
            List of branch names to scan
        """
        branches_with_dates = await self.get_branches_with_dates(repo_path)

        if not branches_with_dates:
            return []

        if max_branches is None or max_branches >= len(branches_with_dates):
            return [b.name for b in branches_with_dates]

        default_branch = await self.get_default_branch(repo_path)

        sorted_by_date = sorted(branches_with_dates, key=lambda b: b.commit_timestamp)
        oldest_branch = sorted_by_date[0].name
        latest_branch = sorted_by_date[-1].name

        # Start with priority branches (deduped)
        priority_branches = set()
        if default_branch:
            priority_branches.add(default_branch)
        priority_branches.add(oldest_branch)
        priority_branches.add(latest_branch)

        selected = list(priority_branches)

        # Fill remaining slots with random sample
        if len(selected) < max_branches:
            remaining = [b.name for b in branches_with_dates if b.name not in priority_branches]
            slots_available = max_branches - len(selected)

            if remaining:
                sampled = random.sample(remaining, min(slots_available, len(remaining)))
                selected.extend(sampled)

        return selected

    async def select_branches_for_repos(
        self,
        repo_paths: list[Path],
        max_branches_per_repo: int | None = None,
        on_progress: Callable[..., Any] | None = None,
    ) -> dict[Path, list[str]]:
        """Select branches for multiple repositories concurrently.

        Args:
            repo_paths: List of repository paths
            max_branches_per_repo: Maximum branches per repository
            on_progress: Optional callback(completed, total, repo_path)

        Returns:
            Dict mapping repo_path to list of selected branch names
        """
        semaphore = asyncio.Semaphore(self.concurrency)
        results: dict[Path, list[str]] = {}
        lock = asyncio.Lock()
        completed = 0
        total = len(repo_paths)

        async def select_for_repo(repo_path: Path) -> tuple[Path, list[str]]:
            nonlocal completed
            async with semaphore:
                branches = await self.select_branches(repo_path, max_branches_per_repo)
                async with lock:
                    completed += 1
                    if on_progress:
                        on_progress(completed, total, repo_path)
                return repo_path, branches

        tasks = await asyncio.gather(
            *[select_for_repo(path) for path in repo_paths],
            return_exceptions=True,
        )

        for result in tasks:
            if isinstance(result, tuple):
                repo_path, branches = result
                results[repo_path] = branches

        return results
