"""Sparse cloning operations for GitHub repositories."""

import asyncio
import re
import shutil
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from actions_scanner.utils.path import encode_branch


class CloneResult(Enum):
    """Result status for repository cloning."""

    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class CloneStats:
    """Statistics for cloning operations."""

    success: int = 0
    failed: int = 0
    skipped: int = 0
    success_repos: list[str] = field(default_factory=list)
    failed_repos: list[str] = field(default_factory=list)
    skipped_repos: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return self.success + self.failed + self.skipped


def parse_repo_url(url: str) -> str | None:
    """Extract owner/repo from GitHub URL.

    Args:
        url: GitHub repository URL

    Returns:
        Repository name in format 'owner/repo' or None if invalid
    """
    # Match github.com URLs with either HTTPS or SSH format
    pattern = r"github\.com[:/]([^/]+)/([^/]+)"
    match = re.search(pattern, url)

    if match:
        owner = match.group(1)
        repo = match.group(2)
        # Remove .git suffix if present
        if repo.endswith(".git"):
            repo = repo[:-4]
        return f"{owner}/{repo}"

    return None


class SparseCloner:
    """Handles sparse cloning of GitHub repositories.

    Clones only specified paths (default: .github/) using sparse-checkout
    and fetches all branches for comprehensive scanning.
    """

    def __init__(
        self,
        sparse_paths: list[str] | None = None,
        concurrency: int = 5,
        shallow: bool = True,
        single_branch: bool = False,
    ):
        """Initialize the sparse cloner.

        Args:
            sparse_paths: List of paths to include in sparse checkout.
                         Defaults to [".github/"].
            concurrency: Maximum number of concurrent clone operations.
            shallow: If True, use --depth=1 for minimal .git folder size.
                    Defaults to True.
            single_branch: If True, only fetch the default branch.
                          If False, fetch all branches for multi-branch scanning.
                          Defaults to False.
        """
        self.sparse_paths = sparse_paths or [".github/"]
        self.concurrency = concurrency
        self.shallow = shallow
        self.single_branch = single_branch
        self._semaphore: asyncio.Semaphore | None = None

    async def _run_git_command(
        self, args: list[str], cwd: Path | None = None
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
        return proc.returncode, stdout.decode(), stderr.decode()

    async def _get_current_branch(self, repo_dir: Path) -> str:
        """Get the current branch name for a repo."""
        returncode, stdout, _stderr = await self._run_git_command(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=repo_dir
        )
        if returncode == 0:
            return stdout.strip()
        return ""

    async def clone_sparse(self, repo_url: str, dest_dir: Path) -> tuple[bool, str | None]:
        """Clone repository with sparse checkout.

        Args:
            repo_url: Repository URL to clone
            dest_dir: Destination directory path

        Returns:
            Tuple of (success: bool, error_message: Optional[str])
        """
        try:
            # Build clone command with configurable options
            clone_cmd = [
                "git",
                "clone",
                "--filter=blob:none",
                "--sparse",
                "--no-checkout",
            ]

            # Add depth for shallow clones (significantly reduces .git size)
            if self.shallow:
                clone_cmd.append("--depth=1")

            # Branch fetching strategy
            if self.single_branch:
                clone_cmd.append("--single-branch")
            else:
                clone_cmd.append("--no-single-branch")

            clone_cmd.extend([repo_url, str(dest_dir)])

            returncode, _, stderr = await self._run_git_command(clone_cmd)
            if returncode != 0:
                return False, stderr.strip()

            # Configure sparse-checkout
            config_commands = [
                ["git", "config", "core.sparseCheckout", "true"],
                ["git", "config", "core.sparseCheckoutCone", "true"],
            ]

            for cmd in config_commands:
                returncode, _, stderr = await self._run_git_command(cmd, cwd=dest_dir)
                if returncode != 0:
                    return False, stderr.strip()

            # Write sparse-checkout configuration
            sparse_checkout_file = dest_dir / ".git" / "info" / "sparse-checkout"
            sparse_checkout_file.parent.mkdir(parents=True, exist_ok=True)
            sparse_checkout_file.write_text("\n".join(self.sparse_paths) + "\n")

            # Checkout the default branch
            returncode, _, stderr = await self._run_git_command(["git", "checkout"], cwd=dest_dir)
            if returncode != 0:
                return False, stderr.strip()

            return True, None

        except Exception as e:
            return False, str(e)

    async def process_repo(self, repo_url: str, repos_dir: Path) -> tuple[str, CloneResult]:
        """Process a single repository clone operation.

        Args:
            repo_url: Repository URL to clone
            repos_dir: Base directory for cloned repositories

        Returns:
            Tuple of (repo_name, result_status)
        """
        # Parse repository URL
        repo_name = parse_repo_url(repo_url)
        if not repo_name:
            return repo_url, CloneResult.FAILED

        owner, repo = repo_name.split("/", 1)
        base_dir = repos_dir / owner / repo

        # Skip if already exists with content
        if base_dir.exists() and any(base_dir.iterdir()):
            return repo_name, CloneResult.SKIPPED

        temp_dir = base_dir / "_tmp_clone"
        if temp_dir.exists():
            shutil.rmtree(temp_dir, ignore_errors=True)
        temp_dir.parent.mkdir(parents=True, exist_ok=True)

        # Attempt to clone
        success, _ = await self.clone_sparse(repo_url, temp_dir)
        if success:
            branch = await self._get_current_branch(temp_dir)
            branch_dir = encode_branch(branch or "default")
            dest_dir = base_dir / branch_dir / "code"
            dest_dir.parent.mkdir(parents=True, exist_ok=True)
            if dest_dir.exists():
                shutil.rmtree(temp_dir, ignore_errors=True)
                return repo_name, CloneResult.SKIPPED

            shutil.move(str(temp_dir), str(dest_dir))
            return repo_name, CloneResult.SUCCESS
        else:
            # Clean up failed clone attempt
            if temp_dir.exists():
                shutil.rmtree(temp_dir, ignore_errors=True)
            return repo_name, CloneResult.FAILED

    async def clone_repos(
        self,
        repo_urls: list[str],
        repos_dir: Path,
        on_progress: Callable[..., Any] | None = None,
    ) -> CloneStats:
        """Clone multiple repositories concurrently.

        Args:
            repo_urls: List of repository URLs to clone
            repos_dir: Base directory for cloned repositories
            on_progress: Optional callback for progress updates.
                        Called with (completed, total, repo_name, result).

        Returns:
            CloneStats with results
        """
        repos_dir.mkdir(parents=True, exist_ok=True)
        stats = CloneStats()
        semaphore = asyncio.Semaphore(self.concurrency)

        async def clone_with_semaphore(url: str) -> tuple[str, CloneResult]:
            async with semaphore:
                return await self.process_repo(url, repos_dir)

        # Create all tasks
        tasks = [clone_with_semaphore(url) for url in repo_urls]
        total = len(tasks)

        # Process results as they complete
        for i, coro in enumerate(asyncio.as_completed(tasks)):
            repo_name, result = await coro

            if result == CloneResult.SUCCESS:
                stats.success += 1
                stats.success_repos.append(repo_name)
            elif result == CloneResult.FAILED:
                stats.failed += 1
                stats.failed_repos.append(repo_name)
            else:
                stats.skipped += 1
                stats.skipped_repos.append(repo_name)

            if on_progress:
                on_progress(i + 1, total, repo_name, result)

        return stats


def read_repos_file(repos_file: Path) -> list[str]:
    """Read repository URLs from file, skipping empty lines and comments.

    Args:
        repos_file: Path to file containing repository URLs

    Returns:
        List of repository URLs
    """
    repos = []
    with repos_file.open("r") as f:
        for line in f:
            line = line.strip()
            # Skip empty lines and comments
            if line and not line.startswith("#"):
                repos.append(line)
    return repos
