"""Find PR mergers for vulnerable repositories using GitHub GraphQL API."""
import asyncio
import subprocess
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

# Known bot accounts to exclude from merger lists
BOT_ACCOUNTS = frozenset({
    "openshift-merge-bot",
    "openshift-merge-robot",
    "renovate",
    "openshift-ci",
    "github-actions",
    "dependabot",
    "red-hat-konflux",
    "renovate-bot",
    "mergify",
    "dependabot[bot]",
    "github-actions[bot]",
    "renovate[bot]",
    "mergify[bot]",
})


@dataclass
class MergerInfo:
    """Information about a PR merger."""

    login: str
    merge_count: int


@dataclass
class RepoMergers:
    """PR mergers for a repository."""

    org: str
    repo: str
    mergers: list[MergerInfo] = field(default_factory=list)
    total_prs_checked: int = 0
    error: str | None = None

    @property
    def repo_url(self) -> str:
        """Get the repository URL."""
        return f"https://github.com/{self.org}/{self.repo}"


class MergerFinder:
    """Finds GitHub users who merge PRs on repositories.

    Uses the GitHub CLI (gh) with GraphQL to query PR merge history.
    This helps identify maintainers who might be targets for social
    engineering in label-gated vulnerabilities.
    """

    def __init__(
        self,
        prs_to_check: int = 100,
        concurrency: int = 5,
        timeout: int = 30,
    ):
        """Initialize the merger finder.

        Args:
            prs_to_check: Number of recent merged PRs to check per repo.
            concurrency: Maximum concurrent gh CLI calls.
            timeout: Timeout for each gh CLI call in seconds.
        """
        self.prs_to_check = prs_to_check
        self.concurrency = concurrency
        self.timeout = timeout
        self._semaphore: asyncio.Semaphore | None = None

    def _build_query(self, limit: int) -> str:
        """Build the GraphQL query for merged PRs."""
        return f"""
        query($owner: String!, $repo: String!) {{
          repository(owner: $owner, name: $repo) {{
            pullRequests(states: MERGED, first: {limit}, orderBy: {{field: UPDATED_AT, direction: DESC}}) {{
              nodes {{ mergedBy {{ login }} }}
            }}
          }}
        }}
        """

    async def get_mergers(self, org: str, repo: str) -> list[str]:
        """Get recent PR mergers for a repository using gh CLI.

        Args:
            org: Repository organization/owner
            repo: Repository name

        Returns:
            List of merger login names (may contain duplicates)
        """
        query = self._build_query(self.prs_to_check)

        try:
            proc = await asyncio.create_subprocess_exec(
                "gh",
                "api",
                "graphql",
                "-f",
                f"query={query}",
                "-f",
                f"owner={org}",
                "-f",
                f"repo={repo}",
                "--jq",
                ".data.repository.pullRequests.nodes[].mergedBy.login // empty",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, _stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=self.timeout
                )
            except TimeoutError:
                proc.kill()
                await proc.wait()
                return []

            if proc.returncode != 0:
                return []

            mergers = [
                m.strip()
                for m in stdout.decode().strip().split("\n")
                if m.strip()
            ]
            return mergers

        except (subprocess.SubprocessError, OSError):
            return []

    async def find_mergers_for_repo(
        self,
        org: str,
        repo: str,
        semaphore: asyncio.Semaphore | None = None,
    ) -> RepoMergers:
        """Find and count PR mergers for a repository.

        Args:
            org: Repository organization/owner
            repo: Repository name
            semaphore: Optional semaphore for concurrency control

        Returns:
            RepoMergers with merger information
        """
        async def _find():
            try:
                mergers = await self.get_mergers(org, repo)

                if not mergers:
                    return RepoMergers(org=org, repo=repo)

                # Count mergers, excluding bots
                merger_counts: dict[str, int] = defaultdict(int)
                for merger in mergers:
                    if merger.lower() not in BOT_ACCOUNTS and "[bot]" not in merger.lower():
                        merger_counts[merger] += 1

                # Convert to MergerInfo list, sorted by count
                merger_list = [
                    MergerInfo(login=login, merge_count=count)
                    for login, count in sorted(
                        merger_counts.items(), key=lambda x: -x[1]
                    )
                ]

                return RepoMergers(
                    org=org,
                    repo=repo,
                    mergers=merger_list,
                    total_prs_checked=len(mergers),
                )

            except Exception as e:
                return RepoMergers(org=org, repo=repo, error=str(e))

        if semaphore:
            async with semaphore:
                return await _find()
        return await _find()

    async def find_mergers_for_repos(
        self,
        repos: list[tuple[str, str]],
        on_progress: Callable[..., Any] | None = None,
    ) -> list[RepoMergers]:
        """Find mergers for multiple repositories concurrently.

        Args:
            repos: List of (org, repo) tuples
            on_progress: Optional callback(completed, total, repo_mergers)

        Returns:
            List of RepoMergers objects
        """
        self._semaphore = asyncio.Semaphore(self.concurrency)
        results: list[RepoMergers] = []
        total = len(repos)
        completed = 0
        lock = asyncio.Lock()

        async def process_repo(org: str, repo: str) -> RepoMergers:
            nonlocal completed
            result = await self.find_mergers_for_repo(org, repo, self._semaphore)
            async with lock:
                completed += 1
                results.append(result)
                if on_progress:
                    on_progress(completed, total, result)
            return result

        await asyncio.gather(
            *[process_repo(org, repo) for org, repo in repos],
            return_exceptions=True,
        )

        return results

    def get_unique_mergers(self, repo_mergers: list[RepoMergers]) -> set[str]:
        """Get set of unique merger logins across all repos.

        Args:
            repo_mergers: List of RepoMergers objects

        Returns:
            Set of unique merger login names
        """
        unique = set()
        for rm in repo_mergers:
            for merger in rm.mergers:
                unique.add(merger.login)
        return unique
