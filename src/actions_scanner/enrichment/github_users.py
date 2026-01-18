"""GitHub user enrichment for vulnerability data.

Adds merger information and repository context to vulnerability records.
"""

from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from actions_scanner.github.mergers import MergerFinder, RepoMergers

from .base import EnrichmentPlugin, EnrichmentResult


@dataclass
class MergerEnrichmentData:
    """Merger enrichment data for a repository."""

    org: str
    repo: str
    mergers: list[str]  # List of merger logins
    top_merger: str  # Most frequent merger
    merge_count: int  # Total merges by top merger


class GitHubUserEnrichment(EnrichmentPlugin):
    """Enrichment plugin for GitHub user information.

    Adds PR merger information to vulnerability records to help
    identify repository maintainers for notification.
    """

    def __init__(
        self,
        prs_to_check: int = 100,
        concurrency: int = 5,
        timeout: int = 30,
    ):
        """Initialize GitHub user enrichment.

        Args:
            prs_to_check: Number of recent merged PRs to analyze
            concurrency: Maximum concurrent gh CLI calls
            timeout: Timeout for each gh CLI call
        """
        self.merger_finder = MergerFinder(
            prs_to_check=prs_to_check,
            concurrency=concurrency,
            timeout=timeout,
        )
        self._cache: dict[tuple[str, str], RepoMergers] = {}

    @property
    def name(self) -> str:
        return "github_users"

    async def get_mergers(self, org: str, repo: str) -> RepoMergers:
        """Get merger information for a repository.

        Args:
            org: Repository organization
            repo: Repository name

        Returns:
            RepoMergers with merger information
        """
        cache_key = (org, repo)
        if cache_key in self._cache:
            return self._cache[cache_key]

        result = await self.merger_finder.find_mergers_for_repo(org, repo)
        self._cache[cache_key] = result
        return result

    async def enrich(self, data: dict[str, Any]) -> EnrichmentResult:
        """Enrich data with merger information.

        Expects data to contain 'org' and 'repo' fields.

        Args:
            data: Dictionary containing org and repo

        Returns:
            EnrichmentResult with merger fields added
        """
        org = data.get("org", "")
        repo = data.get("repo", "")

        if not org or not repo:
            return EnrichmentResult(
                success=False,
                data=data,
                error="Missing org or repo field",
            )

        try:
            mergers = await self.get_mergers(org, repo)

            enriched = data.copy()
            if mergers.mergers:
                merger_logins = [m.login for m in mergers.mergers]
                enriched["mergers"] = ",".join(merger_logins[:5])  # Top 5
                enriched["top_merger"] = mergers.mergers[0].login
                enriched["top_merger_count"] = mergers.mergers[0].merge_count
            else:
                enriched["mergers"] = ""
                enriched["top_merger"] = ""
                enriched["top_merger_count"] = 0

            enriched["total_prs_checked"] = mergers.total_prs_checked

            return EnrichmentResult(success=True, data=enriched)

        except Exception as e:
            return EnrichmentResult(
                success=False,
                data=data,
                error=str(e),
            )

    async def enrich_batch(
        self,
        records: list[dict[str, Any]],
        on_progress: Callable[..., Any] | None = None,
    ) -> list[EnrichmentResult]:
        """Enrich multiple records efficiently.

        Groups records by repository to avoid duplicate API calls.

        Args:
            records: List of dictionaries to enrich
            on_progress: Optional callback(completed, total)

        Returns:
            List of EnrichmentResult objects
        """
        # Group records by (org, repo)
        by_repo: dict[tuple[str, str], list[int]] = defaultdict(list)
        for i, record in enumerate(records):
            org = record.get("org", "")
            repo = record.get("repo", "")
            if org and repo:
                by_repo[(org, repo)].append(i)

        # Fetch mergers for each unique repo
        total_repos = len(by_repo)

        for completed_repos, (org, repo) in enumerate(by_repo, start=1):
            await self.get_mergers(org, repo)

            if on_progress:
                # Scale progress across records, not repos
                progress = int((completed_repos / total_repos) * len(records))
                on_progress(progress, len(records))

        # Now enrich all records using cached data
        results = []
        for record in records:
            result = await self.enrich(record)
            results.append(result)

        return results


def add_mergers_to_vulnerabilities(
    vulnerabilities: list[dict[str, Any]],
    repo_mergers: list[RepoMergers],
) -> list[dict[str, Any]]:
    """Add merger information to vulnerability records.

    Args:
        vulnerabilities: List of vulnerability dictionaries
        repo_mergers: List of RepoMergers from MergerFinder

    Returns:
        Updated vulnerability list with merger columns
    """
    # Build lookup by org/repo
    merger_lookup: dict[tuple[str, str], list[str]] = {}
    for rm in repo_mergers:
        if rm.mergers:
            merger_lookup[(rm.org, rm.repo)] = [m.login for m in rm.mergers[:5]]

    # Add to each vulnerability
    result = []
    for vuln in vulnerabilities:
        updated = vuln.copy()
        key = (vuln.get("org", ""), vuln.get("repo", ""))

        if key in merger_lookup:
            updated["mergers"] = ",".join(merger_lookup[key])
        else:
            updated["mergers"] = ""

        result.append(updated)

    return result
