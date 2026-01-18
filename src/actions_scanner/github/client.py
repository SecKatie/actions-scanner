"""Async GitHub API client using aiohttp."""

import asyncio
import contextlib
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import aiohttp


@dataclass
class RateLimitInfo:
    """GitHub API rate limit information."""

    limit: int = 0
    remaining: int = 0
    reset_timestamp: int = 0


@dataclass
class GitHubClientStats:
    """Statistics for GitHub API operations."""

    requests_made: int = 0
    requests_successful: int = 0
    requests_failed: int = 0
    rate_limit_hits: int = 0


class GitHubClient:
    """Async GitHub API client with rate limiting and concurrency control.

    Provides low-level API access for higher-level scanner operations.
    """

    def __init__(
        self,
        token: str | None = None,
        concurrency: int = 50,
        timeout: int = 30,
    ):
        """Initialize the GitHub client.

        Args:
            token: GitHub API token. Falls back to GITHUB_TOKEN env var.
            concurrency: Maximum concurrent API requests.
            timeout: Request timeout in seconds.
        """
        self.token = token or os.environ.get("GITHUB_TOKEN")
        self.concurrency = concurrency
        self.timeout = timeout
        self.base_url = "https://api.github.com"

        self._session: aiohttp.ClientSession | None = None
        self._semaphore: asyncio.Semaphore | None = None
        self._rate_limit = RateLimitInfo()
        self._stats = GitHubClientStats()

    @property
    def headers(self) -> dict[str, str]:
        """Get default request headers."""
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "actions-scanner/1.0",
        }
        if self.token:
            headers["Authorization"] = f"token {self.token}"
        return headers

    @property
    def stats(self) -> GitHubClientStats:
        """Get client statistics."""
        return self._stats

    @property
    def rate_limit(self) -> RateLimitInfo:
        """Get current rate limit info."""
        return self._rate_limit

    async def __aenter__(self) -> "GitHubClient":
        """Async context manager entry."""
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.close()

    async def start(self) -> None:
        """Start the client session."""
        if self._session is None:
            connector = aiohttp.TCPConnector(
                limit=self.concurrency,
                limit_per_host=self.concurrency,
            )
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
            )
            self._semaphore = asyncio.Semaphore(self.concurrency)

    async def close(self) -> None:
        """Close the client session."""
        if self._session:
            await self._session.close()
            self._session = None

    def _update_rate_limit(self, headers: dict[str, Any]) -> None:
        """Update rate limit info from response headers."""
        if "X-RateLimit-Limit" in headers:
            self._rate_limit.limit = int(headers["X-RateLimit-Limit"])
        if "X-RateLimit-Remaining" in headers:
            self._rate_limit.remaining = int(headers["X-RateLimit-Remaining"])
        if "X-RateLimit-Reset" in headers:
            self._rate_limit.reset_timestamp = int(headers["X-RateLimit-Reset"])

    async def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        **kwargs,
    ) -> tuple[int, Any, dict[str, str]]:
        """Make an API request with rate limiting.

        Args:
            method: HTTP method (GET, POST, etc.)
            url: Full URL or path (will be prefixed with base_url if relative)
            headers: Additional headers to merge with defaults
            **kwargs: Additional arguments passed to aiohttp

        Returns:
            Tuple of (status_code, response_data, response_headers)

        Raises:
            RuntimeError: If client not started or rate limited
        """
        if self._session is None:
            raise RuntimeError("Client not started. Use async with or call start()")

        # Build full URL if relative
        if not url.startswith("http"):
            url = f"{self.base_url}{url}"

        # Merge headers
        request_headers = self.headers.copy()
        if headers:
            request_headers.update(headers)

        # Semaphore is guaranteed to be set after start() is called
        if self._semaphore is None:
            raise RuntimeError("Client not started. Use 'async with client:' or call start()")

        async with self._semaphore:
            self._stats.requests_made += 1

            try:
                async with self._session.request(
                    method, url, headers=request_headers, **kwargs
                ) as response:
                    self._update_rate_limit(response.headers)

                    if (
                        response.status in (429, 403)
                        and self._rate_limit.remaining == 0
                    ):
                        self._stats.rate_limit_hits += 1
                        retry_after = response.headers.get("Retry-After", "60")
                        raise RuntimeError(f"Rate limited. Retry after {retry_after}s")

                    # Try to parse JSON, fall back to text
                    try:
                        data = await response.json()
                    except (aiohttp.ContentTypeError, ValueError):
                        data = await response.text()

                    if 200 <= response.status < 300:
                        self._stats.requests_successful += 1
                    else:
                        self._stats.requests_failed += 1

                    return response.status, data, dict(response.headers)

            except aiohttp.ClientError as e:
                self._stats.requests_failed += 1
                raise RuntimeError(f"Request failed: {e}") from e

    async def get(self, url: str, **kwargs) -> tuple[int, Any, dict[str, str]]:
        """Make a GET request."""
        return await self.request("GET", url, **kwargs)

    async def get_json(self, url: str, **kwargs) -> Any:
        """Make a GET request and return JSON data only."""
        status, data, _ = await self.get(url, **kwargs)
        if status != 200:
            raise RuntimeError(f"Request failed with status {status}: {data}")
        return data

    async def get_raw(self, url: str, **kwargs) -> str:
        """Make a GET request for raw file content."""
        headers = {"Accept": "application/vnd.github.v3.raw"}
        status, data, _ = await self.request("GET", url, headers=headers, **kwargs)
        if status != 200:
            raise RuntimeError(f"Request failed with status {status}")
        return data if isinstance(data, str) else str(data)


@dataclass
class WorkflowFile:
    """Information about a workflow file in a repository."""

    name: str
    path: str
    download_url: str
    sha: str = ""


@dataclass
class RepoWorkflowScanResult:
    """Result of scanning a repository's workflow files via API."""

    repo_url: str
    org: str
    repo: str
    has_workflows: bool
    uses_pull_request_target: bool
    workflow_files: list[WorkflowFile] = field(default_factory=list)
    error: str | None = None


class RepositoryScanner:
    """Scans GitHub repositories for workflow files using the API.

    This is a lightweight scanner that uses the GitHub API to check
    if repositories have pull_request_target triggers, without cloning.
    """

    def __init__(self, client: GitHubClient):
        """Initialize the scanner.

        Args:
            client: GitHubClient instance for API requests
        """
        self.client = client

    def parse_repo_url(self, url: str) -> tuple[str, str]:
        """Extract owner and repo name from GitHub URL.

        Args:
            url: GitHub repository URL

        Returns:
            Tuple of (owner, repo)

        Raises:
            ValueError: If URL is invalid
        """
        url = url.strip().rstrip("/")
        parts = url.replace("https://github.com/", "").split("/")
        if len(parts) >= 2:
            return parts[0], parts[1]
        raise ValueError(f"Invalid GitHub URL: {url}")

    async def get_workflow_files(self, owner: str, repo: str) -> list[WorkflowFile]:
        """Fetch list of workflow files from a repository.

        Args:
            owner: Repository owner
            repo: Repository name

        Returns:
            List of WorkflowFile objects
        """
        url = f"/repos/{owner}/{repo}/contents/.github/workflows"

        try:
            status, data, _ = await self.client.get(url)

            if status == 404:
                return []
            if status != 200:
                return []

            if not isinstance(data, list):
                return []

            files = []
            for item in data:
                name = item.get("name", "")
                if name.endswith((".yml", ".yaml")):
                    files.append(
                        WorkflowFile(
                            name=name,
                            path=item.get("path", ""),
                            download_url=item.get("download_url", item.get("url", "")),
                            sha=item.get("sha", ""),
                        )
                    )
            return files

        except RuntimeError:
            return []

    async def check_workflow_for_prt(self, file_url: str) -> bool:
        """Check if a workflow file contains pull_request_target.

        Args:
            file_url: URL to fetch the workflow file content

        Returns:
            True if workflow uses pull_request_target
        """
        try:
            content = await self.client.get_raw(file_url)
            return "pull_request_target" in content
        except RuntimeError:
            return False

    async def scan_repo(self, repo_url: str) -> RepoWorkflowScanResult:
        """Scan a single repository for pull_request_target workflows.

        Args:
            repo_url: GitHub repository URL

        Returns:
            RepoWorkflowScanResult with findings
        """
        try:
            owner, repo = self.parse_repo_url(repo_url)
            workflow_files = await self.get_workflow_files(owner, repo)

            if not workflow_files:
                return RepoWorkflowScanResult(
                    repo_url=repo_url,
                    org=owner,
                    repo=repo,
                    has_workflows=False,
                    uses_pull_request_target=False,
                )

            # Check each workflow for pull_request_target
            has_prt = False
            for wf in workflow_files:
                if wf.download_url and await self.check_workflow_for_prt(wf.download_url):
                    has_prt = True
                    break

            return RepoWorkflowScanResult(
                repo_url=repo_url,
                org=owner,
                repo=repo,
                has_workflows=True,
                uses_pull_request_target=has_prt,
                workflow_files=workflow_files,
            )

        except ValueError as e:
            return RepoWorkflowScanResult(
                repo_url=repo_url,
                org="",
                repo="",
                has_workflows=False,
                uses_pull_request_target=False,
                error=str(e),
            )
        except RuntimeError as e:
            owner, repo = "", ""
            with contextlib.suppress(ValueError):
                owner, repo = self.parse_repo_url(repo_url)
            return RepoWorkflowScanResult(
                repo_url=repo_url,
                org=owner,
                repo=repo,
                has_workflows=False,
                uses_pull_request_target=False,
                error=str(e),
            )

    async def scan_repos(
        self,
        repo_urls: list[str],
        on_progress: Callable[..., Any] | None = None,
    ) -> list[RepoWorkflowScanResult]:
        """Scan multiple repositories concurrently.

        Args:
            repo_urls: List of repository URLs
            on_progress: Optional callback(completed, total, result)

        Returns:
            List of RepoWorkflowScanResult objects
        """
        results: list[RepoWorkflowScanResult] = []
        total = len(repo_urls)

        tasks = [self.scan_repo(url) for url in repo_urls]

        for i, coro in enumerate(asyncio.as_completed(tasks)):
            result = await coro
            results.append(result)

            if on_progress:
                on_progress(i + 1, total, result)

        return results


@dataclass
class OrgRepo:
    """Basic repository information from org listing."""

    name: str
    full_name: str
    clone_url: str
    html_url: str
    default_branch: str
    archived: bool = False
    fork: bool = False
    private: bool = False


class OrgScanner:
    """Discovers and lists repositories in GitHub organizations."""

    def __init__(self, client: GitHubClient):
        """Initialize the org scanner.

        Args:
            client: GitHubClient instance for API requests
        """
        self.client = client

    async def list_org_repos(
        self,
        org: str,
        include_archived: bool = False,
        include_forks: bool = False,
        repo_type: str = "all",
        on_progress: Callable[..., Any] | None = None,
    ) -> list[OrgRepo]:
        """List all repositories in an organization.

        Args:
            org: Organization name
            include_archived: Include archived repositories
            include_forks: Include forked repositories
            repo_type: Type filter: 'all', 'public', 'private', 'forks', 'sources'
            on_progress: Optional callback(page, repos_so_far)

        Returns:
            List of OrgRepo objects
        """
        repos: list[OrgRepo] = []
        page = 1
        per_page = 100

        while True:
            url = f"/orgs/{org}/repos?type={repo_type}&per_page={per_page}&page={page}"

            try:
                status, data, _ = await self.client.get(url)

                if status == 404:
                    raise RuntimeError(f"Organization '{org}' not found")
                if status != 200:
                    raise RuntimeError(f"Failed to list repos: {status} - {data}")

                if not isinstance(data, list) or len(data) == 0:
                    break

                for item in data:
                    repo = OrgRepo(
                        name=item.get("name", ""),
                        full_name=item.get("full_name", ""),
                        clone_url=item.get("clone_url", ""),
                        html_url=item.get("html_url", ""),
                        default_branch=item.get("default_branch", "main"),
                        archived=item.get("archived", False),
                        fork=item.get("fork", False),
                        private=item.get("private", False),
                    )

                    # Apply filters
                    if repo.archived and not include_archived:
                        continue
                    if repo.fork and not include_forks:
                        continue

                    repos.append(repo)

                if on_progress:
                    on_progress(page, len(repos))

                # Check if there are more pages
                if len(data) < per_page:
                    break

                page += 1

            except RuntimeError:
                raise

        return repos

    async def list_user_repos(
        self,
        username: str,
        include_forks: bool = False,
        on_progress: Callable[..., Any] | None = None,
    ) -> list[OrgRepo]:
        """List all repositories for a user.

        Args:
            username: GitHub username
            include_forks: Include forked repositories
            on_progress: Optional callback(page, repos_so_far)

        Returns:
            List of OrgRepo objects
        """
        repos: list[OrgRepo] = []
        page = 1
        per_page = 100

        while True:
            url = f"/users/{username}/repos?per_page={per_page}&page={page}"

            try:
                status, data, _ = await self.client.get(url)

                if status == 404:
                    raise RuntimeError(f"User '{username}' not found")
                if status != 200:
                    raise RuntimeError(f"Failed to list repos: {status} - {data}")

                if not isinstance(data, list) or len(data) == 0:
                    break

                for item in data:
                    repo = OrgRepo(
                        name=item.get("name", ""),
                        full_name=item.get("full_name", ""),
                        clone_url=item.get("clone_url", ""),
                        html_url=item.get("html_url", ""),
                        default_branch=item.get("default_branch", "main"),
                        archived=item.get("archived", False),
                        fork=item.get("fork", False),
                        private=item.get("private", False),
                    )

                    if repo.fork and not include_forks:
                        continue

                    repos.append(repo)

                if on_progress:
                    on_progress(page, len(repos))

                if len(data) < per_page:
                    break

                page += 1

            except RuntimeError:
                raise

        return repos

    async def list_multiple_orgs(
        self,
        orgs: list[str],
        include_archived: bool = False,
        include_forks: bool = False,
        on_progress: Callable[..., Any] | None = None,
    ) -> dict[str, list[OrgRepo]]:
        """List repositories from multiple organizations.

        Args:
            orgs: List of organization names
            include_archived: Include archived repositories
            include_forks: Include forked repositories
            on_progress: Optional callback(org_name, repos_count)

        Returns:
            Dict mapping org name to list of repos
        """
        results: dict[str, list[OrgRepo]] = {}

        for org in orgs:
            try:
                repos = await self.list_org_repos(
                    org,
                    include_archived=include_archived,
                    include_forks=include_forks,
                )
                results[org] = repos

                if on_progress:
                    on_progress(org, len(repos))

            except RuntimeError:
                # Store empty list on error
                results[org] = []
                if on_progress:
                    on_progress(org, 0)

        return results
