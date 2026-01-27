"""GitHub API client and repository discovery."""

from .client import (
    GitHubClient,
    GitHubClientStats,
    OrgRepo,
    OrgScanner,
    RateLimitInfo,
    RepositoryScanner,
    RepoWorkflowScanResult,
    WorkflowFile,
)

__all__ = [
    "GitHubClient",
    "GitHubClientStats",
    "OrgRepo",
    "OrgScanner",
    "RateLimitInfo",
    "RepoWorkflowScanResult",
    "RepositoryScanner",
    "WorkflowFile",
]
