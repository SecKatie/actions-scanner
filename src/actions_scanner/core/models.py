"""Data models for vulnerability detection."""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class ProtectionLevel(str, Enum):
    """Protection level for a vulnerable job."""

    NONE = "none"  # Fully exploitable, any PR can trigger
    LABEL = "label"  # Requires maintainer to add label (social engineering vector)
    PERMISSION = "permission"  # Requires PR author to have write/admin/maintain access
    SAME_REPO = "same_repo"  # Only runs for PRs from same repo (not forks)
    ACTOR = "actor"  # Only runs for specific bot actors (not exploitable by external)
    MERGED = "merged"  # Only runs on merged PRs (code already reviewed)
    SAFE_USAGE = "safe_usage"  # Artifact data extracted/used safely (jq, quoted vars, heredoc)
    DISPATCH_FALLBACK = (
        "dispatch_fallback"  # Ref has workflow_dispatch input fallback (requires write)
    )


class VulnerabilityType(str, Enum):
    """Type of workflow vulnerability."""

    PWNREQUEST = "pwnrequest"  # pull_request_target trigger
    WORKFLOW_RUN = "workflow_run"  # workflow_run trigger
    CONTEXT_INJECTION = "context_injection"  # Direct ${{ }} injection in run blocks
    ARTIFACT_INJECTION = "artifact_injection"  # Reading artifact content into shell commands
    DISPATCH_CHECKOUT = "dispatch_checkout"  # issue_comment/workflow_dispatch checkout of PR code


class ExecType(str, Enum):
    """Type of dangerous execution after checkout."""

    LOCAL_ACTION = "local_action"
    BUILD_COMMAND = "build_command"


@dataclass
class VulnerableJob:
    """Represents a vulnerable job in a workflow."""

    workflow_path: Path
    job_name: str
    checkout_line: int
    checkout_ref: str
    exec_line: int
    exec_type: str  # 'local_action', 'build_command'
    exec_value: str
    has_authorization: bool = False
    branch: str = ""  # Populated by scanner when scanning worktrees
    protection: str = "none"  # none, label, permission, same_repo
    protection_detail: str = ""  # Description of the protection
    vulnerability_type: str = VulnerabilityType.PWNREQUEST.value  # pwnrequest or workflow_run
    triggering_workflows: list[str] = field(
        default_factory=list
    )  # For workflow_run: upstream workflows

    def is_exploitable(self) -> bool:
        """Return True if this vulnerability can be exploited by external attackers."""
        return self.protection in (ProtectionLevel.NONE.value, ProtectionLevel.LABEL.value)

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        result = {
            "vulnerability_type": self.vulnerability_type,
            "workflow_path": str(self.workflow_path),
            "job_name": self.job_name,
            "checkout_line": self.checkout_line,
            "checkout_ref": self.checkout_ref,
            "exec_line": self.exec_line,
            "exec_type": self.exec_type,
            "exec_value": self.exec_value,
            "has_authorization": self.has_authorization,
            "branch": self.branch,
            "protection": self.protection,
            "protection_detail": self.protection_detail,
        }
        # Only include triggering_workflows if non-empty (for workflow_run types)
        if self.triggering_workflows:
            result["triggering_workflows"] = self.triggering_workflows
        return result


@dataclass
class ScanResult:
    """Result of scanning a repository or directory."""

    vulnerabilities: list[VulnerableJob] = field(default_factory=list)
    files_scanned: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def exploitable_count(self) -> int:
        """Count of exploitable vulnerabilities."""
        return sum(1 for v in self.vulnerabilities if v.is_exploitable())

    @property
    def counts_by_protection(self) -> dict[str, int]:
        """Count vulnerabilities by protection level."""
        counts: dict[str, int] = {level.value: 0 for level in ProtectionLevel}
        for v in self.vulnerabilities:
            counts[v.protection] = counts.get(v.protection, 0) + 1
        return counts


@dataclass
class RepoInfo:
    """Information about a repository."""

    org: str
    name: str
    url: str = ""
    default_branch: str = "main"
    clone_path: Path | None = None

    @property
    def full_name(self) -> str:
        """Return org/name format."""
        return f"{self.org}/{self.name}"


@dataclass
class BranchInfo:
    """Information about a branch."""

    name: str
    commit_sha: str = ""
    commit_date: str = ""
    is_default: bool = False
