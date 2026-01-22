"""Core detection logic for workflow vulnerabilities."""

from .detector import (
    ContextInjectionDetector,
    PwnRequestDetector,
    WorkflowRunDetector,
    analyze_workflow,
    analyze_workflow_all,
    scan_directory,
)
from .models import (
    BranchInfo,
    ExecType,
    ProtectionLevel,
    RepoInfo,
    ScanResult,
    VulnerabilityType,
    VulnerableJob,
)
from .patterns import (
    DANGEROUS_COMMANDS,
    DANGEROUS_REF_PATTERNS,
    PR_TARGET_INJECTABLE_CONTEXTS,
    WORKFLOW_RUN_DANGEROUS_REF_PATTERNS,
    WORKFLOW_RUN_GIT_CHECKOUT_PATTERNS,
    WORKFLOW_RUN_INJECTABLE_CONTEXTS,
)

__all__ = [
    "DANGEROUS_COMMANDS",
    "DANGEROUS_REF_PATTERNS",
    "PR_TARGET_INJECTABLE_CONTEXTS",
    "WORKFLOW_RUN_DANGEROUS_REF_PATTERNS",
    "WORKFLOW_RUN_GIT_CHECKOUT_PATTERNS",
    "WORKFLOW_RUN_INJECTABLE_CONTEXTS",
    "BranchInfo",
    "ContextInjectionDetector",
    "ExecType",
    "ProtectionLevel",
    "PwnRequestDetector",
    "RepoInfo",
    "ScanResult",
    "VulnerabilityType",
    "VulnerableJob",
    "WorkflowRunDetector",
    "analyze_workflow",
    "analyze_workflow_all",
    "scan_directory",
]
