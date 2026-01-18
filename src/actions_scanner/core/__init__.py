"""Core detection logic for PwnRequest vulnerabilities."""

from .detector import PwnRequestDetector, analyze_workflow, scan_directory
from .models import (
    BranchInfo,
    ExecType,
    ProtectionLevel,
    RepoInfo,
    ScanResult,
    VulnerableJob,
)
from .patterns import (
    DANGEROUS_COMMANDS,
    DANGEROUS_REF_PATTERNS,
)

__all__ = [
    "DANGEROUS_COMMANDS",
    "DANGEROUS_REF_PATTERNS",
    "BranchInfo",
    "ExecType",
    "ProtectionLevel",
    "PwnRequestDetector",
    "RepoInfo",
    "ScanResult",
    "VulnerableJob",
    "analyze_workflow",
    "scan_directory",
]
