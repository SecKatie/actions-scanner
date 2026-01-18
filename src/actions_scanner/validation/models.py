"""Data models for AI-assisted validation."""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class ValidationResult(str, Enum):
    """Result of AI validation."""

    VULNERABLE = "vulnerable"  # Confirmed exploitable
    WEAKNESS = "weakness"  # Requires approval but exploitable
    FALSE_POSITIVE = "false_positive"  # Not actually vulnerable
    FAILED = "failed"  # Validation error


@dataclass
class ValidationOutput:
    """Output from a validation run."""

    org: str
    repo: str
    result: ValidationResult
    workflow_paths: list[str] = field(default_factory=list)
    output_file: Path | None = None
    error: str | None = None
    duration_seconds: float = 0.0

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "org": self.org,
            "repo": self.repo,
            "result": self.result.value,
            "workflow_paths": self.workflow_paths,
            "output_file": str(self.output_file) if self.output_file else None,
            "error": self.error,
            "duration_seconds": self.duration_seconds,
        }


@dataclass
class ValidationStats:
    """Statistics from validation runs."""

    total: int = 0
    vulnerable: int = 0
    weakness: int = 0
    false_positive: int = 0
    failed: int = 0

    def record(self, result: ValidationResult) -> None:
        """Record a validation result."""
        self.total += 1
        if result == ValidationResult.VULNERABLE:
            self.vulnerable += 1
        elif result == ValidationResult.WEAKNESS:
            self.weakness += 1
        elif result == ValidationResult.FALSE_POSITIVE:
            self.false_positive += 1
        else:
            self.failed += 1

    @property
    def success_rate(self) -> float:
        """Get success rate (non-failed)."""
        if self.total == 0:
            return 0.0
        return (self.total - self.failed) / self.total * 100
