"""Base classes for enrichment plugins."""

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass
class EnrichmentResult:
    """Result from an enrichment operation."""

    success: bool
    data: dict[str, Any]
    error: str | None = None


class EnrichmentPlugin(ABC):
    """Abstract base class for enrichment plugins.

    Enrichment plugins add additional context to vulnerability findings,
    such as identity information, organization data, or security context.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Plugin name for identification."""
        ...

    @property
    def is_available(self) -> bool:
        """Check if the plugin is available (dependencies installed, configured, etc.)."""
        return True

    @abstractmethod
    async def enrich(self, data: dict[str, Any]) -> EnrichmentResult:
        """Enrich a single data record.

        Args:
            data: Dictionary containing the data to enrich

        Returns:
            EnrichmentResult with enriched data
        """
        ...

    async def enrich_batch(
        self,
        records: list[dict[str, Any]],
        on_progress: Callable[..., Any] | None = None,
    ) -> list[EnrichmentResult]:
        """Enrich multiple records.

        Default implementation calls enrich() for each record.
        Override for batch-optimized implementations.

        Args:
            records: List of dictionaries to enrich
            on_progress: Optional callback(completed, total)

        Returns:
            List of EnrichmentResult objects
        """
        results = []
        total = len(records)

        for i, record in enumerate(records):
            result = await self.enrich(record)
            results.append(result)

            if on_progress:
                on_progress(i + 1, total)

        return results
