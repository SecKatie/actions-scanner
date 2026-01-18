"""Enrichment plugins for vulnerability data."""

from .base import EnrichmentPlugin, EnrichmentResult
from .github_users import (
    GitHubUserEnrichment,
    MergerEnrichmentData,
    add_mergers_to_vulnerabilities,
)
from .ldap import LDAP_AVAILABLE, LDAPEnrichment, LDAPUser

__all__ = [
    "LDAP_AVAILABLE",
    "EnrichmentPlugin",
    "EnrichmentResult",
    "GitHubUserEnrichment",
    "LDAPEnrichment",
    "LDAPUser",
    "MergerEnrichmentData",
    "add_mergers_to_vulnerabilities",
]
