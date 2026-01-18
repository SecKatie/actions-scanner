"""LDAP enrichment plugin for identity lookup.

This plugin looks up GitHub usernames in LDAP to find
associated corporate identities (name, email).

Requires the ldap3 package: pip install actions-scanner[ldap]
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
from typing import Any

from .base import EnrichmentPlugin, EnrichmentResult

# Runtime check for ldap3 availability
try:
    import ldap3 as _ldap3
    from ldap3 import Connection as _Connection
    from ldap3 import Server as _Server
    from ldap3.core.exceptions import LDAPException as _LDAPException
    from ldap3.utils.conv import escape_filter_chars as _escape_filter_chars

    LDAP_AVAILABLE = True
except ImportError:
    LDAP_AVAILABLE = False
    _ldap3 = None  # type: ignore[assignment]
    _Connection = None  # type: ignore[assignment, misc]
    _Server = None  # type: ignore[assignment, misc]
    _LDAPException = Exception  # type: ignore[assignment, misc]
    _escape_filter_chars = None  # type: ignore[assignment]


def _escape_filter(value: str) -> str:
    """Escape LDAP filter values defensively."""
    if value is None:
        return ""
    if _escape_filter_chars:
        return _escape_filter_chars(str(value))
    replacements = {
        "\\": r"\5c",
        "*": r"\2a",
        "(": r"\28",
        ")": r"\29",
        "\x00": r"\00",
    }
    return "".join(replacements.get(ch, ch) for ch in str(value))


@dataclass
class LDAPUser:
    """User information from LDAP."""

    github_username: str
    email: str
    full_name: str
    dn: str = ""


class LDAPEnrichment(EnrichmentPlugin):
    """Enrichment plugin for LDAP identity lookup.

    Searches LDAP for users with social URLs containing GitHub usernames.
    Commonly used with corporate LDAP directories (e.g., Red Hat).
    """

    def __init__(
        self,
        host: str,
        base_dn: str,
        social_url_attribute: str = "rhatSocialURL",
        bind_dn: str = "",
        bind_password: str = "",
        timeout: int = 10,
    ):
        """Initialize LDAP enrichment.

        Args:
            host: LDAP server hostname (e.g., "ldap://ldap.corp.example.com")
            base_dn: Base DN for searches (e.g., "ou=users,dc=example,dc=com")
            social_url_attribute: LDAP attribute containing social URLs
            bind_dn: DN to bind as (empty for anonymous)
            bind_password: Password for bind
            timeout: Connection timeout in seconds
        """
        self.host = host
        self.base_dn = base_dn
        self.social_url_attribute = social_url_attribute
        self.bind_dn = bind_dn
        self.bind_password = bind_password
        self.timeout = timeout
        self._connection: Any = None
        self._cache: dict[str, LDAPUser | None] = {}

    @property
    def name(self) -> str:
        return "ldap"

    @property
    def is_available(self) -> bool:
        return LDAP_AVAILABLE and bool(self.host)

    def _get_connection(self) -> Any:
        """Get or create LDAP connection."""
        if not LDAP_AVAILABLE or _ldap3 is None or _Server is None or _Connection is None:
            raise RuntimeError(
                "ldap3 package not installed. Run: pip install actions-scanner[ldap]"
            )

        if self._connection is None:
            server = _Server(self.host, get_info=_ldap3.NONE, connect_timeout=self.timeout)

            if self.bind_dn:
                self._connection = _Connection(
                    server,
                    user=self.bind_dn,
                    password=self.bind_password,
                    auto_bind=True,
                )
            else:
                self._connection = _Connection(server, auto_bind=True)

        return self._connection

    def _extract_github_url_filter(self, github_username: str) -> str:
        """Build LDAP filter to find user by GitHub username in social URL."""
        # The social URL typically looks like: https://github.com/username
        safe_username = _escape_filter(github_username)
        return f"({self.social_url_attribute}=*github.com/{safe_username}*)"

    def lookup_user(self, github_username: str) -> LDAPUser | None:
        """Look up a GitHub user in LDAP.

        Args:
            github_username: GitHub username to look up

        Returns:
            LDAPUser if found, None otherwise
        """
        # Check cache first
        if github_username in self._cache:
            return self._cache[github_username]

        if not self.is_available:
            return None

        try:
            conn = self._get_connection()
            search_filter = self._extract_github_url_filter(github_username)

            conn.search(
                search_base=self.base_dn,
                search_filter=search_filter,
                attributes=["mail", "cn", "displayName", self.social_url_attribute],
            )

            if conn.entries:
                entry = conn.entries[0]
                user = LDAPUser(
                    github_username=github_username,
                    email=str(entry.mail) if hasattr(entry, "mail") else "",
                    full_name=str(entry.displayName if hasattr(entry, "displayName") else entry.cn),
                    dn=str(entry.entry_dn),
                )
                self._cache[github_username] = user
                return user

            self._cache[github_username] = None
            return None

        except (_LDAPException, OSError):
            # Log error but don't fail
            self._cache[github_username] = None
            return None

    async def enrich(self, data: dict[str, Any]) -> EnrichmentResult:
        """Enrich data with LDAP user information.

        Expects data to contain a 'github_username' or 'merger' field.

        Args:
            data: Dictionary containing GitHub username

        Returns:
            EnrichmentResult with email and name fields added
        """
        # Look for username in common fields
        github_username = (
            data.get("github_username")
            or data.get("merger")
            or data.get("merger_login")
            or data.get("username")
        )

        if not github_username:
            return EnrichmentResult(
                success=False,
                data=data,
                error="No GitHub username field found",
            )

        try:
            user = self.lookup_user(github_username)

            if user:
                enriched = data.copy()
                enriched["ldap_email"] = user.email
                enriched["ldap_name"] = user.full_name
                enriched["ldap_found"] = True
                return EnrichmentResult(success=True, data=enriched)
            else:
                enriched = data.copy()
                enriched["ldap_email"] = ""
                enriched["ldap_name"] = ""
                enriched["ldap_found"] = False
                return EnrichmentResult(success=True, data=enriched)

        except Exception as e:
            return EnrichmentResult(
                success=False,
                data=data,
                error=str(e),
            )

    def close(self) -> None:
        """Close the LDAP connection."""
        if self._connection:
            with contextlib.suppress(Exception):
                self._connection.unbind()
            self._connection = None

    def __enter__(self) -> LDAPEnrichment:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()
