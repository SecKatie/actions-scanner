"""Application settings using Pydantic Settings.

Supports configuration from:
- Environment variables (ACTIONS_SCANNER_* prefix)
- .env files
- YAML config files (.actions-scanner.yaml)
- CLI arguments
"""

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ScanConfig(BaseModel):
    """Configuration for scanning operations."""

    workers: int = Field(default=10, description="Number of parallel scan workers")
    max_branches_per_repo: int = Field(
        default=100, description="Maximum branches to scan per repository"
    )
    include_protected: bool = Field(
        default=False, description="Include permission-gated findings in results"
    )
    sparse_paths: list[str] = Field(
        default=[".github/"], description="Paths to include in sparse checkout"
    )


class GitHubConfig(BaseModel):
    """Configuration for GitHub API operations."""

    token: str | None = Field(
        default=None, description="GitHub API token (falls back to GITHUB_TOKEN env var)"
    )
    concurrency: int = Field(default=50, description="Max concurrent API requests")
    timeout: int = Field(default=30, description="Request timeout in seconds")


class ValidationConfig(BaseModel):
    """Configuration for AI-assisted validation."""

    enabled: bool = Field(default=False, description="Enable AI validation")
    command_template: str = Field(
        default="claude --dangerously-skip-permissions -p {}",
        description="Command template for AI validation. Use {} for prompt placeholder. "
        "Do NOT include quotes around {} - they are added automatically via shlex.quote().",
    )
    timeout: int = Field(default=300, description="Validation timeout per repo in seconds")
    workers: int = Field(default=5, description="Number of parallel validation workers")
    prompt_template: str | None = Field(
        default=None, description="Custom prompt template (uses default if not set)"
    )


class LDAPConfig(BaseModel):
    """Configuration for optional LDAP enrichment."""

    enabled: bool = Field(default=False, description="Enable LDAP enrichment")
    host: str = Field(default="", description="LDAP server hostname")
    base: str = Field(default="", description="LDAP search base DN")
    social_url_attribute: str = Field(
        default="rhatSocialURL", description="LDAP attribute containing social URLs"
    )
    bind_dn: str = Field(default="", description="Bind DN for LDAP authentication")
    timeout: int = Field(default=10, description="LDAP connection timeout in seconds")


class OutputConfig(BaseModel):
    """Configuration for output and reporting."""

    format: str = Field(default="csv", description="Output format (csv, json, markdown)")
    output_dir: Path = Field(default=Path("."), description="Output directory")
    include_false_positives: bool = Field(
        default=False, description="Include false positives in reports"
    )
    verbose: bool = Field(default=False, description="Enable verbose output")


class Settings(BaseSettings):
    """Main application settings.

    Configuration sources (in order of precedence):
    1. CLI arguments (via Click)
    2. Environment variables (ACTIONS_SCANNER_SCAN__WORKERS=20)
    3. .env files
    4. YAML config file (.actions-scanner.yaml)
    5. Default values

    Environment variable examples:
        ACTIONS_SCANNER_SCAN__WORKERS=20
        ACTIONS_SCANNER_GITHUB__TOKEN=ghp_xxx
        ACTIONS_SCANNER_VALIDATION__ENABLED=true
        ACTIONS_SCANNER_VALIDATION__COMMAND_TEMPLATE='codex -m gpt-4 -p {}'
        ACTIONS_SCANNER_LDAP__ENABLED=true

    Note: Do NOT include quotes around {} in command templates - shlex.quote() handles this.
    """

    model_config = SettingsConfigDict(
        env_prefix="ACTIONS_SCANNER_",
        env_nested_delimiter="__",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    scan: ScanConfig = Field(default_factory=ScanConfig)
    github: GitHubConfig = Field(default_factory=GitHubConfig)
    validation: ValidationConfig = Field(default_factory=ValidationConfig)
    ldap: LDAPConfig = Field(default_factory=LDAPConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)

    @classmethod
    def from_yaml(cls, yaml_path: Path | str) -> "Settings":
        """Load settings from a YAML file.

        Args:
            yaml_path: Path to YAML configuration file

        Returns:
            Settings instance with values from YAML merged with defaults
        """
        import yaml

        yaml_path = Path(yaml_path)
        if not yaml_path.exists():
            return cls()

        with yaml_path.open() as f:
            data = yaml.safe_load(f) or {}

        return cls(**data)

    @classmethod
    def load(
        cls,
        yaml_path: Path | str | None = None,
        **overrides: Any,
    ) -> "Settings":
        """Load settings from all sources with optional overrides.

        Args:
            yaml_path: Optional path to YAML config file
            **overrides: Key-value overrides (e.g., scan={"workers": 20})

        Returns:
            Settings instance
        """
        # Start with base settings (loads from env vars and .env)
        settings_dict: dict[str, Any] = {}

        # Load from YAML if provided
        if yaml_path:
            import yaml

            yaml_path = Path(yaml_path)
            if yaml_path.exists():
                with yaml_path.open() as f:
                    yaml_data = yaml.safe_load(f) or {}
                    settings_dict.update(yaml_data)

        # Apply overrides
        for key, value in overrides.items():
            if value is not None:
                if isinstance(value, dict) and key in settings_dict:
                    # Merge nested dicts
                    settings_dict[key] = {**settings_dict.get(key, {}), **value}
                else:
                    settings_dict[key] = value

        return cls(**settings_dict)

    def get_validation_command(self, prompt: str) -> str:
        """Build a validation command with a safely quoted prompt."""
        import shlex

        quoted_prompt = shlex.quote(prompt)
        return self.validation.command_template.format(quoted_prompt)


# Default config file paths to check
DEFAULT_CONFIG_PATHS = [
    Path(".actions-scanner.yaml"),
    Path(".actions-scanner.yml"),
    Path("actions-scanner.yaml"),
    Path("actions-scanner.yml"),
]


def find_config_file(start_dir: Path | None = None) -> Path | None:
    """Find the configuration file in the current or parent directories.

    Args:
        start_dir: Directory to start searching from (defaults to cwd)

    Returns:
        Path to config file if found, None otherwise
    """
    start_dir = start_dir or Path.cwd()

    # Check current directory first
    for config_name in DEFAULT_CONFIG_PATHS:
        config_path = start_dir / config_name
        if config_path.exists():
            return config_path

    # Check parent directories up to home
    current = start_dir
    home = Path.home()

    while current != home and current.parent != current:
        current = current.parent
        for config_name in DEFAULT_CONFIG_PATHS:
            config_path = current / config_name
            if config_path.exists():
                return config_path

    return None


def get_settings(
    config_path: Path | str | None = None,
    **overrides: Any,
) -> Settings:
    """Get application settings.

    Convenience function that:
    1. Finds config file if not specified
    2. Loads settings from all sources
    3. Applies any overrides

    Args:
        config_path: Optional explicit config file path
        **overrides: Key-value overrides

    Returns:
        Settings instance
    """
    if config_path is None:
        config_path = find_config_file()

    return Settings.load(yaml_path=config_path, **overrides)
