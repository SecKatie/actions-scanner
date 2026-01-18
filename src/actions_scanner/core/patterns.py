"""Detection patterns for PwnRequest vulnerabilities."""

# Patterns for dangerous PR refs that checkout untrusted code
DANGEROUS_REF_PATTERNS = [
    r"github\.event\.pull_request\.head\.ref",
    r"github\.event\.pull_request\.head\.sha",
    r"github\.event\.pull_request\.merge_commit_sha",
    r"github\.head_ref",  # Shorthand equivalent to github.event.pull_request.head.ref
]

# Patterns for dangerous checkout repository values that point to PR head repos
DANGEROUS_REPO_PATTERNS = [
    r"github\.event\.pull_request\.head\.repo\.full_name",
    r"github\.event\.pull_request\.head\.repo\.name",
    r"github\.event\.pull_request\.head\.repo\.clone_url",
    r"github\.event\.pull_request\.head\.repo\.ssh_url",
]

# Dangerous build commands that execute from checked-out code
DANGEROUS_COMMANDS = [
    r"^\s*npm\s",
    r"^\s*yarn\s",
    r"^\s*pnpm\s",
    r"^\s*npx\s",
    r"^\s*make\b",
    r"^\s*pip\s",
    r"^\s*cargo\s",
    r"^\s*go\s+(build|run|test|install|mod)",
    r"^\s*\./",
    r"^\s*bash\s",
    r"^\s*sh\s",
    r"^\s*source\s",
    r"^\s*\.\s+",  # Sourcing with dot notation: . script.sh
    r"^\s*mvn\s",
    r"^\s*gradle\s",
    r"^\s*poetry\s",
    r"^\s*bundle\s",
    r"^\s*gem\s",
    r"^\s*rake\s",
    r"^\s*composer\s",
    r"^\s*phpunit\s",
    r"^\s*python[23]?\s",
    r"^\s*pytest\b",
    r"^\s*tox\b",
    r"^\s*docker\s+build",
    r"^\s*docker-compose\s",
    r"^\s*podman\s+build",
    r"^\s*ant\b",
    r"^\s*cmake\b",
    r"^\s*meson\b",
    r"^\s*node\s",
    r"^\s*deno\s",
    r"^\s*bun\s",
]

# Patterns that indicate collaborator permission checking in scripts
PERMISSION_CHECK_PATTERNS = [
    r"getCollaboratorPermissionLevel",
    r"repos\.getCollaboratorPermissionLevel",
]

# Patterns that indicate checking for write/admin/maintain access
WRITE_ACCESS_PATTERNS = [
    r"['\"](write|admin|maintain)['\"]",
    r"\.includes\s*\(\s*['\"]?(write|admin|maintain)",
    r"===?\s*['\"]?(write|admin|maintain)",
]

# Patterns in if conditions that indicate permission output gating
PERMISSION_OUTPUT_PATTERNS = [
    r"needs\.([a-zA-Z_-]+)\.outputs\.has-access\s*==\s*['\"]?true",
    r"needs\.([a-zA-Z_-]+)\.outputs\.is-collaborator\s*==\s*['\"]?true",
    r"needs\.([a-zA-Z_-]+)\.outputs\.is-member\s*==\s*['\"]?true",
    r"needs\.([a-zA-Z_-]+)\.outputs\.authorized\s*==\s*['\"]?true",
    r"needs\.([a-zA-Z_-]+)\.outputs\.allowed\s*==\s*['\"]?true",
]

# Patterns for POSITIVE label gating (require label to run)
# These indicate the job only runs when a maintainer adds a specific label
LABEL_REQUIRED_PATTERNS = [
    # Pattern: github.event.action == 'labeled' && github.event.label.name == 'ok-to-test'
    r"github\.event\.action\s*==\s*['\"]labeled['\"]",
]

# Patterns for same-repo checks (not from fork)
SAME_REPO_PATTERNS = [
    r"github\.event\.pull_request\.head\.repo\.full_name\s*==",
    r"github\.event\.pull_request\.head\.repo\.fork\s*==\s*false",
    r"github\.event\.pull_request\.head\.repo\.fork\s*!=\s*true",
]

# Authorization job patterns for dependency checking
AUTHORIZATION_JOB_PATTERNS = [
    "authorize",
    "auth",
    "approval",
    "check",
]
