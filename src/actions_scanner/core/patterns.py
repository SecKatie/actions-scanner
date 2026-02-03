"""Detection patterns for PwnRequest vulnerabilities."""

# Patterns for dangerous PR refs that checkout untrusted code
DANGEROUS_REF_PATTERNS = [
    r"github\.event\.pull_request\.head\.ref",
    r"github\.event\.pull_request\.head\.sha",
    r"github\.event\.pull_request\.merge_commit_sha",
    r"github\.head_ref",  # Shorthand equivalent to github.event.pull_request.head.ref
    # refs/pull/N/merge and refs/pull/N/head patterns - checkout PR code by number
    r"refs/pull/\$\{\{.*github\.event\.pull_request\.number.*\}\}/merge",
    r"refs/pull/\$\{\{.*github\.event\.pull_request\.number.*\}\}/head",
    r"refs/pull/\$\{\{.*github\.event\.number.*\}\}/merge",
    r"refs/pull/\$\{\{.*github\.event\.number.*\}\}/head",
    # format() function patterns for refs/pull
    r"format\s*\(\s*['\"]refs/pull/\{0\}/(merge|head)['\"]",
    # fromJson patterns for reusable workflows that pass github context as input
    r"refs/pull/\$\{\{.*fromJson\(inputs\.github\)\.event\.number.*\}\}/merge",
    r"refs/pull/\$\{\{.*fromJson\(inputs\.github\)\.event\.number.*\}\}/head",
    r"fromJson\(inputs\.github\)\.event\.pull_request\.head\.(ref|sha)",
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
    r"^\s*uv\s+(run|sync|pip)",
    r"^\s*pdm\s+(run|install)",
    r"^\s*hatch\s+run",
    r"^\s*rye\s+run",
    r"^\s*pixi\s+run",
    r"^\s*pre-commit\s",
    # Nix/devbox environments that can run arbitrary commands
    r"^\s*devbox\s+run",
    r"^\s*nix\s+(run|shell|develop)",
    r"^\s*nix-shell\s",
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
    # Infrastructure as Code tools
    r"^\s*terraform\s",
    r"^\s*terramate\s",
    r"^\s*pulumi\s",
    r"^\s*helm\s",
    r"^\s*kubectl\s+apply",
    r"^\s*ansible-playbook\s",
    r"^\s*ansible\s",
    # Ruby/Rails
    r"^\s*rails\s",
    # Rust
    r"^\s*rustc\s",
    # Swift
    r"^\s*swift\s+(build|run|test)",
    # Elixir
    r"^\s*mix\s",
    r"^\s*elixir\s",
    # Haskell
    r"^\s*cabal\s",
    r"^\s*stack\s",
    # Scala
    r"^\s*sbt\s",
    # Clojure
    r"^\s*lein\s",
]

# Patterns for dangerous git commands that checkout PR code in run steps
# These patterns indicate checking out untrusted PR code via git commands
DANGEROUS_GIT_CHECKOUT_PATTERNS = [
    # git fetch origin pull/N/head followed by git checkout
    r"git\s+fetch\s+.*pull/.*/(head|merge)",
    # git checkout of a PR ref
    r"git\s+checkout\s+.*pull/",
    # gh pr checkout
    r"gh\s+pr\s+checkout",
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

# Patterns for label checking inside github-script steps
# These indicate the script is inspecting PR labels
SCRIPT_LABEL_CHECK_PATTERNS = [
    r"\.labels",
    r"labels\.includes\b",
    r"labels\.map\b",
    r"labels\.find\b",
    r"labels\.some\b",
    r"labels\.filter\b",
]

# Patterns for script failure/halt that confirm gating behavior
# Without these, a label check might just be informational
SCRIPT_FAIL_PATTERNS = [
    r"core\.setFailed\b",
    r"process\.exit\b",
    r"throw\s+new\s+Error",
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

# Patterns for actor-gating (only specific actor can trigger)
# When a workflow requires the actor to be a specific bot or user, external attackers cannot trigger it
ACTOR_GATING_PATTERNS = [
    r"github\.actor\s*==\s*['\"][^'\"]+\[bot\]['\"]",  # github.actor == 'dependabot[bot]'
    r"github\.actor\s*==\s*['\"]dependabot\[bot\]['\"]",
    r"github\.actor\s*==\s*['\"]renovate\[bot\]['\"]",
    r"github\.actor\s*==\s*['\"]github-actions\[bot\]['\"]",
    # sender.login checks (equivalent to github.actor for PR events)
    r"github\.event\.sender\.login\s*==\s*['\"][^'\"]+['\"]",
]

# Patterns for merged-PR gating (only runs after PR is merged/reviewed)
# When a workflow only runs on merged PRs, the maintainer has already reviewed the code
MERGED_PR_PATTERNS = [
    r"github\.event\.pull_request\.merged\s*==\s*true",
    r"github\.event\.pull_request\.merged\s*!=\s*false",
]

# Patterns for workflow_run events that checkout PR code
# workflow_run can be triggered by PRs and runs with base repo privileges
WORKFLOW_RUN_DANGEROUS_REF_PATTERNS = [
    r"github\.event\.workflow_run\.head_commit\.id",
    r"github\.event\.workflow_run\.head_sha",
    r"github\.event\.workflow_run\.head_branch",
    r"github\.event\.workflow_run\.pull_requests\[.*\]\.head\.(ref|sha)",
]

# Git checkout patterns specific to workflow_run
# These indicate checking out the triggering workflow's commit
WORKFLOW_RUN_GIT_CHECKOUT_PATTERNS = [
    r"git\s+checkout\s+.*github\.event\.workflow_run\.head_commit",
    r"git\s+checkout\s+.*github\.event\.workflow_run\.head_sha",
]

# Context variables for pull_request_target that can be injected directly into run blocks
# These are attacker-controlled values that should NOT be interpolated in shell commands
# NOTE: github.event.pull_request.head.repo.full_name and .name are NOT included here
# because GitHub constrains repo/owner names to alphanumeric, hyphens, underscores, and dots
# which cannot be used for shell injection attacks
PR_TARGET_INJECTABLE_CONTEXTS = [
    r"github\.head_ref",
    r"github\.event\.pull_request\.head\.ref",
    r"github\.event\.pull_request\.head\.label",
    r"github\.event\.pull_request\.title",
    r"github\.event\.pull_request\.body",
    r"github\.event\.comment\.body",
    r"github\.event\.review\.body",
    r"github\.event\.issue\.title",
    r"github\.event\.issue\.body",
]

# Context variables for workflow_run that can be injected directly into run blocks
# These are attacker-controlled values from the triggering workflow
# NOTE: head_repository.full_name and .name are NOT included here because GitHub
# constrains repo/owner names to alphanumeric, hyphens, underscores, and dots
WORKFLOW_RUN_INJECTABLE_CONTEXTS = [
    r"github\.event\.workflow_run\.head_branch",
    r"github\.event\.workflow_run\.head_repository\.default_branch",
    r"github\.event\.workflow_run\.head_commit\.message",
    r"github\.event\.workflow_run\.head_commit\.author\.name",
    r"github\.event\.workflow_run\.head_commit\.author\.email",
    r"github\.event\.workflow_run\.display_title",
    r"github\.event\.workflow_run\.pull_requests\[\d*\]\.head\.ref",
]

# Context variables for issues trigger that can be injected directly into run blocks
# These are attacker-controlled values - anyone can create an issue with malicious content
# NOTE: .user.login is NOT included because GitHub usernames are constrained to
# alphanumeric characters and hyphens [a-zA-Z0-9-], which cannot be used for shell injection.
# .user.name IS included because display names are free-form text.
ISSUES_INJECTABLE_CONTEXTS = [
    r"github\.event\.issue\.title",
    r"github\.event\.issue\.body",
    r"github\.event\.issue\.user\.name",
]

# Context variables for issue_comment trigger that can be injected directly into run blocks
# These are attacker-controlled - anyone who can comment can inject content
# NOTE: .user.login is NOT included (see ISSUES_INJECTABLE_CONTEXTS note above)
ISSUE_COMMENT_INJECTABLE_CONTEXTS = [
    r"github\.event\.comment\.body",
    r"github\.event\.comment\.user\.name",
    r"github\.event\.issue\.title",
    r"github\.event\.issue\.body",
]

# Context variables for discussion/discussion_comment triggers
# These are attacker-controlled - anyone who can participate in discussions can inject content
# NOTE: .user.login is NOT included (see ISSUES_INJECTABLE_CONTEXTS note above)
DISCUSSION_INJECTABLE_CONTEXTS = [
    r"github\.event\.discussion\.title",
    r"github\.event\.discussion\.body",
    r"github\.event\.discussion\.user\.name",
    r"github\.event\.comment\.body",
    r"github\.event\.comment\.user\.name",
]

# Patterns for artifact download that retrieves artifacts from the triggering workflow
# When combined with workflow_run, this allows attacker-controlled artifact content
WORKFLOW_RUN_ARTIFACT_DOWNLOAD_PATTERNS = [
    r"github\.event\.workflow_run\.id",  # run-id from workflow_run
]

# Patterns for issue_comment/workflow_dispatch checkout of PR code
# These patterns indicate dynamic checkout of PR code based on issue/PR number
# When triggered by issue_comment, an attacker's PR code gets executed with elevated privileges
DISPATCH_PR_CHECKOUT_PATTERNS = [
    # refs/pull/N/head patterns with dynamic PR number from issue
    r"refs/pull/\$\{\{.*github\.event\.issue\.number.*\}\}/(head|merge)",
    r"refs/pull/\$\{\{.*needs\.[^}]+\.outputs\.[^}]*(pr-number|pr_number|number)[^}]*\}\}/(head|merge)",
    # Job outputs that construct PR refs
    r"refs/pull/\$\{\{.*env\.[^}]*(PR_NUMBER|pr_number)[^}]*\}\}/(head|merge)",
]

# Patterns indicating a job is referencing PR context from issue_comment
# These indicate the workflow is trying to act on a PR from an issue comment
ISSUE_COMMENT_PR_PATTERNS = [
    r"github\.event\.issue\.pull_request",  # Check if issue is a PR
]

# Patterns for workflow_run repository validation in run blocks
# When a workflow_run job validates that the triggering repo matches the current repo,
# it rejects fork triggers (equivalent to same_repo gating)
WORKFLOW_RUN_REPO_VALIDATION_PATTERNS = [
    r"github\.event\.workflow_run\.head_repository\.full_name",
]

# Patterns for reading file content into shell variables or commands
# These patterns indicate artifact content being used unsafely in shell commands
ARTIFACT_READ_PATTERNS = [
    r"\$\(<[^)]+\)",  # $(<file) - bash file read
    r"\$\(cat\s+[^)]+\)",  # $(cat file) - subshell cat
    r"`cat\s+[^`]+`",  # `cat file` - backtick subshell
    r"cat\s+\S+\s*\|",  # cat file | - piped cat
    r"source\s+\S+",  # source file - sourcing a file (require path)
    r"^\s*\.\s+[\./$]",  # . file - dot sourcing at line start with path (./file, /file, $var)
    r"[;&|]\s*\.\s+[\./$]",  # . file - dot sourcing after separator with path
]

# Patterns for SAFE artifact data extraction
# When data is extracted via jq and used with proper quoting, command injection is prevented
SAFE_ARTIFACT_EXTRACTION_PATTERNS = [
    r"\$\(jq\s+(-r\s+)?['\"]",  # $(jq -r '.field' file) or $(jq '.field' file)
]

# Patterns indicating ref comes from safe sources (manual dispatch input)
# inputs.* comes from workflow_dispatch which requires repo write access to trigger
SAFE_WORKFLOW_DISPATCH_REF_PATTERNS = [
    r"inputs\.[a-zA-Z_][a-zA-Z0-9_]*",  # ${{ inputs.tag }} - from workflow_dispatch
]
