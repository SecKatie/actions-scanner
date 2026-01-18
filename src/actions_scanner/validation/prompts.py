"""Prompt templates for AI-assisted validation."""

# Default validation prompt template
# Placeholders: {org}, {repo}, {workflow_list}
DEFAULT_VALIDATION_PROMPT = '''You are a security researcher analyzing GitHub workflows for PwnRequest vulnerabilities in the {org}/{repo} repository.

IMPORTANT: You MUST read and analyze each of the following workflow files. These files have already been flagged by an automated scanner as potentially vulnerable. Your job is to confirm the vulnerability and document how to exploit it.

WORKFLOW FILES TO READ AND ANALYZE (paths relative to current directory):
{workflow_list}

STEP 1: Read each workflow file listed above using the read tool.

STEP 2: For each workflow, check for PwnRequest vulnerability pattern:
- Uses pull_request_target trigger
- Checks out untrusted PR code (look for: github.event.pull_request.head.ref, github.event.pull_request.head.sha, or checkout of PR head repo)
- Executes that code (runs scripts, builds, tests, docker commands, etc.)

STEP 3: Check for existing analysis files (confirmed_vulnerable.txt, confirmed_weakness.txt, or not_vulnerable.txt). If one exists but your analysis disagrees with it, DELETE the old file before creating the correct one.

Create ONE of these files:

OPTION A - confirmed_vulnerable.txt:
Create this if workflows can be exploited WITHOUT any approval gates.

OPTION B - confirmed_weakness.txt:
Create this if workflows require approval (labels, maintainer review) but are still exploitable once approved.

OPTION C - not_vulnerable.txt:
Create this if the automated scanner flagged a FALSE POSITIVE. Document why the workflow is NOT actually vulnerable.

For EACH workflow, document:

## Workflow: [full path]

1. **Vulnerability Pattern Found**:
   - Line X: pull_request_target trigger
   - Line Y: Checkout of untrusted code
   - Line Z: Execution of untrusted code

2. **Secrets/Permissions at Risk**:
   - List ALL secrets referenced in the workflow
   - Note any write permissions

3. **Exploitation Steps**:
   - Fork the repository
   - Create a PR with malicious code in [specific file]
   - The workflow will execute [specific malicious action]
   - Secrets can be exfiltrated via [method]

4. **Impact**: What an attacker could achieve

---

For NOT VULNERABLE (false positive) workflows, document:

## Workflow: [full path]

1. **Why Scanner Flagged It**: What pattern triggered the scanner
2. **Why It's Safe**: Explain the protection mechanism the scanner missed
   - Does checkout happen but no code execution follows?
   - Is execution only of trusted code (not from checkout)?
   - Is there a protection the scanner didn't detect?
3. **Scanner Improvement**: How could the scanner be improved to avoid this false positive?

---

CRITICAL: You MUST create exactly ONE of these files: confirmed_vulnerable.txt, confirmed_weakness.txt, or not_vulnerable.txt. Every flagged workflow must be documented in whichever file you create.'''


def build_validation_prompt(
    org: str,
    repo: str,
    workflow_paths: list[str],
    custom_template: str | None = None,
) -> str:
    """Build a validation prompt for the AI agent.

    Args:
        org: Repository organization
        repo: Repository name
        workflow_paths: List of workflow file paths relative to working dir
        custom_template: Optional custom prompt template

    Returns:
        Formatted prompt string
    """
    template = custom_template or DEFAULT_VALIDATION_PROMPT

    # Format workflow list as bullet points
    workflow_list = "\n".join(f"  - {path}" for path in workflow_paths)

    return template.format(
        org=org,
        repo=repo,
        workflow_list=workflow_list,
    )


# Shorter prompt for quick validation
QUICK_VALIDATION_PROMPT = '''Analyze these GitHub workflows in {org}/{repo} for PwnRequest vulnerabilities:

{workflow_list}

Check for the pattern: pull_request_target + untrusted checkout + code execution.

Create one of:
- confirmed_vulnerable.txt (exploitable without approval)
- confirmed_weakness.txt (exploitable with approval)
- not_vulnerable.txt (false positive)

Document the vulnerability or why it's safe.'''


def build_quick_prompt(
    org: str,
    repo: str,
    workflow_paths: list[str],
) -> str:
    """Build a shorter validation prompt.

    Args:
        org: Repository organization
        repo: Repository name
        workflow_paths: List of workflow file paths

    Returns:
        Formatted prompt string
    """
    workflow_list = "\n".join(f"- {path}" for path in workflow_paths)
    return QUICK_VALIDATION_PROMPT.format(
        org=org,
        repo=repo,
        workflow_list=workflow_list,
    )
