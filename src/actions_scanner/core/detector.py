"""PwnRequest vulnerability detector for GitHub Actions workflows."""

import re
from pathlib import Path

import yaml

from .models import ScanResult, VulnerableJob
from .patterns import (
    AUTHORIZATION_JOB_PATTERNS,
    DANGEROUS_COMMANDS,
    DANGEROUS_REPO_PATTERNS,
    DANGEROUS_REF_PATTERNS,
    PERMISSION_CHECK_PATTERNS,
    PERMISSION_OUTPUT_PATTERNS,
    SAME_REPO_PATTERNS,
    WRITE_ACCESS_PATTERNS,
)


class PwnRequestDetector:
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
            # Invalid YAML - skip silently (common in the wild)
            return []

        if not isinstance(workflow, dict):
            return []

        # Check for pull_request_target trigger
        if not self._has_pull_request_target_trigger(workflow):
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

            # Find dangerous checkout in this job
            checkout_result = self._find_dangerous_checkout(steps)
            if not checkout_result:
                continue

            checkout_index, checkout_ref = checkout_result

            # Find dangerous exec after the checkout in this job
            exec_result = self._find_dangerous_exec(steps, checkout_index)
            if not exec_result:
                continue

            exec_index, exec_type, exec_value = exec_result

            # Found a potential vulnerability - check what protection it has
            checkout_line = self._get_line_number(content, job_name, checkout_index)
            exec_line = self._get_line_number(content, job_name, exec_index)
            has_auth = self._has_authorization_job(workflow, job_name)
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
                    has_authorization=has_auth,
                    protection=protection,
                    protection_detail=protection_detail,
                )
            )

        return vulnerabilities

    def scan_directory(self, directory: Path) -> ScanResult:
        """Scan a directory for vulnerable workflows."""
        result = ScanResult()

        for yaml_file in directory.rglob("*"):
            if not yaml_file.is_file():
                continue
            if yaml_file.suffix not in (".yml", ".yaml"):
                continue
            if ".git" in yaml_file.parts:
                continue
            try:
                vulns = self.analyze_workflow(yaml_file)
                result.vulnerabilities.extend(vulns)
                result.files_scanned += 1
            except Exception as e:
                result.errors.append(f"{yaml_file}: {e}")

        return result

    def _has_pull_request_target_trigger(self, workflow: dict) -> bool:
        """Check if workflow has pull_request_target trigger."""
        on_section = workflow.get("on") or workflow.get(True)  # 'on' parses as True in YAML
        if on_section is None:
            return False

        if isinstance(on_section, (dict, list)):
            return "pull_request_target" in on_section
        if isinstance(on_section, str):
            return on_section == "pull_request_target"

        return False

    def _is_dangerous_ref(self, ref_value: str) -> bool:
        """Check if a ref value contains dangerous PR references."""
        if not ref_value:
            return False
        ref_str = str(ref_value)
        return any(re.search(pattern, ref_str) for pattern in DANGEROUS_REF_PATTERNS)

    def _is_dangerous_command(self, cmd: str) -> bool:
        """Check if a command is a dangerous build command."""
        if not cmd:
            return False
        # Handle multi-line commands (YAML block scalars)
        cmd_str = str(cmd).strip()
        # Check first line or any line for dangerous patterns
        lines = cmd_str.split("\n")
        for line in lines:
            line = line.strip()
            if any(re.search(pattern, line, re.IGNORECASE) for pattern in DANGEROUS_COMMANDS):
                return True
        return False

    def _is_local_action(self, uses_value: str) -> bool:
        """Check if a uses value is a local action (starts with ./)."""
        if not uses_value:
            return False
        return str(uses_value).strip().startswith("./")

    def _find_dangerous_checkout(self, steps: list) -> tuple[int, str] | None:
        """Find a dangerous checkout step in a list of steps.

        Returns (step_index, ref_value) or None.
        """
        for i, step in enumerate(steps):
            if not isinstance(step, dict):
                continue

            uses = step.get("uses", "")
            if not uses or "actions/checkout" not in str(uses):
                continue

            with_block = step.get("with", {})
            if not isinstance(with_block, dict):
                continue

            ref = with_block.get("ref", "")
            if self._is_dangerous_ref(ref):
                return (i, str(ref))

            repo_value = with_block.get("repository", "")
            if repo_value:
                repo_str = str(repo_value)
                if any(re.search(pattern, repo_str) for pattern in DANGEROUS_REPO_PATTERNS):
                    return (i, f"repository={repo_str}")

        return None

    def _find_dangerous_exec(
        self, steps: list, checkout_index: int
    ) -> tuple[int, str, str] | None:
        """Find a dangerous exec step after the checkout.

        Returns (step_index, exec_type, exec_value) or None.
        """
        for i, step in enumerate(steps):
            if i <= checkout_index:
                # Only check steps after the checkout
                continue

            if not isinstance(step, dict):
                continue

            # Check for local action
            uses = step.get("uses", "")
            if self._is_local_action(uses):
                return (i, "local_action", str(uses))

            # Check for dangerous run command
            run = step.get("run", "")
            if self._is_dangerous_command(run):
                # Get first dangerous line for reporting
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

        # Check if any dependency looks like an authorization job
        for need in needs:
            need_lower = str(need).lower()
            if any(pattern in need_lower for pattern in AUTHORIZATION_JOB_PATTERNS):
                return True

        return False

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
            # Check if there's a negation right before (with possible whitespace)
            # Negated contains = skip if label present = NOT a gate
            # Non-negated contains = require label = IS a gate
            return not (
                re.search(r"!\s*$", before_contains)
                or re.search(r"\bnot\s*$", before_contains, re.IGNORECASE)
            )

        return False

    def _check_job_label_gating(self, job: dict, workflow: dict) -> tuple[bool, str]:
        """Check if a job or its dependencies require a specific label to run.

        Returns (is_label_gated, description).
        """
        jobs = workflow.get("jobs", {})

        # Check this job's if condition
        if_condition = str(job.get("if", ""))
        if self._is_positive_label_gate(if_condition):
            return True, f"Job requires label: {if_condition[:80]}"

        # Check dependency jobs' if conditions
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
        """Check if a job only runs for PRs from the same repo (not forks).

        Returns (is_same_repo_gated, description).
        """
        jobs = workflow.get("jobs", {})

        # Check this job's if condition
        if_condition = str(job.get("if", ""))
        for pattern in SAME_REPO_PATTERNS:
            if re.search(pattern, if_condition, re.IGNORECASE):
                return True, f"Job only runs for same-repo PRs: {if_condition[:80]}"

        # Check dependency jobs' if conditions
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

        Returns (is_permission_gated, description).
        """
        jobs = workflow.get("jobs", {})
        if_condition = str(job.get("if", ""))

        # Extract job names referenced in permission output patterns
        referenced_jobs = set()
        for pattern in PERMISSION_OUTPUT_PATTERNS:
            for match in re.finditer(pattern, if_condition):
                if match.groups():
                    referenced_jobs.add(match.group(1))

        if not referenced_jobs:
            return False, ""

        # Check each referenced job for actual permission verification
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

                # Look for github-script actions that check permissions
                uses = step.get("uses", "")
                if "github-script" not in str(uses):
                    continue

                with_block = step.get("with", {})
                script = str(with_block.get("script", ""))

                # Check if script calls getCollaboratorPermissionLevel
                has_perm_check = any(
                    re.search(pattern, script) for pattern in PERMISSION_CHECK_PATTERNS
                )

                # Check if script verifies write/admin/maintain access
                has_write_check = any(
                    re.search(pattern, script, re.IGNORECASE) for pattern in WRITE_ACCESS_PATTERNS
                )

                if has_perm_check and has_write_check:
                    return (
                        True,
                        f"Job '{ref_job_name}' verifies collaborator has write/admin/maintain access",
                    )

        return False, ""

    def _analyze_protection(self, workflow: dict, job_name: str) -> tuple[str, str]:
        """Determine what protection (if any) a vulnerable job has.

        Returns (protection_type, detail).

        Protection types:
        - "none": Fully exploitable by any PR author
        - "label": Requires maintainer to add label (social engineering vector)
        - "permission": Requires PR author to have write/admin/maintain access (not exploitable)
        - "same_repo": Only runs for PRs from same repo, not forks (not exploitable by external)
        """
        jobs = workflow.get("jobs", {})
        job = jobs.get(job_name, {})

        # Check for permission gating (strongest protection - not exploitable)
        is_perm_gated, perm_reason = self._check_job_permission_gating(job, workflow)
        if is_perm_gated:
            return "permission", perm_reason

        # Check for both same-repo and label gating
        is_same_repo, same_repo_reason = self._check_job_same_repo_gating(job, workflow)
        is_label_gated, label_reason = self._check_job_label_gating(job, workflow)

        # If both same-repo AND label checks exist in an OR condition,
        # the protection is only as strong as the weaker one (label-gated)
        if is_same_repo and is_label_gated:
            # Check if the if condition contains OR (||)
            if_condition = str(job.get("if", ""))
            # Also check dependency jobs' if conditions
            needs = job.get("needs", [])
            if isinstance(needs, str):
                needs = [needs]
            for need in needs:
                dep_job = jobs.get(need, {})
                if isinstance(dep_job, dict):
                    if_condition += " " + str(dep_job.get("if", ""))

            if "||" in if_condition:
                # OR condition - external attackers can use label-gated path
                return "label", f"OR condition: {label_reason}"

        # If only same-repo (no label alternative), it's truly same-repo-only
        if is_same_repo:
            return "same_repo", same_repo_reason

        # If only label-gated
        if is_label_gated:
            return "label", label_reason

        # No protection found - fully exploitable
        return "none", ""

    def _get_line_number(self, workflow_content: str, job_name: str, step_index: int) -> int:
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

            # Look for job start
            if re.match(rf"^\s*{re.escape(job_name)}:\s*$", line) or re.match(
                rf"^\s*{re.escape(job_name)}:\s*#", line
            ):
                in_job = True
                continue

            if in_job:
                # Check if we've left the job (another job at same indentation)
                if (
                    re.match(r"^\s{2}[a-zA-Z_-]+:\s*$", line)
                    and not stripped.startswith("-")
                    and "steps:" not in stripped
                    and ":" in stripped
                ):
                    # Might be a new job
                    indent = len(line) - len(line.lstrip())
                    if indent <= 2:
                        break

                if "steps:" in stripped:
                    in_steps = True
                    continue

                # Count steps (lines starting with '- ')
                if in_steps and re.match(r"^\s*-\s+", line):
                    step_count += 1
                    if step_count == step_index:
                        return i

        return 0  # Fallback


# Convenience functions for standalone usage
def analyze_workflow(workflow_path: Path) -> list[VulnerableJob]:
    """Analyze a workflow file for PwnRequest vulnerabilities."""
    detector = PwnRequestDetector()
    return detector.analyze_workflow(workflow_path)


def scan_directory(directory: Path) -> ScanResult:
    """Scan a directory for vulnerable workflows."""
    detector = PwnRequestDetector()
    return detector.scan_directory(directory)
