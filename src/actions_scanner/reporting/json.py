"""JSON report generation for vulnerability findings."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from actions_scanner.core.models import VulnerableJob
from actions_scanner.utils.path import (
    extract_org_repo_branch_from_path,
    extract_org_repo_from_path,
    repo_display_name,
)


def generate_json_report(
    vulnerabilities: list[VulnerableJob],
    output_path: Path,
    include_protected: bool = False,
    pretty: bool = True,
    scan_base_dir: Path | None = None,
    validations: list[dict[str, Any]] | None = None,
) -> Path:
    """Generate a JSON report of vulnerable workflows.

    Args:
        vulnerabilities: List of VulnerableJob findings
        output_path: Path to write JSON file
        include_protected: Include permission-gated findings
        pretty: Format JSON with indentation

    Returns:
        Path to the generated JSON file
    """
    # Filter if not including protected
    if not include_protected:
        vulnerabilities = [v for v in vulnerabilities if v.is_exploitable()]

    # Build report structure
    validation_index = _build_validation_index(validations or [])
    metadata: dict[str, Any] = {
        "generated_at": datetime.now().isoformat(),
        "total_findings": len(vulnerabilities),
        "include_protected": include_protected,
    }
    if scan_base_dir:
        metadata["scan_base_dir"] = str(scan_base_dir)

    report: dict[str, Any] = {
        "metadata": metadata,
        "summary": {
            "by_protection": _count_by_protection(vulnerabilities),
            "unique_repos": len(_get_unique_repos(vulnerabilities)),
        },
        "vulnerabilities": [
            _vuln_to_dict(v, validation_index.get(_vuln_key(v))) for v in vulnerabilities
        ],
    }

    if validations:
        report["validations"] = validations

    with output_path.open("w", encoding="utf-8") as f:
        if pretty:
            json.dump(report, f, indent=2)
        else:
            json.dump(report, f)

    return output_path


def generate_exploitable_json(
    vulnerabilities: list[VulnerableJob],
    output_path: Path,
) -> Path:
    """Generate a JSON file with only exploitable vulnerabilities.

    This format is optimized for downstream tools that need to
    process exploitable workflows.

    Args:
        vulnerabilities: List of VulnerableJob findings
        output_path: Path to write JSON file

    Returns:
        Path to the generated JSON file
    """
    exploitable = [v for v in vulnerabilities if v.is_exploitable()]

    # Group by repo
    by_repo: dict[str, list[dict[str, Any]]] = {}
    for v in exploitable:
        repo_name = _extract_repo_name(str(v.workflow_path))
        if repo_name not in by_repo:
            by_repo[repo_name] = []
        by_repo[repo_name].append(_vuln_to_dict(v))

    output = {
        "generated_at": datetime.now().isoformat(),
        "total_exploitable": len(exploitable),
        "repositories": by_repo,
    }

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    return output_path


def _vuln_key(v: VulnerableJob) -> tuple[str, str, str]:
    """Build a repo key for validation matching."""
    org, repo = _extract_org_repo(str(v.workflow_path))
    branch = v.branch or ""
    return org, repo, branch


def _vuln_to_dict(v: VulnerableJob, validation: dict[str, Any] | None = None) -> dict[str, Any]:
    """Convert VulnerableJob to dictionary.

    Note: This preserves raw values including multiline content,
    which JSON handles natively via escaping.
    """
    path_str = str(v.workflow_path)
    org, repo = _extract_org_repo(path_str)

    record = {
        "org": org,
        "repo": repo,
        "workflow_path": path_str,
        "job_name": v.job_name,
        "branch": v.branch,
        "checkout": {
            "line": v.checkout_line,
            "ref": v.checkout_ref,  # Preserved as-is, including multiline
        },
        "execution": {
            "line": v.exec_line,
            "type": v.exec_type,
            "value": v.exec_value,  # Preserved as-is, including multiline
        },
        "protection": {
            "level": v.protection,
            "detail": v.protection_detail,  # Preserved as-is
        },
        "has_authorization_gate": v.has_authorization,
        "is_exploitable": v.is_exploitable(),
    }

    if validation:
        record["issue_type"] = validation.get("issue_type", "")
        record["cvss"] = validation.get("cvss")
        record["cwe"] = validation.get("cwe", "")
        record["validation"] = {
            "result": validation.get("result", ""),
            "confirmation_file": validation.get("confirmation_file"),
            "summary": validation.get("summary", ""),
            "confidence": validation.get("confidence", ""),
        }

    return record


def _count_by_protection(vulnerabilities: list[VulnerableJob]) -> dict[str, int]:
    """Count vulnerabilities by protection level."""
    counts: dict[str, int] = {
        "none": 0,
        "label": 0,
        "permission": 0,
        "same_repo": 0,
    }
    for v in vulnerabilities:
        counts[v.protection] = counts.get(v.protection, 0) + 1
    return counts


def _get_unique_repos(vulnerabilities: list[VulnerableJob]) -> set[str]:
    """Get set of unique repository names."""
    repos = set()
    for v in vulnerabilities:
        repos.add(_extract_repo_name(str(v.workflow_path)))
    return repos


def _extract_repo_name(path_str: str) -> str:
    """Extract repository name from workflow path."""
    return repo_display_name(path_str)


def _extract_org_repo(path_str: str) -> tuple[str, str]:
    """Extract organization and repository name from workflow path."""
    org, repo = extract_org_repo_from_path(path_str)
    return org, repo or "unknown"


def load_json_report(json_path: Path) -> dict[str, Any]:
    """Load a JSON vulnerability report.

    Args:
        json_path: Path to JSON file

    Returns:
        Report dictionary
    """
    with json_path.open("r", encoding="utf-8") as f:
        return json.load(f)


def read_vulnerabilities_json(json_path: Path) -> list[dict[str, Any]]:
    """Read vulnerability records from a JSON report.

    Supports:
    - Standard report format with "vulnerabilities" list
    - Exploitable JSON format with "repositories" dict
    - Raw list of vulnerability dicts
    """
    data = load_json_report(json_path)
    if isinstance(data, list):
        records = [dict(v) for v in data]
        return _normalize_json_records(records)

    if isinstance(data, dict):
        vulns = data.get("vulnerabilities")
        if isinstance(vulns, list):
            records = [dict(v) for v in vulns]
            return _normalize_json_records(records)

        repositories = data.get("repositories")
        if isinstance(repositories, dict):
            results: list[dict[str, Any]] = []
            for repo_vulns in repositories.values():
                if isinstance(repo_vulns, list):
                    results.extend([dict(v) for v in repo_vulns])
            return _normalize_json_records(results)

    return []


def _normalize_json_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Ensure org/repo fields are populated for validation."""
    normalized = []
    for record in records:
        org = record.get("org", "") or ""
        repo = record.get("repo", "") or ""
        branch = record.get("branch", "") or ""
        if (not org or not repo) and record.get("workflow_path"):
            inferred_org, inferred_repo = extract_org_repo_from_path(
                str(record.get("workflow_path", ""))
            )
            if not org:
                org = inferred_org
            if not repo:
                repo = inferred_repo
        if not branch and record.get("workflow_path"):
            _org, _repo, inferred_branch = extract_org_repo_branch_from_path(
                str(record.get("workflow_path", ""))
            )
            if inferred_branch:
                branch = inferred_branch
        record["org"] = org
        record["repo"] = repo
        record["branch"] = branch
        normalized.append(record)
    return normalized


def _build_validation_index(
    validations: list[dict[str, Any]],
) -> dict[tuple[str, str, str], dict[str, Any]]:
    """Build lookup from validation records."""
    index: dict[tuple[str, str, str], dict[str, Any]] = {}
    for v in validations:
        org = v.get("org", "") or ""
        repo = v.get("repo", "") or ""
        branch = v.get("branch", "") or ""
        key = (org, repo, branch)
        index[key] = v
    return index
