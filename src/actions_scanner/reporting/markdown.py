"""Markdown report generation for vulnerability findings."""

from collections import defaultdict
from datetime import datetime
from pathlib import Path

from actions_scanner.core.models import VulnerableJob
from actions_scanner.utils.path import repo_display_name


def generate_markdown_report(
    vulnerabilities: list[VulnerableJob],
    output_path: Path,
    title: str = "PwnRequest Vulnerability Scan Results",
    include_protected: bool = False,
) -> Path:
    """Generate a Markdown report of vulnerable workflows.

    Args:
        vulnerabilities: List of VulnerableJob findings
        output_path: Path to write Markdown file
        title: Report title
        include_protected: Include permission-gated findings

    Returns:
        Path to the generated Markdown file
    """
    # Group by protection level
    by_protection: dict[str, list[VulnerableJob]] = defaultdict(list)
    for v in vulnerabilities:
        by_protection[v.protection].append(v)

    # Separate exploitable from protected
    exploitable = by_protection.get("none", []) + by_protection.get("label", [])
    protected = by_protection.get("permission", []) + by_protection.get("same_repo", [])

    with output_path.open("w", encoding="utf-8") as f:
        # Header
        f.write(f"# {title}\n\n")
        f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        # Summary
        f.write("## Summary\n\n")
        f.write(f"- **Total findings:** {len(vulnerabilities)}\n")
        f.write(f"- **Exploitable (no protection):** {len(by_protection.get('none', []))}\n")
        f.write(f"- **Label-gated (social eng.):** {len(by_protection.get('label', []))}\n")
        f.write(f"- **Permission-gated (filtered):** {len(by_protection.get('permission', []))}\n")
        f.write(f"- **Same-repo only (filtered):** {len(by_protection.get('same_repo', []))}\n")
        f.write("\n")

        if not vulnerabilities:
            f.write("No vulnerabilities found.\n")
            return output_path

        # Exploitable section (critical)
        if exploitable:
            f.write("---\n\n")
            f.write("## EXPLOITABLE VULNERABILITIES\n\n")
            f.write("These workflows can be exploited by submitting a malicious pull request.\n\n")

            # Group by repo
            by_repo: dict[str, list[VulnerableJob]] = defaultdict(list)
            for v in exploitable:
                # Extract repo from path
                path_str = str(v.workflow_path)
                repo_name = _extract_repo_name(path_str)
                by_repo[repo_name].append(v)

            for repo_name in sorted(by_repo.keys()):
                repo_vulns = by_repo[repo_name]
                f.write(f"### {repo_name}\n\n")

                # Group by workflow file
                by_workflow: dict[str, list[VulnerableJob]] = defaultdict(list)
                for v in repo_vulns:
                    by_workflow[str(v.workflow_path)].append(v)

                for workflow_path in sorted(by_workflow.keys()):
                    workflow_vulns = by_workflow[workflow_path]
                    rel_path = _get_relative_workflow_path(workflow_path)
                    f.write(f"**Workflow:** `{rel_path}`\n\n")

                    for v in workflow_vulns:
                        protection_label = (
                            "EXPLOITABLE" if v.protection == "none" else "LABEL-GATED"
                        )
                        f.write(f"- **[{protection_label}]** Job: `{v.job_name}`\n")
                        if v.branch:
                            f.write(f"  - Branch: `{v.branch}`\n")
                        f.write(f"  - Checkout: Line {v.checkout_line} - `{v.checkout_ref}`\n")
                        f.write(
                            f"  - Execution: Line {v.exec_line} - {v.exec_type}: `{v.exec_value}`\n"
                        )
                        if v.protection_detail:
                            f.write(f"  - Protection: {v.protection_detail}\n")
                        f.write("\n")

                f.write("---\n\n")

        # Protected section (if requested)
        if include_protected and protected:
            f.write("## PROTECTED VULNERABILITIES\n\n")
            f.write("These workflows have protection mechanisms that prevent exploitation.\n\n")

            by_repo: dict[str, list[VulnerableJob]] = defaultdict(list)
            for v in protected:
                path_str = str(v.workflow_path)
                repo_name = _extract_repo_name(path_str)
                by_repo[repo_name].append(v)

            for repo_name in sorted(by_repo.keys()):
                repo_vulns = by_repo[repo_name]
                f.write(f"### {repo_name}\n\n")

                for v in repo_vulns:
                    protection_label = (
                        "PERMISSION-GATED" if v.protection == "permission" else "SAME-REPO-ONLY"
                    )
                    f.write(f"- **[{protection_label}]** Job: `{v.job_name}`\n")
                    f.write(f"  - {v.protection_detail}\n")
                    f.write("\n")

            f.write("---\n\n")

    return output_path


def _extract_repo_name(path_str: str) -> str:
    """Extract repository name from workflow path."""
    return repo_display_name(path_str)


def _get_relative_workflow_path(path_str: str) -> str:
    """Get workflow path relative to .github directory."""
    if ".github" in path_str:
        idx = path_str.find(".github")
        return path_str[idx:]
    return path_str


def generate_summary_report(
    vulnerabilities: list[VulnerableJob],
    output_path: Path,
) -> Path:
    """Generate a concise summary report.

    Args:
        vulnerabilities: List of VulnerableJob findings
        output_path: Path to write Markdown file

    Returns:
        Path to the generated file
    """
    by_protection: dict[str, list[VulnerableJob]] = defaultdict(list)
    for v in vulnerabilities:
        by_protection[v.protection].append(v)

    unique_repos = set()
    for v in vulnerabilities:
        repo_name = _extract_repo_name(str(v.workflow_path))
        unique_repos.add(repo_name)

    with output_path.open("w", encoding="utf-8") as f:
        f.write("# Vulnerability Summary\n\n")
        f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        f.write("## Statistics\n\n")
        f.write("| Category | Count |\n")
        f.write("|----------|-------|\n")
        f.write(f"| Unique Repositories | {len(unique_repos)} |\n")
        f.write(f"| Total Findings | {len(vulnerabilities)} |\n")
        f.write(f"| Exploitable (none) | {len(by_protection.get('none', []))} |\n")
        f.write(f"| Label-gated | {len(by_protection.get('label', []))} |\n")
        f.write(f"| Permission-gated | {len(by_protection.get('permission', []))} |\n")
        f.write(f"| Same-repo only | {len(by_protection.get('same_repo', []))} |\n")
        f.write("\n")

        # List exploitable repos
        exploitable = by_protection.get("none", []) + by_protection.get("label", [])
        if exploitable:
            exploitable_repos = set()
            for v in exploitable:
                exploitable_repos.add(_extract_repo_name(str(v.workflow_path)))

            f.write("## Exploitable Repositories\n\n")
            for repo in sorted(exploitable_repos):
                f.write(f"- {repo}\n")

    return output_path
