"""CSV report generation for vulnerability findings."""

import csv
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from actions_scanner.core.models import VulnerableJob
from actions_scanner.utils.path import extract_org_repo_from_path


def _sanitize_value(value: Any) -> str:
    """Sanitize a value for CSV output.

    Replaces newlines and multiple whitespace with single spaces to prevent
    multiline values that break CSV parsing in some tools.

    Args:
        value: Value to sanitize

    Returns:
        Sanitized string value
    """
    if value is None:
        return ""
    text = str(value)
    # Replace newlines and carriage returns with spaces
    text = text.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    # Collapse multiple whitespace into single space
    text = re.sub(r"\s+", " ", text)
    # Strip leading/trailing whitespace
    text = text.strip()
    if text and text[0] in ("=", "+", "-", "@"):
        text = f"'{text}"
    return text


def sanitize_csv_value(value: Any) -> str:
    """Public wrapper for CSV sanitization."""
    return _sanitize_value(value)


def generate_csv_report(
    vulnerabilities: list[VulnerableJob],
    output_path: Path,
    include_protected: bool = False,
) -> Path:
    """Generate a CSV report of vulnerable workflows.

    Args:
        vulnerabilities: List of VulnerableJob findings
        output_path: Path to write CSV file
        include_protected: Include permission-gated findings

    Returns:
        Path to the generated CSV file
    """
    # Filter if not including protected
    if not include_protected:
        vulnerabilities = [v for v in vulnerabilities if v.is_exploitable()]

    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "org",
            "repo",
            "branch",
            "workflow_path",
            "job_name",
            "checkout_line",
            "checkout_ref",
            "exec_line",
            "exec_type",
            "exec_value",
            "protection",
            "protection_detail",
        ])

        for v in sorted(vulnerabilities, key=lambda x: (str(x.workflow_path), x.job_name)):
            org, repo = extract_org_repo_from_path(str(v.workflow_path))

            row = [
                org,
                repo,
                v.branch,
                str(v.workflow_path),
                v.job_name,
                v.checkout_line,
                v.checkout_ref,
                v.exec_line,
                v.exec_type,
                v.exec_value,
                v.protection,
                v.protection_detail,
            ]
            writer.writerow([_sanitize_value(value) for value in row])

    return output_path


def generate_vulnerabilities_csv(
    vulnerabilities: list[VulnerableJob],
    output_path: Path,
    extra_columns: dict[str, Callable[[VulnerableJob], Any]] | None = None,
) -> Path:
    """Generate a comprehensive vulnerabilities CSV for further enrichment.

    Args:
        vulnerabilities: List of VulnerableJob findings
        output_path: Path to write CSV file
        extra_columns: Optional dict of column_name -> callable(vuln) for extra columns

    Returns:
        Path to the generated CSV file
    """
    extra_columns = extra_columns or {}

    base_columns = [
        "org",
        "repo",
        "branch",
        "workflow_path",
        "job_name",
        "checkout_line",
        "checkout_ref",
        "exec_line",
        "exec_type",
        "exec_value",
        "protection",
        "protection_detail",
        "repo_url",
    ]

    columns = base_columns + list(extra_columns.keys())

    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()

        for v in vulnerabilities:
            org, repo = extract_org_repo_from_path(str(v.workflow_path))

            row = {
                "org": org,
                "repo": repo,
                "branch": v.branch,
                "workflow_path": str(v.workflow_path),
                "job_name": v.job_name,
                "checkout_line": v.checkout_line,
                "checkout_ref": _sanitize_value(v.checkout_ref),
                "exec_line": v.exec_line,
                "exec_type": v.exec_type,
                "exec_value": _sanitize_value(v.exec_value),
                "protection": v.protection,
                "protection_detail": _sanitize_value(v.protection_detail),
                "repo_url": f"https://github.com/{org}/{repo}" if org and repo else "",
            }

            # Add extra columns
            for col_name, col_fn in extra_columns.items():
                row[col_name] = col_fn(v)

            writer.writerow({k: _sanitize_value(v) for k, v in row.items()})

    return output_path


def read_vulnerabilities_csv(csv_path: Path) -> list[dict]:
    """Read vulnerabilities from a CSV file.

    Args:
        csv_path: Path to CSV file

    Returns:
        List of vulnerability dictionaries
    """
    vulnerabilities = []
    with csv_path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            vulnerabilities.append(dict(row))
    return vulnerabilities


def append_columns_to_csv(
    input_path: Path,
    output_path: Path,
    new_columns: dict[str, Callable[[dict[str, Any]], Any]],
) -> Path:
    """Append new columns to an existing CSV file.

    Args:
        input_path: Path to input CSV
        output_path: Path to output CSV
        new_columns: Dict of column_name -> callable(row_dict)

    Returns:
        Path to output CSV
    """
    rows = read_vulnerabilities_csv(input_path)

    if not rows:
        return output_path

    fieldnames = list(rows[0].keys()) + list(new_columns.keys())

    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for row in rows:
            for col_name, col_fn in new_columns.items():
                row[col_name] = col_fn(row)
            writer.writerow({k: _sanitize_value(v) for k, v in row.items()})

    return output_path
