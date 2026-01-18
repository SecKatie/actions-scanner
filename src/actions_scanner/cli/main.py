"""Main CLI entry point for actions-scanner."""

import asyncio
import json
import os
import tempfile
from datetime import datetime
from pathlib import Path

import click

from actions_scanner import __version__
from actions_scanner.config import Settings, find_config_file, get_settings
from actions_scanner.utils.console import console, print_banner


@click.group()
@click.option(
    "--config",
    "-c",
    type=click.Path(exists=True, path_type=Path),
    help="Configuration file path",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option("--no-banner", is_flag=True, help="Suppress the banner")
@click.version_option(version=__version__)
@click.pass_context
def cli(ctx: click.Context, config: Path | None, verbose: bool, no_banner: bool) -> None:
    """GitHub Actions vulnerability scanner for PwnRequest attacks.

    Scans GitHub Actions workflows for the PwnRequest vulnerability pattern:
    pull_request_target + untrusted checkout + code execution.
    """
    ctx.ensure_object(dict)

    # Load settings
    if config:
        settings = get_settings(config_path=config)
    else:
        config_file = find_config_file()
        settings = get_settings(config_path=config_file)

    if verbose:
        settings.output.verbose = True

    ctx.obj["settings"] = settings
    ctx.obj["verbose"] = verbose

    if not no_banner:
        print_banner()


def _is_repo_url(value: str) -> bool:
    lowered = value.lower()
    return lowered.startswith(("https://", "http://", "git@")) and "github.com" in lowered


def _looks_like_org_repo(value: str) -> bool:
    return "/" in value and not value.startswith((".", "/"))


def _normalize_repo_target(value: str) -> str:
    if _is_repo_url(value):
        return value
    if _looks_like_org_repo(value):
        return f"https://github.com/{value}"
    return value


def _read_targets_file(path: Path) -> list[str]:
    targets: list[str] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            targets.append(line)
    return targets


def _expand_targets(target: str) -> list[str]:
    target_path = Path(target)
    if target_path.exists() and target_path.is_file():
        return _read_targets_file(target_path)
    return [target]


def _collect_code_dirs(base_dir: Path) -> list[Path]:
    return [p for p in base_dir.glob("*/*/*/code") if p.is_dir()]


def _default_output_path(output_format: str) -> Path:
    suffix = {"csv": ".csv", "json": ".json", "markdown": ".md"}[output_format]
    return Path("outputs") / f"vulnerabilities{suffix}"


def _find_repo_dir_from_path(path: Path) -> Path | None:
    for parent in [path, *path.parents]:
        git_path = parent / ".git"
        if git_path.exists():
            return parent
    return None


def _apply_validation_to_json_report(
    report: dict,
    validations: list[dict],
) -> dict:
    validation_index = {}
    for entry in validations:
        key = (
            entry.get("org", ""),
            entry.get("repo", ""),
            entry.get("branch", ""),
        )
        validation_index[key] = entry

    for vuln in report.get("vulnerabilities", []):
        key = (
            vuln.get("org", ""),
            vuln.get("repo", ""),
            vuln.get("branch", ""),
        )
        validation = validation_index.get(key)
        if validation:
            vuln["issue_type"] = validation.get("issue_type", "")
            vuln["cvss"] = validation.get("cvss")
            vuln["cwe"] = validation.get("cwe", "")
            vuln["validation"] = {
                "result": validation.get("result", ""),
                "confirmation_file": validation.get("confirmation_file"),
                "summary": validation.get("summary", ""),
                "confidence": validation.get("confidence", ""),
            }

    report["validations"] = validations
    report.setdefault("metadata", {})
    report["metadata"]["validated_at"] = datetime.now().isoformat()
    return report


@cli.command()
@click.argument("target", type=str)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    default=None,
    help="Output file path",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["csv", "json", "markdown"]),
    default="csv",
    help="Output format",
)
@click.option(
    "--include-protected",
    is_flag=True,
    help="Include permission-gated findings in output",
)
@click.option(
    "--validate",
    is_flag=True,
    help="Run AI validation after scanning",
)
@click.option(
    "--validate-agent",
    type=str,
    help='Custom validation agent command template (e.g., "codex -m gpt-4 -p {}")',
)
@click.option("--validate-workers", type=int, default=5, help="Parallel validation workers")
@click.option("--validate-timeout", type=int, default=300, help="Timeout per repo in seconds")
@click.option(
    "--all-branches",
    is_flag=True,
    help="Scan all branches using smart sampling (default + oldest + newest + random)",
)
@click.option(
    "--max-branches",
    type=int,
    default=10,
    help="Maximum branches per repo when using --all-branches",
)
@click.option("--clone-workers", type=int, default=5, help="Parallel clone workers")
@click.pass_context
def scan(
    ctx: click.Context,
    target: str,
    output: Path | None,
    output_format: str,
    include_protected: bool,
    validate: bool,
    validate_agent: str | None,
    validate_workers: int,
    validate_timeout: int,
    all_branches: bool,
    max_branches: int,
    clone_workers: int,
) -> None:
    """Scan repositories for PwnRequest vulnerabilities.

    TARGET can be a GitHub org name, a repo URL, a directory path, or a file
    containing newline-separated repo URLs and/or directories.

    Use --all-branches to scan multiple branches per repo using smart sampling:
    default branch + oldest + newest + random sample up to --max-branches.
    """
    from actions_scanner.core import PwnRequestDetector
    from actions_scanner.core.models import ScanResult
    from actions_scanner.git import MultiBranchScanner, SparseCloner
    from actions_scanner.github import GitHubClient, OrgScanner
    from actions_scanner.reporting import (
        append_columns_to_csv,
        generate_csv_report,
        generate_json_report,
        generate_markdown_report,
    )
    from actions_scanner.utils.console import print_error, print_info, print_success, print_warning
    from actions_scanner.utils.path import (
        extract_org_repo_from_path,
    )
    from actions_scanner.validation import BatchValidationRunner, ValidationAgent

    settings: Settings = ctx.obj["settings"]
    detector = PwnRequestDetector()

    targets = _expand_targets(target)
    local_dirs: list[Path] = []
    repo_urls: list[str] = []
    orgs: list[str] = []

    for item in targets:
        item_path = Path(item)
        if item_path.exists():
            if item_path.is_dir():
                local_dirs.append(item_path)
            else:
                print_warning(f"Skipping unsupported target file: {item}")
            continue

        normalized = _normalize_repo_target(item)
        if _is_repo_url(normalized) or _looks_like_org_repo(item):
            repo_urls.append(normalized)
        else:
            orgs.append(item)

    if not local_dirs and not repo_urls and not orgs:
        print_error("No valid targets provided")
        raise SystemExit(1)

    if orgs:
        token = settings.github.token or os.environ.get("GITHUB_TOKEN")
        if not token:
            print_error("GITHUB_TOKEN environment variable is required to scan orgs")
            raise SystemExit(1)

        async def discover_org_repos() -> list[str]:
            async with GitHubClient(token=token, concurrency=settings.github.concurrency) as client:
                scanner = OrgScanner(client)
                results = []
                for org in orgs:
                    repos = await scanner.list_org_repos(
                        org, include_archived=False, include_forks=False
                    )
                    results.extend([r.html_url for r in repos])
                return results

        org_repo_urls = asyncio.run(discover_org_repos())
        repo_urls.extend(org_repo_urls)

    repo_urls = sorted(set(repo_urls))

    scan_base_dir: Path | None = None
    if repo_urls:
        scan_base_dir = Path(tempfile.mkdtemp(prefix="actions-scanner-"))
        print_info(f"Cloning {len(repo_urls)} repositories to {scan_base_dir}...")
        cloner = SparseCloner(concurrency=clone_workers)
        asyncio.run(cloner.clone_repos(repo_urls, scan_base_dir))
        print_info("Clone complete (temporary directory retained for analysis)")

    result = ScanResult()

    def scan_paths(paths: list[Path]) -> None:
        for scan_path in paths:
            path_result = detector.scan_directory(scan_path)
            result.vulnerabilities.extend(path_result.vulnerabilities)
            result.files_scanned += path_result.files_scanned
            result.errors.extend(path_result.errors)

    if all_branches:
        print_info(f"Setting up multi-branch scanning (max {max_branches} branches per repo)...")
        mb_scanner = MultiBranchScanner(
            max_branches_per_repo=max_branches,
            concurrency=10,
        )

        def on_mb_progress(phase: str, completed: int, total: int, detail: str) -> None:
            if phase == "branches":
                console.print(f"\r  Selecting branches: {completed}/{total} repos", end="")
            elif phase == "worktrees":
                console.print(f"\r  Creating worktrees: {completed}/{total}       ", end="")

        base_dirs = list(local_dirs)
        if scan_base_dir:
            base_dirs.append(scan_base_dir)
        for base_dir in base_dirs:
            setup = asyncio.run(mb_scanner.setup_worktrees(base_dir, on_progress=on_mb_progress))
            console.print()
            total_branches = sum(len(b) for b in setup.branches_by_repo.values())
            print_info(f"Created {setup.worktrees_created} worktrees for {total_branches} branches")
            if setup.worktrees_failed > 0:
                print_info(f"  ({setup.worktrees_failed} worktrees failed)")
            print_info(f"Scanning {len(setup.scan_paths)} paths...")
            scan_paths(setup.scan_paths)
    else:
        for local_dir in local_dirs:
            print_info(f"Scanning {local_dir}...")
            scan_paths([local_dir])

        if scan_base_dir:
            code_dirs = _collect_code_dirs(scan_base_dir)
            if not code_dirs:
                print_warning(f"No repo directories found under {scan_base_dir}")
            else:
                print_info(f"Scanning {len(code_dirs)} cloned repositories...")
                scan_paths(code_dirs)

    print_info(f"Scanned {result.files_scanned} workflow files")
    print_info(f"Found {len(result.vulnerabilities)} potential vulnerabilities")

    # Filter if not including protected
    vulns = result.vulnerabilities
    if not include_protected:
        vulns = [v for v in vulns if v.is_exploitable()]
        print_info(f"Filtered to {len(vulns)} exploitable vulnerabilities")

    if output is None:
        output = _default_output_path(output_format)
    output.parent.mkdir(parents=True, exist_ok=True)

    validation_results: list[dict] = []
    if validate and vulns:
        command_template = validate_agent or settings.validation.command_template
        validation_agent = ValidationAgent(
            command_template=command_template,
            timeout=validate_timeout,
        )
        runner = BatchValidationRunner(agent=validation_agent, concurrency=validate_workers)

        repo_map: dict[tuple[str, str, str], dict] = {}
        for v in vulns:
            org, repo = extract_org_repo_from_path(str(v.workflow_path))
            key = (org, repo, v.branch)
            if key not in repo_map:
                repo_map[key] = {
                    "org": org,
                    "repo": repo,
                    "branch": v.branch,
                    "workflow_paths": [],
                    "working_dir": None,
                }
            repo_map[key]["workflow_paths"].append(str(v.workflow_path))
            if repo_map[key]["working_dir"] is None:
                repo_dir = _find_repo_dir_from_path(Path(v.workflow_path))
                if repo_dir:
                    repo_map[key]["working_dir"] = repo_dir

        repo_list = list(repo_map.values())
        print_info(
            f"Validating {len(repo_list)} repositories with {validate_workers} parallel agents..."
        )
        results = asyncio.run(runner.validate_repos(repo_list, scan_base_dir or output.parent))
        validation_results = [r.to_dict() for r in results]

    # Generate report
    if output_format == "csv":
        generate_csv_report(vulns, output, include_protected=include_protected)
        if validate and vulns:
            validation_index = {
                (v.get("org", ""), v.get("repo", ""), v.get("branch", "")): v
                for v in validation_results
            }
            append_columns_to_csv(
                output,
                output,
                {
                    "issue_type": lambda row: validation_index.get(
                        (row.get("org", ""), row.get("repo", ""), row.get("branch", "")), {}
                    ).get("issue_type", ""),
                    "cvss": lambda row: validation_index.get(
                        (row.get("org", ""), row.get("repo", ""), row.get("branch", "")), {}
                    ).get("cvss", ""),
                    "cwe": lambda row: validation_index.get(
                        (row.get("org", ""), row.get("repo", ""), row.get("branch", "")), {}
                    ).get("cwe", ""),
                    "confirmation_file": lambda row: validation_index.get(
                        (row.get("org", ""), row.get("repo", ""), row.get("branch", "")), {}
                    ).get("confirmation_file", ""),
                },
            )
    elif output_format == "json":
        generate_json_report(
            vulns,
            output,
            include_protected=include_protected,
            scan_base_dir=scan_base_dir,
            validations=validation_results if validate else None,
        )
    else:
        generate_markdown_report(vulns, output, include_protected=include_protected)

    print_success(f"Report written to {output}")

    # Print summary
    counts = result.counts_by_protection
    console.print("\n[bold]Summary:[/bold]")
    console.print(f"  Exploitable (no protection): {counts['none']}")
    console.print(f"  Label-gated:            {counts['label']}")
    console.print(f"  Permission-gated:       {counts['permission']}")
    console.print(f"  Same-repo only:         {counts['same_repo']}")


@cli.command()
@click.argument("repos_file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--output-dir",
    "-d",
    type=click.Path(path_type=Path),
    default="repos",
    help="Output directory for cloned repos",
)
@click.option("--workers", "-w", type=int, default=5, help="Parallel clone workers")
@click.pass_context
def clone(
    ctx: click.Context,
    repos_file: Path,
    output_dir: Path,
    workers: int,
) -> None:
    """Clone repositories with sparse checkout.

    REPOS_FILE contains one repository URL per line.
    Only .github/ directories are checked out for efficient scanning.
    """
    from actions_scanner.git import SparseCloner, read_repos_file
    from actions_scanner.utils.console import (
        create_simple_progress,
        is_terminal,
        print_error,
        print_info,
        print_success,
    )

    print_info(f"Reading repository list from {repos_file}...")
    repos = read_repos_file(repos_file)
    print_info(f"Found {len(repos)} repositories")

    cloner = SparseCloner(concurrency=workers)

    print_info(f"Cloning to {output_dir}...")
    if is_terminal():
        progress = create_simple_progress()
        task_id = progress.add_task("Cloning", total=len(repos))

        def on_progress(completed: int, total: int, name: str, result) -> None:
            progress.update(task_id, completed=completed, description=f"Cloning {name}")

        with progress:
            stats = asyncio.run(cloner.clone_repos(repos, output_dir, on_progress=on_progress))
    else:
        stats = asyncio.run(cloner.clone_repos(repos, output_dir))
    print_success(f"Cloned {stats.success} repositories")
    if stats.skipped:
        print_info(f"Skipped {stats.skipped} (already exist)")
    if stats.failed:
        print_error(f"Failed {stats.failed} repositories")


@cli.command()
@click.argument("vulnerabilities_file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output file (defaults to input file with -validated suffix)",
)
@click.option(
    "--repos-dir",
    "-d",
    type=click.Path(exists=True, path_type=Path),
    help="Directory containing cloned repositories",
)
@click.option(
    "--agent",
    type=str,
    help='Custom validation agent command template (e.g., "codex -m gpt-4 -p {}")',
)
@click.option("--workers", "-w", type=int, default=5, help="Parallel validation workers")
@click.option("--timeout", type=int, default=300, help="Timeout per repo in seconds")
@click.pass_context
def validate(
    ctx: click.Context,
    vulnerabilities_file: Path,
    output: Path | None,
    repos_dir: Path | None,
    agent: str | None,
    workers: int,
    timeout: int,
) -> None:
    """Validate vulnerabilities using AI agent.

    Runs an AI agent to confirm or reject scanner findings.
    Creates confirmed_vulnerable.txt, confirmed_weakness.txt, or not_vulnerable.txt.
    """
    import csv

    from rich.live import Live
    from rich.table import Table

    from actions_scanner.reporting import (
        load_json_report,
        read_vulnerabilities_csv,
        read_vulnerabilities_json,
    )
    from actions_scanner.utils.console import is_terminal, print_info, print_success, print_warning
    from actions_scanner.utils.path import (
        extract_org_repo_branch_from_path,
        extract_org_repo_from_path,
    )
    from actions_scanner.validation import BatchValidationRunner, ValidationAgent

    settings: Settings = ctx.obj["settings"]

    # Use provided agent or settings
    command_template = agent or settings.validation.command_template

    print_info(f"Using agent: {command_template.split()[0]}")
    print_info(f"Reading vulnerabilities from {vulnerabilities_file}...")
    suffix = vulnerabilities_file.suffix.lower()
    if suffix == ".json":
        vulns = read_vulnerabilities_json(vulnerabilities_file)
        report_data = load_json_report(vulnerabilities_file)
    else:
        vulns = read_vulnerabilities_csv(vulnerabilities_file)
        report_data = {"vulnerabilities": vulns, "metadata": {}}
    if not isinstance(report_data, dict):
        report_data = {"vulnerabilities": vulns, "metadata": {}}
    print_info(f"Found {len(vulns)} vulnerability records")

    normalized_vulns = []
    skipped = 0
    for v in vulns:
        org = v.get("org", "") or ""
        repo = v.get("repo", "") or ""
        branch = v.get("branch", "") or ""
        if (not org or not repo) and v.get("workflow_path"):
            inferred_org, inferred_repo = extract_org_repo_from_path(
                str(v.get("workflow_path", ""))
            )
            if not org:
                org = inferred_org
            if not repo:
                repo = inferred_repo
        if not branch and v.get("workflow_path"):
            _org, _repo, inferred_branch = extract_org_repo_branch_from_path(
                str(v.get("workflow_path", ""))
            )
            if inferred_branch:
                branch = inferred_branch
        if not repo:
            skipped += 1
            continue
        v["org"] = org
        v["repo"] = repo
        v["branch"] = branch
        normalized_vulns.append(v)

    if skipped:
        print_warning(f"Skipped {skipped} records without a resolvable repository")

    if isinstance(report_data, dict):
        report_data["vulnerabilities"] = normalized_vulns

    # Group by repo + branch
    repos: dict[tuple[str, str, str], dict] = {}
    for v in normalized_vulns:
        key = (v.get("org", ""), v.get("repo", ""))
        branch = v.get("branch", "") or ""
        full_key = (key[0], key[1], branch)
        if full_key not in repos:
            repos[full_key] = {
                "org": key[0],
                "repo": key[1],
                "branch": branch,
                "workflow_paths": [],
                "working_dir": None,
            }
        repos[full_key]["workflow_paths"].append(v.get("workflow_path", ""))
        if repos[full_key]["working_dir"] is None and v.get("workflow_path"):
            repo_dir = _find_repo_dir_from_path(Path(str(v.get("workflow_path"))))
            if repo_dir:
                repos[full_key]["working_dir"] = repo_dir

    repo_list = list(repos.values())

    print_info(f"Validating {len(repo_list)} repositories with {workers} parallel agents...")
    console.print()

    validation_agent = ValidationAgent(
        command_template=command_template,
        timeout=timeout,
    )
    runner = BatchValidationRunner(agent=validation_agent, concurrency=workers)

    # Track results for live display
    results_log: list[tuple[str, str, str]] = []

    def make_progress_table(completed: int, total: int) -> Table:
        """Create a progress table showing recent results."""
        table = Table(show_header=True, header_style="bold", box=None)
        table.add_column("Progress", width=20)
        table.add_column("Repository", width=40)
        table.add_column("Result", width=15)

        # Progress bar
        pct = (completed / total) * 100
        bar_width = 15
        filled = int(bar_width * completed / total)
        bar = "█" * filled + "░" * (bar_width - filled)
        progress_str = f"[{bar}] {pct:5.1f}%"

        # Show last 8 results
        for org, repo, status in results_log[-8:]:
            repo_display = f"{org}/{repo}"
            if len(repo_display) > 38:
                repo_display = repo_display[:35] + "..."

            # Color based on result
            if status == "vulnerable":
                status_display = f"[red bold]{status}[/]"
            elif status == "weakness":
                status_display = f"[yellow]{status}[/]"
            elif status == "false_positive":
                status_display = f"[green]{status}[/]"
            else:
                status_display = f"[dim]{status}[/]"

            table.add_row("", repo_display, status_display)

        # Add progress row at the bottom
        table.add_row(progress_str, f"[dim]{completed}/{total} complete[/]", "")

        return table

    def on_progress(completed: int, total: int, result) -> None:
        if result:
            status = result.result.value
            results_log.append((result.org, result.repo, status))

    # Determine base directory for repos
    if repos_dir:
        base_dir = repos_dir
    else:
        base_dir = None
        if isinstance(report_data, dict):
            metadata = report_data.get("metadata")
            if isinstance(metadata, dict):
                scan_base = metadata.get("scan_base_dir")
                if scan_base:
                    base_dir = Path(str(scan_base))
        if base_dir is None:
            base_dir = vulnerabilities_file.parent

    validation_results: list = []

    # Run with live progress display
    async def run_with_progress() -> None:
        nonlocal validation_results
        if is_terminal():
            with Live(
                make_progress_table(0, len(repo_list)), refresh_per_second=2, console=console
            ) as live:
                original_callback = on_progress

                def live_progress(completed: int, total: int, result) -> None:
                    original_callback(completed, total, result)
                    live.update(make_progress_table(completed, total))

                validation_results = await runner.validate_repos(
                    repo_list, base_dir, on_progress=live_progress
                )
        else:
            validation_results = await runner.validate_repos(
                repo_list, base_dir, on_progress=on_progress
            )

    asyncio.run(run_with_progress())

    console.print()

    stats = runner.get_stats()
    print_success("Validation complete!")
    console.print()
    console.print("[bold]Results Summary:[/bold]")
    console.print(f"  [red]● Vulnerable:[/]     {stats.vulnerable}")
    console.print(f"  [yellow]● Weakness:[/]       {stats.weakness}")
    console.print(f"  [green]● False positive:[/] {stats.false_positive}")
    console.print(f"  [dim]● Failed:[/]         {stats.failed}")

    validations = [r.to_dict() for r in validation_results]

    if output is None:
        output = vulnerabilities_file.with_name(f"{vulnerabilities_file.stem}-validated.json")
    output.parent.mkdir(parents=True, exist_ok=True)

    if output.suffix.lower() == ".csv":
        validation_index = {
            (v.get("org", ""), v.get("repo", ""), v.get("branch", "")): v for v in validations
        }
        rows = [dict(v) for v in normalized_vulns]
        for row in rows:
            validation = validation_index.get(
                (row.get("org", ""), row.get("repo", ""), row.get("branch", "")), {}
            )
            row["issue_type"] = validation.get("issue_type", "")
            row["cvss"] = validation.get("cvss", "")
            row["cwe"] = validation.get("cwe", "")
            row["confirmation_file"] = validation.get("confirmation_file", "")

        fieldnames = list(rows[0].keys()) if rows else []
        with output.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for row in rows:
                writer.writerow(row)
    else:
        report_data = _apply_validation_to_json_report(report_data, validations)
        with output.open("w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)

    print_success(f"Validated report written to {output}")


@cli.command()
@click.argument("vulnerabilities_file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output file (defaults to input file)",
)
@click.option("--with-mergers", is_flag=True, help="Add PR merger information")
@click.option("--with-ldap", is_flag=True, help="Add LDAP identity information")
@click.pass_context
def enrich(
    ctx: click.Context,
    vulnerabilities_file: Path,
    output: Path | None,
    with_mergers: bool,
    with_ldap: bool,
) -> None:
    """Enrich vulnerability data with additional context.

    Adds merger information and/or LDAP identity data to vulnerability records.
    """
    from actions_scanner.enrichment import GitHubUserEnrichment, LDAPEnrichment
    from actions_scanner.reporting import read_vulnerabilities_csv
    from actions_scanner.reporting.csv import sanitize_csv_value
    from actions_scanner.utils.console import (
        is_terminal,
        print_error,
        print_info,
        print_success,
    )

    settings: Settings = ctx.obj["settings"]
    output = output or vulnerabilities_file

    print_info(f"Reading vulnerabilities from {vulnerabilities_file}...")
    vulns = read_vulnerabilities_csv(vulnerabilities_file)
    print_info(f"Found {len(vulns)} records")

    if with_mergers:
        print_info("Fetching merger information...")
        enricher = GitHubUserEnrichment()

        def merger_progress(completed: int, total: int) -> None:
            if not is_terminal():
                return
            pct = (completed / total) * 100
            console.print(f"\r[{pct:5.1f}%] {completed}/{total}", end="")

        results = asyncio.run(enricher.enrich_batch(vulns, on_progress=merger_progress))
        console.print()

        # Update vulns with enriched data
        vulns = [r.data for r in results if r.success]
        print_success(f"Added merger information to {len(vulns)} records")

    if with_ldap:
        if not settings.ldap.enabled or not settings.ldap.host:
            print_error("LDAP not configured. Set ACTIONS_SCANNER_LDAP__ENABLED=true")
            return

        print_info("Looking up LDAP identities...")
        ldap_enricher = LDAPEnrichment(
            host=settings.ldap.host,
            base_dn=settings.ldap.base,
            social_url_attribute=settings.ldap.social_url_attribute,
        )

        try:
            results = asyncio.run(ldap_enricher.enrich_batch(vulns))
            vulns = [r.data for r in results if r.success]
            print_success("Added LDAP information")
        finally:
            ldap_enricher.close()

    # Write output
    import csv

    fieldnames = list(vulns[0].keys()) if vulns else []
    with output.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in vulns:
            sanitized = {k: sanitize_csv_value(v) for k, v in row.items()}
            writer.writerow(sanitized)

    print_success(f"Enriched data written to {output}")


@cli.command()
@click.argument("vulnerabilities_file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output file path",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["csv", "json", "markdown"]),
    default="markdown",
    help="Output format",
)
@click.pass_context
def report(
    ctx: click.Context,
    vulnerabilities_file: Path,
    output: Path | None,
    output_format: str,
) -> None:
    """Generate reports from vulnerability data.

    Converts vulnerability CSV to other formats (markdown, json).
    """
    from actions_scanner.core.models import VulnerableJob
    from actions_scanner.reporting import (
        generate_json_report,
        generate_markdown_report,
        read_vulnerabilities_csv,
    )
    from actions_scanner.utils.console import print_info, print_success

    print_info(f"Reading vulnerabilities from {vulnerabilities_file}...")
    vulns_data = read_vulnerabilities_csv(vulnerabilities_file)
    print_info(f"Found {len(vulns_data)} records")

    # Convert to VulnerableJob objects
    vulns = []
    for v in vulns_data:
        vulns.append(
            VulnerableJob(
                workflow_path=Path(v.get("workflow_path", "")),
                job_name=v.get("job_name", ""),
                checkout_line=int(v.get("checkout_line", 0) or 0),
                checkout_ref=v.get("checkout_ref", ""),
                exec_line=int(v.get("exec_line", 0) or 0),
                exec_type=v.get("exec_type", ""),
                exec_value=v.get("exec_value", ""),
                branch=v.get("branch", ""),
                protection=v.get("protection", "none"),
                protection_detail=v.get("protection_detail", ""),
            )
        )

    # Determine output path
    if output is None:
        suffix = {"csv": ".csv", "json": ".json", "markdown": ".md"}[output_format]
        output = vulnerabilities_file.with_suffix(suffix)

    # Generate report
    if output_format == "markdown":
        generate_markdown_report(vulns, output)
    elif output_format == "json":
        generate_json_report(vulns, output)
    else:
        # Already CSV, just copy
        import shutil

        shutil.copy(vulnerabilities_file, output)

    print_success(f"Report written to {output}")


@cli.command("scan-org")
@click.argument("org", type=str)
@click.option(
    "--output-dir",
    "-d",
    type=click.Path(path_type=Path),
    default=None,
    help="Directory to clone repositories into",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    default=None,
    help="Output file for vulnerability report",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["csv", "json", "markdown"]),
    default="csv",
    help="Output format",
)
@click.option(
    "--include-forks",
    is_flag=True,
    help="Include forked repositories",
)
@click.option(
    "--include-archived",
    is_flag=True,
    help="Include archived repositories",
)
@click.option(
    "--clone-workers",
    type=int,
    default=5,
    help="Parallel clone workers",
)
@click.option(
    "--skip-clone",
    is_flag=True,
    help="Skip cloning, use existing repos in output-dir",
)
@click.option(
    "--list-only",
    is_flag=True,
    help="Only list repositories, don't clone or scan",
)
@click.option(
    "--all-branches",
    is_flag=True,
    help="Scan all branches using smart sampling (default + oldest + newest + random)",
)
@click.option(
    "--max-branches",
    type=int,
    default=10,
    help="Maximum branches per repo when using --all-branches",
)
@click.pass_context
def scan_org(
    ctx: click.Context,
    org: str,
    output_dir: Path | None,
    output: Path | None,
    output_format: str,
    include_forks: bool,
    include_archived: bool,
    clone_workers: int,
    skip_clone: bool,
    list_only: bool,
    all_branches: bool,
    max_branches: int,
) -> None:
    """Scan all repositories in a GitHub organization.

    Discovers all repos in ORG, clones them (sparse checkout), and scans
    for PwnRequest vulnerabilities.

    Requires GITHUB_TOKEN environment variable to be set.

    Use --all-branches to scan multiple branches per repo using smart sampling.

    Examples:

        actions-scanner scan-org ansible

        actions-scanner scan-org redhat --include-forks -d repos/redhat

        actions-scanner scan-org myorg --list-only

        actions-scanner scan-org myorg --all-branches --max-branches 5
    """
    from rich.live import Live
    from rich.table import Table

    from actions_scanner.core import PwnRequestDetector
    from actions_scanner.core.models import ScanResult
    from actions_scanner.git import CloneResult, MultiBranchScanner, SparseCloner
    from actions_scanner.github import GitHubClient, OrgScanner
    from actions_scanner.reporting import (
        generate_csv_report,
        generate_json_report,
        generate_markdown_report,
    )
    from actions_scanner.utils.console import (
        is_terminal,
        print_error,
        print_info,
        print_success,
        print_warning,
    )
    from actions_scanner.utils.path import resolve_repo_dir

    settings: Settings = ctx.obj["settings"]

    # Check for GitHub token
    token = settings.github.token
    if not token:
        import os

        token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print_error("GITHUB_TOKEN environment variable is required")
        raise SystemExit(1)

    print_info(f"Discovering repositories in '{org}'...")

    if output_dir is None:
        output_dir = Path(tempfile.mkdtemp(prefix="actions-scanner-"))
        print_info(f"Using temporary directory {output_dir}")

    async def discover_repos() -> list[tuple[str, str]]:
        """Discover all repos in the org."""
        async with GitHubClient(token=token, concurrency=settings.github.concurrency) as client:
            scanner = OrgScanner(client)
            repos = await scanner.list_org_repos(
                org,
                include_archived=include_archived,
                include_forks=include_forks,
            )
            return [(r.full_name, r.html_url) for r in repos]

    repos = asyncio.run(discover_repos())
    print_info(f"Found {len(repos)} repositories")
    repo_info = []
    for full_name, url in repos:
        if "/" in full_name:
            org_name, repo_name = full_name.split("/", 1)
            repo_info.append((org_name, repo_name, url))

    if list_only:
        console.print()
        console.print("[bold]Repositories:[/bold]")
        for full_name, _url in sorted(repos):
            console.print(f"  {full_name}")
        return

    if not repos:
        print_info("No repositories to scan")
        return

    # Clone repositories
    if not skip_clone:
        print_info(f"Cloning repositories to {output_dir}...")

        # Create repo URLs file content
        repo_urls = [url for _org, _repo, url in repo_info]

        cloner = SparseCloner(concurrency=clone_workers)

        clone_results: list[tuple[str, str]] = []

        def on_clone_progress(completed: int, total: int, name: str, result) -> None:
            status = "ok" if result == CloneResult.SUCCESS else "fail"
            clone_results.append((name, status))

        def make_clone_table(completed: int, total: int) -> Table:
            table = Table(show_header=True, header_style="bold", box=None)
            table.add_column("Progress", width=20)
            table.add_column("Repository", width=50)
            table.add_column("Status", width=10)

            pct = (completed / total) * 100 if total > 0 else 0
            bar_width = 15
            filled = int(bar_width * completed / total) if total > 0 else 0
            bar = "█" * filled + "░" * (bar_width - filled)

            for name, status in clone_results[-6:]:
                status_display = "[green]ok[/]" if status == "ok" else "[red]fail[/]"
                table.add_row("", name[:48], status_display)

            table.add_row(f"[{bar}] {pct:5.1f}%", f"[dim]{completed}/{total} cloned[/]", "")
            return table

        if is_terminal():

            async def clone_with_progress() -> None:
                with Live(
                    make_clone_table(0, len(repo_urls)), refresh_per_second=2, console=console
                ) as live:
                    completed = 0

                    def live_progress(c: int, t: int, name: str, result) -> None:
                        nonlocal completed
                        completed = c
                        on_clone_progress(c, t, name, result)
                        live.update(make_clone_table(c, t))

                    await cloner.clone_repos(repo_urls, output_dir, on_progress=live_progress)

            asyncio.run(clone_with_progress())
            console.print()
        else:
            asyncio.run(cloner.clone_repos(repo_urls, output_dir))

    # Resolve repo directories to scan
    repo_dirs: list[tuple[str, str, Path]] = []
    missing_repos: list[str] = []
    for org_name, repo_name, _url in repo_info:
        repo_dir, found = resolve_repo_dir(output_dir, org_name, repo_name)
        if found:
            repo_dirs.append((org_name, repo_name, repo_dir))
        else:
            missing_repos.append(f"{org_name}/{repo_name}")

    if missing_repos:
        print_warning(f"Missing {len(missing_repos)} repositories; scan may be incomplete")

    if not repo_dirs:
        print_error("No repositories found to scan")
        return

    # Scan repositories
    detector = PwnRequestDetector()
    combined = ScanResult()

    if all_branches:
        # Multi-branch scanning
        print_info(f"Setting up multi-branch scanning (max {max_branches} branches per repo)...")

        mb_scanner = MultiBranchScanner(
            max_branches_per_repo=max_branches,
            concurrency=10,
        )

        def on_mb_progress(phase: str, completed: int, total: int, detail: str) -> None:
            if phase == "branches":
                console.print(f"\r  Selecting branches: {completed}/{total} repos", end="")
            elif phase == "worktrees":
                console.print(f"\r  Creating worktrees: {completed}/{total}       ", end="")

        setup = asyncio.run(mb_scanner.setup_worktrees(output_dir, on_progress=on_mb_progress))
        console.print()

        total_branches = sum(len(b) for b in setup.branches_by_repo.values())
        print_info(f"Created {setup.worktrees_created} worktrees for {total_branches} branches")

        if setup.worktrees_failed > 0:
            print_info(f"  ({setup.worktrees_failed} worktrees failed)")

        print_info(f"Scanning {len(setup.scan_paths)} paths...")

        for scan_path in setup.scan_paths:
            path_result = detector.scan_directory(scan_path)
            combined.vulnerabilities.extend(path_result.vulnerabilities)
            combined.files_scanned += path_result.files_scanned
            combined.errors.extend(path_result.errors)
    else:
        # Default: scan only default branch
        print_info(f"Scanning {len(repo_dirs)} repositories in {output_dir}...")

        for _org, _repo, repo_dir in repo_dirs:
            repo_result = detector.scan_directory(repo_dir)
            combined.vulnerabilities.extend(repo_result.vulnerabilities)
            combined.files_scanned += repo_result.files_scanned
            combined.errors.extend(repo_result.errors)

    print_info(f"Scanned {combined.files_scanned} workflow files")
    print_info(f"Found {len(combined.vulnerabilities)} potential vulnerabilities")

    # Filter to exploitable only
    vulns = [v for v in combined.vulnerabilities if v.is_exploitable()]
    print_info(f"Filtered to {len(vulns)} exploitable vulnerabilities")

    if output is None:
        output = _default_output_path(output_format)
    output.parent.mkdir(parents=True, exist_ok=True)

    # Generate report
    if output_format == "csv":
        generate_csv_report(vulns, output, include_protected=False)
    elif output_format == "json":
        generate_json_report(vulns, output, include_protected=False, scan_base_dir=output_dir)
    else:
        generate_markdown_report(vulns, output, include_protected=False)

    print_success(f"Report written to {output}")

    # Print summary
    counts = combined.counts_by_protection
    console.print()
    console.print("[bold]Summary:[/bold]")
    console.print(f"  Organization:           {org}")
    console.print(f"  Repositories scanned:   {len(repo_dirs)}")
    if missing_repos:
        console.print(f"  Repositories missing:   {len(missing_repos)}")
    console.print(f"  Workflow files:         {combined.files_scanned}")
    console.print(f"  [red]Exploitable (no protection):[/] {counts['none']}")
    console.print(f"  [yellow]Label-gated:[/]           {counts['label']}")
    console.print(f"  [dim]Permission-gated:[/]      {counts['permission']}")
    console.print(f"  [dim]Same-repo only:[/]        {counts['same_repo']}")


def main() -> None:
    """Main entry point."""
    cli(obj={})


if __name__ == "__main__":
    main()
