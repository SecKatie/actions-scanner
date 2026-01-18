"""Main CLI entry point for actions-scanner."""

import asyncio
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


@cli.command()
@click.argument("target", type=click.Path(exists=True, path_type=Path))
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
def scan(
    ctx: click.Context,
    target: Path,
    output: Path | None,
    output_format: str,
    include_protected: bool,
    all_branches: bool,
    max_branches: int,
) -> None:
    """Scan repositories for PwnRequest vulnerabilities.

    TARGET is a directory containing cloned repositories or workflow files.

    Use --all-branches to scan multiple branches per repo using smart sampling:
    default branch + oldest + newest + random sample up to --max-branches.
    """
    from actions_scanner.core import PwnRequestDetector
    from actions_scanner.core.models import ScanResult
    from actions_scanner.git import MultiBranchScanner
    from actions_scanner.reporting import (
        generate_csv_report,
        generate_json_report,
        generate_markdown_report,
    )
    from actions_scanner.utils.console import print_info, print_success

    detector = PwnRequestDetector()

    # Set up multi-branch scanning if requested
    if all_branches:
        print_info(f"Setting up multi-branch scanning (max {max_branches} branches per repo)...")

        scanner = MultiBranchScanner(
            max_branches_per_repo=max_branches,
            concurrency=10,
        )

        def on_mb_progress(phase: str, completed: int, total: int, detail: str) -> None:
            if phase == "branches":
                console.print(f"\r  Selecting branches: {completed}/{total} repos", end="")
            elif phase == "worktrees":
                console.print(f"\r  Creating worktrees: {completed}/{total}       ", end="")

        setup = asyncio.run(scanner.setup_worktrees(target, on_progress=on_mb_progress))
        console.print()  # Newline after progress

        total_branches = sum(len(b) for b in setup.branches_by_repo.values())
        print_info(f"Created {setup.worktrees_created} worktrees for {total_branches} branches")

        if setup.worktrees_failed > 0:
            print_info(f"  ({setup.worktrees_failed} worktrees failed)")

        # Scan all paths (repos + worktrees)
        print_info(f"Scanning {len(setup.scan_paths)} paths...")

        all_vulns = []
        files_scanned = 0
        for scan_path in setup.scan_paths:
            path_result = detector.scan_directory(scan_path)
            all_vulns.extend(path_result.vulnerabilities)
            files_scanned += path_result.files_scanned

        result = ScanResult(
            files_scanned=files_scanned,
            vulnerabilities=all_vulns,
        )
    else:
        print_info(f"Scanning {target}...")
        result = detector.scan_directory(target)

    print_info(f"Scanned {result.files_scanned} workflow files")
    print_info(f"Found {len(result.vulnerabilities)} potential vulnerabilities")

    # Filter if not including protected
    vulns = result.vulnerabilities
    if not include_protected:
        vulns = [v for v in vulns if v.is_exploitable()]
        print_info(f"Filtered to {len(vulns)} exploitable vulnerabilities")

    if output is None:
        suffix = {"csv": ".csv", "json": ".json", "markdown": ".md"}[output_format]
        output = Path(f"vulnerabilities{suffix}")

    # Generate report
    if output_format == "csv":
        generate_csv_report(vulns, output, include_protected=include_protected)
    elif output_format == "json":
        generate_json_report(vulns, output, include_protected=include_protected)
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
    from rich.live import Live
    from rich.table import Table

    from actions_scanner.reporting import read_vulnerabilities_csv, read_vulnerabilities_json
    from actions_scanner.utils.console import is_terminal, print_info, print_success, print_warning
    from actions_scanner.utils.path import extract_org_repo_from_path
    from actions_scanner.validation import BatchValidationRunner, ValidationAgent

    settings: Settings = ctx.obj["settings"]

    # Use provided agent or settings
    command_template = agent or settings.validation.command_template

    print_info(f"Using agent: {command_template.split()[0]}")
    print_info(f"Reading vulnerabilities from {vulnerabilities_file}...")
    suffix = vulnerabilities_file.suffix.lower()
    if suffix == ".json":
        vulns = read_vulnerabilities_json(vulnerabilities_file)
    else:
        vulns = read_vulnerabilities_csv(vulnerabilities_file)
    print_info(f"Found {len(vulns)} vulnerability records")

    normalized_vulns = []
    skipped = 0
    for v in vulns:
        org = v.get("org", "") or ""
        repo = v.get("repo", "") or ""
        if (not org or not repo) and v.get("workflow_path"):
            inferred_org, inferred_repo = extract_org_repo_from_path(
                str(v.get("workflow_path", ""))
            )
            if not org:
                org = inferred_org
            if not repo:
                repo = inferred_repo
        if not repo:
            skipped += 1
            continue
        v["org"] = org
        v["repo"] = repo
        normalized_vulns.append(v)

    if skipped:
        print_warning(f"Skipped {skipped} records without a resolvable repository")

    # Group by repo
    repos: dict[tuple[str, str], list[str]] = {}
    for v in normalized_vulns:
        key = (v.get("org", ""), v.get("repo", ""))
        if key not in repos:
            repos[key] = []
        repos[key].append(v.get("workflow_path", ""))

    repo_list = [
        {"org": org, "repo": repo, "workflow_paths": paths}
        for (org, repo), paths in repos.items()
    ]

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
        # Fallback: check for scan-output.txt or use parent directory
        base_dir = vulnerabilities_file.parent / "scan-output.txt"
        if not base_dir.exists():
            base_dir = vulnerabilities_file.parent

    # Run with live progress display
    async def run_with_progress() -> None:
        if is_terminal():
            with Live(make_progress_table(0, len(repo_list)), refresh_per_second=2, console=console) as live:
                original_callback = on_progress

                def live_progress(completed: int, total: int, result) -> None:
                    original_callback(completed, total, result)
                    live.update(make_progress_table(completed, total))

                await runner.validate_repos(repo_list, base_dir, on_progress=live_progress)
        else:
            await runner.validate_repos(repo_list, base_dir, on_progress=on_progress)

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
    default="repos",
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
    output_dir: Path,
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
                with Live(make_clone_table(0, len(repo_urls)), refresh_per_second=2, console=console) as live:
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
        suffix = {"csv": ".csv", "json": ".json", "markdown": ".md"}[output_format]
        output = Path(f"vulnerabilities{suffix}")

    # Generate report
    if output_format == "csv":
        generate_csv_report(vulns, output, include_protected=False)
    elif output_format == "json":
        generate_json_report(vulns, output, include_protected=False)
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
