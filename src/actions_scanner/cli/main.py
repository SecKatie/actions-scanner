"""Main CLI entry point for actions-scanner."""

import asyncio
import os
import tempfile
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
    "--no-protected",
    is_flag=True,
    help="Exclude permission-gated findings",
)
@click.option(
    "--no-labeled",
    is_flag=True,
    help="Exclude label-gated findings",
)
@click.option(
    "--include-same-repo",
    is_flag=True,
    help="Include same-repo-only findings (excluded by default)",
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
@click.option("--clone-workers", type=int, default=5, help="Parallel clone workers")
@click.option(
    "--full-history",
    is_flag=True,
    default=False,
    help="Fetch full git history instead of shallow clone (larger .git folders)",
)
@click.option(
    "--single-branch",
    is_flag=True,
    default=False,
    help="Only fetch default branch (smaller .git but no multi-branch scanning)",
)
@click.pass_context
def scan(
    ctx: click.Context,
    target: str,
    output: Path | None,
    output_format: str,
    no_protected: bool,
    no_labeled: bool,
    include_same_repo: bool,
    all_branches: bool,
    max_branches: int,
    clone_workers: int,
    full_history: bool,
    single_branch: bool,
) -> None:
    """Scan repositories for PwnRequest vulnerabilities.

    TARGET can be a GitHub org name, a repo URL, a directory path, or a file
    containing newline-separated repo URLs and/or directories.

    Use --all-branches to scan multiple branches per repo using smart sampling:
    default branch + oldest + newest + random sample up to --max-branches.
    """
    from actions_scanner.core import ScanResult, scan_directory
    from actions_scanner.git import MultiBranchScanner, SparseCloner
    from actions_scanner.github import GitHubClient, OrgScanner
    from actions_scanner.reporting import (
        generate_csv_report,
        generate_json_report,
        generate_markdown_report,
    )
    from actions_scanner.utils.console import (
        create_progress,
        is_terminal,
        print_error,
        print_info,
        print_success,
        print_warning,
    )

    settings: Settings = ctx.obj["settings"]

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

        if is_terminal():
            progress = create_progress()
            task_id = progress.add_task("Discovering", total=len(orgs))
            repos_found = 0

            async def discover_org_repos() -> list[str]:
                nonlocal repos_found
                async with GitHubClient(
                    token=token, concurrency=settings.github.concurrency
                ) as client:
                    scanner = OrgScanner(client)
                    results = []
                    for i, org in enumerate(orgs):

                        def on_page_progress(page: int, count: int, org: str = org) -> None:
                            nonlocal repos_found
                            repos_found = len(results) + count
                            org_display = org[:30].ljust(30)
                            progress.update(
                                task_id,
                                description=f"Discovering {org_display} ({repos_found} repos)",
                            )

                        repos = await scanner.list_org_repos(
                            org,
                            include_archived=False,
                            include_forks=False,
                            on_progress=on_page_progress,
                        )
                        results.extend([r.html_url for r in repos])
                        repos_found = len(results)
                        progress.update(task_id, completed=i + 1)
                    return results

            with progress:
                org_repo_urls = asyncio.run(discover_org_repos())
        else:
            if len(orgs) == 1:
                print_info(f"Discovering repositories in '{orgs[0]}'...")
            else:
                print_info(f"Discovering repositories across {len(orgs)} organizations...")

            async def discover_org_repos() -> list[str]:
                async with GitHubClient(
                    token=token, concurrency=settings.github.concurrency
                ) as client:
                    scanner = OrgScanner(client)
                    results = []
                    for org in orgs:
                        repos = await scanner.list_org_repos(
                            org, include_archived=False, include_forks=False
                        )
                        results.extend([r.html_url for r in repos])
                    return results

            org_repo_urls = asyncio.run(discover_org_repos())
        print_info(f"Found {len(org_repo_urls)} repositories in {len(orgs)} organization(s)")
        repo_urls.extend(org_repo_urls)

    repo_urls = sorted(set(repo_urls))

    scan_base_dir: Path | None = None
    if repo_urls:
        scan_base_dir = Path(tempfile.mkdtemp(prefix="actions-scanner-"))
        print_info(f"Cloning {len(repo_urls)} repositories to {scan_base_dir}...")
        cloner = SparseCloner(
            concurrency=clone_workers,
            shallow=not full_history,
            single_branch=single_branch,
        )
        if is_terminal():
            progress = create_progress()
            task_id = progress.add_task("Cloning", total=len(repo_urls))

            def on_progress(completed: int, total: int, name: str, result) -> None:
                # Fixed-width name keeps the progress bar stable
                display_name = name[:40].ljust(40)
                progress.update(task_id, completed=completed, description=f"Cloning {display_name}")

            with progress:
                asyncio.run(cloner.clone_repos(repo_urls, scan_base_dir, on_progress=on_progress))
        else:
            asyncio.run(cloner.clone_repos(repo_urls, scan_base_dir))
        print_info("Clone complete (temporary directory retained for analysis)")

    result = ScanResult()

    def scan_paths(paths: list[Path]) -> None:
        for scan_path in paths:
            path_result = scan_directory(scan_path)
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

    # Filter vulnerabilities based on flags
    vulns = result.vulnerabilities
    excluded_protections: list[str] = []
    if no_protected:
        excluded_protections.append("permission")
    if no_labeled:
        excluded_protections.append("label")
    if not include_same_repo:
        excluded_protections.append("same_repo")
    if excluded_protections:
        vulns = [v for v in vulns if v.protection not in excluded_protections]
        print_info(
            f"Filtered to {len(vulns)} vulnerabilities (excluded: {', '.join(excluded_protections)})"
        )

    if output is None:
        output = _default_output_path(output_format)
    output.parent.mkdir(parents=True, exist_ok=True)

    # Generate report (include_protected=True since filtering is done above)
    if output_format == "csv":
        generate_csv_report(vulns, output, include_protected=True)
    elif output_format == "json":
        generate_json_report(
            vulns,
            output,
            include_protected=True,
            scan_base_dir=scan_base_dir,
        )
    else:
        generate_markdown_report(vulns, output, include_protected=True)

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
@click.option(
    "--full-history",
    is_flag=True,
    default=False,
    help="Fetch full git history instead of shallow clone (larger .git folders)",
)
@click.option(
    "--single-branch",
    is_flag=True,
    default=False,
    help="Only fetch default branch (smaller .git but no multi-branch scanning)",
)
@click.pass_context
def clone(
    ctx: click.Context,
    repos_file: Path,
    output_dir: Path,
    workers: int,
    full_history: bool,
    single_branch: bool,
) -> None:
    """Clone repositories with sparse checkout.

    REPOS_FILE contains one repository URL per line.
    Only .github/ directories are checked out for efficient scanning.

    By default, uses shallow clones (--depth=1) with all branches for minimal
    .git folder size while supporting multi-branch scanning.
    """
    from actions_scanner.git import SparseCloner, read_repos_file
    from actions_scanner.utils.console import (
        create_progress,
        is_terminal,
        print_error,
        print_info,
        print_success,
    )

    print_info(f"Reading repository list from {repos_file}...")
    repos = read_repos_file(repos_file)
    print_info(f"Found {len(repos)} repositories")

    cloner = SparseCloner(
        concurrency=workers,
        shallow=not full_history,
        single_branch=single_branch,
    )

    print_info(f"Cloning to {output_dir}...")
    if is_terminal():
        progress = create_progress()
        task_id = progress.add_task("Cloning", total=len(repos))

        def on_progress(completed: int, total: int, name: str, result) -> None:
            display_name = name[:40].ljust(40)
            progress.update(task_id, completed=completed, description=f"Cloning {display_name}")

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
@click.argument("org", type=str, required=False)
@click.option(
    "--org-file",
    type=click.Path(path_type=Path, exists=True),
    default=None,
    help="File containing newline-separated list of organizations to scan",
)
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
    "--no-protected",
    is_flag=True,
    help="Exclude permission-gated findings",
)
@click.option(
    "--no-labeled",
    is_flag=True,
    help="Exclude label-gated findings",
)
@click.option(
    "--include-same-repo",
    is_flag=True,
    help="Include same-repo-only findings (excluded by default)",
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
    "--full-history",
    is_flag=True,
    default=False,
    help="Fetch full git history instead of shallow clone (larger .git folders)",
)
@click.option(
    "--single-branch",
    is_flag=True,
    default=False,
    help="Only fetch default branch (smaller .git but no multi-branch scanning)",
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
    org: str | None,
    org_file: Path | None,
    output_dir: Path | None,
    output: Path | None,
    output_format: str,
    no_protected: bool,
    no_labeled: bool,
    include_same_repo: bool,
    include_forks: bool,
    include_archived: bool,
    clone_workers: int,
    full_history: bool,
    single_branch: bool,
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

    Either ORG or --org-file must be provided.

    Examples:

        actions-scanner scan-org ansible

        actions-scanner scan-org myorg --include-forks -d repos/myorg

        actions-scanner scan-org --org-file orgs.txt

        actions-scanner scan-org myorg --list-only

        actions-scanner scan-org myorg --all-branches --max-branches 5
    """
    from actions_scanner.core import ScanResult, scan_directory
    from actions_scanner.git import MultiBranchScanner, SparseCloner
    from actions_scanner.github import GitHubClient, OrgScanner
    from actions_scanner.reporting import (
        generate_csv_report,
        generate_json_report,
        generate_markdown_report,
    )
    from actions_scanner.utils.console import (
        create_progress,
        is_terminal,
        print_error,
        print_info,
        print_success,
        print_warning,
    )
    from actions_scanner.utils.path import resolve_repo_dir

    settings: Settings = ctx.obj["settings"]

    # Validate and parse organizations
    orgs: list[str] = []
    if org_file:
        orgs = [line.strip() for line in org_file.read_text().splitlines() if line.strip()]
        if not orgs:
            print_error(f"No organizations found in {org_file}")
            raise SystemExit(1)
        print_info(f"Found {len(orgs)} organizations in {org_file}")
    elif org:
        orgs = [org]
    else:
        print_error("Either ORG or --org-file must be provided")
        raise SystemExit(1)

    # Check for GitHub token
    token = settings.github.token
    if not token:
        import os

        token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print_error("GITHUB_TOKEN environment variable is required")
        raise SystemExit(1)

    if output_dir is None:
        output_dir = Path(tempfile.mkdtemp(prefix="actions-scanner-"))
        print_info(f"Using temporary directory {output_dir}")

    if is_terminal():
        progress = create_progress()
        task_id = progress.add_task("Discovering", total=len(orgs))
        repos_found = 0

        async def discover_repos() -> list[tuple[str, str]]:
            nonlocal repos_found
            async with GitHubClient(token=token, concurrency=settings.github.concurrency) as client:
                scanner = OrgScanner(client)
                all_repos: list[tuple[str, str]] = []
                for i, org_name in enumerate(orgs):

                    def on_page_progress(page: int, count: int, org_name: str = org_name) -> None:
                        nonlocal repos_found
                        repos_found = len(all_repos) + count
                        org_display = org_name[:30].ljust(30)
                        progress.update(
                            task_id,
                            description=f"Discovering {org_display} ({repos_found} repos)",
                        )

                    repos = await scanner.list_org_repos(
                        org_name,
                        include_archived=include_archived,
                        include_forks=include_forks,
                        on_progress=on_page_progress,
                    )
                    all_repos.extend((r.full_name, r.html_url) for r in repos)
                    repos_found = len(all_repos)
                    progress.update(task_id, completed=i + 1)
                return all_repos

        with progress:
            repos = asyncio.run(discover_repos())
    else:
        if len(orgs) == 1:
            print_info(f"Discovering repositories in '{orgs[0]}'...")
        else:
            print_info(f"Discovering repositories across {len(orgs)} organizations...")

        async def discover_repos() -> list[tuple[str, str]]:
            async with GitHubClient(token=token, concurrency=settings.github.concurrency) as client:
                scanner = OrgScanner(client)
                all_repos: list[tuple[str, str]] = []
                for org_name in orgs:
                    repos = await scanner.list_org_repos(
                        org_name,
                        include_archived=include_archived,
                        include_forks=include_forks,
                    )
                    all_repos.extend((r.full_name, r.html_url) for r in repos)
                return all_repos

        repos = asyncio.run(discover_repos())
    print_info(f"Found {len(repos)} repositories in {len(orgs)} organization(s)")
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
        print_info(f"Cloning {len(repo_info)} repositories to {output_dir}...")

        repo_urls = [url for _org, _repo, url in repo_info]

        cloner = SparseCloner(
            concurrency=clone_workers,
            shallow=not full_history,
            single_branch=single_branch,
        )

        if is_terminal():
            progress = create_progress()
            task_id = progress.add_task("Cloning", total=len(repo_urls))

            def on_progress(completed: int, total: int, name: str, result) -> None:
                display_name = name[:40].ljust(40)
                progress.update(task_id, completed=completed, description=f"Cloning {display_name}")

            with progress:
                asyncio.run(cloner.clone_repos(repo_urls, output_dir, on_progress=on_progress))
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
            path_result = scan_directory(scan_path)
            combined.vulnerabilities.extend(path_result.vulnerabilities)
            combined.files_scanned += path_result.files_scanned
            combined.errors.extend(path_result.errors)
    else:
        # Default: scan only default branch
        print_info(f"Scanning {len(repo_dirs)} repositories in {output_dir}...")

        for _org, _repo, repo_dir in repo_dirs:
            repo_result = scan_directory(repo_dir)
            combined.vulnerabilities.extend(repo_result.vulnerabilities)
            combined.files_scanned += repo_result.files_scanned
            combined.errors.extend(repo_result.errors)

    print_info(f"Scanned {combined.files_scanned} workflow files")
    print_info(f"Found {len(combined.vulnerabilities)} potential vulnerabilities")

    # Filter vulnerabilities based on flags
    vulns = combined.vulnerabilities
    excluded_protections: list[str] = []
    if no_protected:
        excluded_protections.append("permission")
    if no_labeled:
        excluded_protections.append("label")
    if not include_same_repo:
        excluded_protections.append("same_repo")
    if excluded_protections:
        vulns = [v for v in vulns if v.protection not in excluded_protections]
        print_info(
            f"Filtered to {len(vulns)} vulnerabilities (excluded: {', '.join(excluded_protections)})"
        )

    if output is None:
        output = _default_output_path(output_format)
    output.parent.mkdir(parents=True, exist_ok=True)

    # Generate report (include_protected=True since filtering is done above)
    if output_format == "csv":
        generate_csv_report(vulns, output, include_protected=True)
    elif output_format == "json":
        generate_json_report(vulns, output, include_protected=True, scan_base_dir=output_dir)
    else:
        generate_markdown_report(vulns, output, include_protected=True)

    print_success(f"Report written to {output}")

    # Print summary
    counts = combined.counts_by_protection
    console.print()
    console.print("[bold]Summary:[/bold]")
    orgs_display = (
        ", ".join(orgs) if len(orgs) <= 3 else f"{', '.join(orgs[:3])}, ... ({len(orgs)} total)"
    )
    console.print(f"  Organization(s):        {orgs_display}")
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
