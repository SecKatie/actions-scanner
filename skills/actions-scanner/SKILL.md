---
name: actions-scanner
description: Scan GitHub Actions workflows for PwnRequest and other CI/CD vulnerabilities. Use when the user wants to scan repositories, organizations, or local directories for GitHub Actions security issues like pull_request_target exploits, context injection, artifact injection, or dispatch checkout vulnerabilities.
---

# GitHub Actions Vulnerability Scanner

A security scanner that detects exploitable patterns in GitHub Actions workflows, focusing on PwnRequest attacks and related CI/CD supply chain vulnerabilities.

## Quick Reference

```bash
# Scan a single repo
actions-scanner scan owner/repo

# Scan a GitHub org (requires GITHUB_TOKEN)
actions-scanner scan-org myorg

# Scan a local directory
actions-scanner scan ./path/to/repo

# Scan repos from a file (one URL per line)
actions-scanner scan repos.txt

# Clone repos for analysis
actions-scanner clone repos.txt -d repos/

# Generate a markdown report from CSV results
actions-scanner report vulnerabilities.csv --format markdown

# AI-assisted validation of findings
actions-scanner validate vulnerabilities.csv
```

## What It Detects

The scanner identifies 6 vulnerability classes:

| Detector | Trigger | Risk |
|---|---|---|
| **PwnRequest** | `pull_request_target` + untrusted checkout + code execution | Secrets exfiltration via malicious PR |
| **WorkflowRun** | `workflow_run` + artifact injection | Code execution via poisoned artifacts |
| **ContextInjection** | `${{ }}` expressions in `run:` blocks using attacker-controlled inputs | Arbitrary command injection |
| **ArtifactInjection** | Reading artifact content into shell commands | Code execution via crafted artifacts |
| **DispatchCheckout** | `issue_comment`/`workflow_dispatch` + PR checkout | Code execution via comment-triggered builds |
| **MergedPR** | Patterns above but gated on merged PRs | Lower risk, requires merged code |

### Protection Levels

Each finding is classified by its protection level:

- **none** - Fully exploitable by any fork PR (critical)
- **label** - Requires a maintainer to add a label (social engineering vector)
- **permission** - Requires PR author to have write/admin access
- **same_repo** - Only triggers for PRs from the same repo, not forks
- **actor** - Restricted to specific bot actors
- **merged** - Only runs on already-merged PRs

## Commands

### `scan` - Primary Scanner

```bash
actions-scanner scan TARGET [OPTIONS]
```

**TARGET** accepts: GitHub org name, repo URL (`owner/repo` or full URL), local directory path, or a file with one target per line.

Key options:
- `-o, --output PATH` - Output file (default: `outputs/vulnerabilities.csv`)
- `--format csv|json|markdown` - Output format (default: csv)
- `--no-protected` - Exclude permission-gated findings
- `--no-labeled` - Exclude label-gated findings
- `--include-same-repo` - Include same-repo-only findings (excluded by default)
- `--all-branches` - Scan multiple branches via smart sampling
- `--max-branches N` - Max branches per repo (default: 10)
- `--validate` - Run AI validation after scanning
- `--clone-workers N` - Parallel clone workers (default: 5)

### `scan-org` - Organization Scanner

```bash
actions-scanner scan-org ORG [OPTIONS]
```

Discovers all repos in a GitHub organization, clones them with sparse checkout, and scans. Requires `GITHUB_TOKEN`.

Additional options:
- `--org-file PATH` - File with newline-separated org names
- `--include-forks` - Include forked repos
- `--include-archived` - Include archived repos
- `--list-only` - List repos without scanning
- `--skip-clone` - Scan existing clones in output-dir
- `-d, --output-dir PATH` - Clone destination

### `validate` - AI Validation

```bash
actions-scanner validate VULNERABILITIES_FILE [OPTIONS]
```

Uses an AI agent to confirm or reject findings. Produces per-repo confirmation files (`confirmed_vulnerable.txt`, `confirmed_weakness.txt`, `not_vulnerable.txt`).

Options:
- `-d, --repos-dir PATH` - Directory containing cloned repos
- `--agent TEMPLATE` - Custom agent command (e.g., `"codex -m gpt-4 -p {}"`)
- `-w, --workers N` - Parallel validation workers (default: 5)
- `--timeout SECS` - Per-repo timeout (default: 300)

### `clone` - Sparse Cloner

```bash
actions-scanner clone REPOS_FILE [OPTIONS]
```

Clones repos with sparse checkout (only `.github/` directory) for efficient scanning.

### `report` - Format Converter

```bash
actions-scanner report VULNERABILITIES_FILE [OPTIONS]
```

Converts vulnerability CSV to markdown or JSON.

## Common Workflows

### Scan a single org and get a markdown report

```bash
export GITHUB_TOKEN=ghp_...
actions-scanner scan-org myorg --format markdown -o report.md
```

### Scan multiple orgs from a file

```bash
# orgs.txt contains one org name per line
actions-scanner scan-org --org-file orgs.txt -d repos/ -o results.csv
```

### Scan with multi-branch coverage

```bash
actions-scanner scan owner/repo --all-branches --max-branches 5
```

### Full pipeline: scan then validate

```bash
actions-scanner scan-org myorg -o findings.json --format json
actions-scanner validate findings.json -d /tmp/actions-scanner-*/
```

### Scan a local checkout

```bash
git clone https://github.com/org/repo
actions-scanner scan ./repo
```

## Environment Variables

| Variable | Purpose |
|---|---|
| `GITHUB_TOKEN` | Required for org scanning and API access |
| `ANTHROPIC_API_KEY` | Required for AI validation with Claude |
| `ACTIONS_SCANNER_*` | Override any config setting (e.g., `ACTIONS_SCANNER_SCAN__WORKERS=20`) |

## Configuration

The scanner reads config from `.actions-scanner.yaml` in the working directory or parents:

```yaml
scan:
  workers: 10
  sparse_paths: [".github/"]

github:
  concurrency: 50
  timeout: 30

validation:
  command_template: 'claude -p "{}"'
  timeout: 300
  workers: 5

output:
  format: csv
  verbose: false
```

## Output Format

CSV columns: `vulnerability_type`, `org`, `repo`, `branch`, `workflow_path`, `job_name`, `checkout_line`, `checkout_ref`, `exec_line`, `exec_type`, `exec_value`, `protection`, `protection_detail`

## Development

```bash
# Install with dev dependencies
uv sync --dev

# Run tests
uv run pytest

# Lint
uv run ruff check src/

# Type check
uv run ty check src/
```

## Project Structure

```
src/actions_scanner/
  cli/main.py          # CLI entry point (click-based)
  core/
    detector.py        # 6 vulnerability detector classes
    models.py          # VulnerableJob, ScanResult models
    patterns.py        # Regex patterns for dangerous refs/commands
  config/settings.py   # Pydantic settings (YAML, env, CLI)
  git/                 # Sparse cloning, worktrees, multi-branch
  github/              # Async GitHub API client, org scanning
  reporting/           # CSV, JSON, markdown report generators
  validation/          # AI-assisted validation agent
  utils/               # Console, progress, path utilities
```
