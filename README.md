# GitHub Actions PwnRequest Vulnerability Scanner

A toolkit for detecting GitHub Actions workflows vulnerable to the [PwnRequest](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/) attack pattern — where `pull_request_target` workflows check out and execute untrusted PR code, allowing secret exfiltration.

> [!CAUTION]
> Use findings responsibly and follow responsible disclosure practices.

## Installation

```bash
uv tool install git+https://github.com/SecKatie/actions-scanner.git
```

## Usage

```bash
# Scan an org, repo URL, local directory, or list file (default format: csv)
actions-scanner scan your-org -o results.csv

# Export to markdown
actions-scanner report results.csv -o report.md --format markdown
```

## What It Detects

The scanner flags workflows where all three conditions exist in the same job:

1. **Trigger:** `pull_request_target` (runs with write permissions and secrets)
2. **Checkout:** Untrusted PR ref (`head.sha`, `head.ref`, `merge_commit_sha`, `github.head_ref`)
3. **Execution:** Build commands (`npm install`, `make`, `pip install`, `docker build`, etc.) or local actions (`./action`)

## Development

**Prerequisites:** Python 3.11+, [uv](https://github.com/astral-sh/uv), `gh` CLI (authenticated), `git`

```bash
git clone https://github.com/SecKatie/actions-scanner.git && cd actions-scanner
uv sync
uv run pytest tests/ -v
```

### Environment Variables

| Variable | Description |
|---|---|
| `GITHUB_TOKEN` | GitHub personal access token (required for org scanning) |

## References

- [GitHub Security Lab: Preventing pwn requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)
- [GitHub Docs: Security hardening for GitHub Actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)

## License

MIT License. See [LICENSE](LICENSE) for details.
