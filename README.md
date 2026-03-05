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

The scanner identifies five vulnerability classes across GitHub Actions workflows:

### 1. PwnRequest (`pull_request_target` + untrusted checkout + execution)

Flags jobs where all three conditions exist:

- **Trigger:** `pull_request_target` (runs with write permissions and secrets)
- **Checkout of untrusted ref:** any of the following in an `actions/checkout` `ref:` parameter:
  - `github.event.pull_request.head.ref` / `.sha` / `.merge_commit_sha`
  - `github.head_ref`
  - `refs/pull/${{ github.event.pull_request.number }}/head` or `/merge`
  - `format('refs/pull/{0}/...', ...)` patterns
  - `fromJson(inputs.github).event.pull_request.head.ref/sha` (reusable workflow passthrough)
  - Checkout of a fork's repository via `github.event.pull_request.head.repo.*`
- **Dangerous execution** in the same job (see [Execution Patterns](#execution-patterns) below)

### 2. `workflow_run` Injection

Flags jobs triggered by `workflow_run` that checkout or use attacker-controlled data from the triggering workflow:

- Checkout using `github.event.workflow_run.head_sha`, `.head_branch`, or `pull_requests[*].head.ref/sha`
- Direct `git checkout` of the triggering commit
- **Artifact injection:** downloading artifacts from the triggering run (via `github.event.workflow_run.id`) and reading their content into shell commands unsafely (e.g. `$(cat file)`, `` `cat file` ``, `source file`)

### 3. Context Injection (Script Injection)

Flags workflows where attacker-controlled GitHub context values are interpolated directly into `run:` blocks via `${{ }}` expressions. Covered triggers and contexts:

| Trigger | Injectable contexts |
|---|---|
| `pull_request_target` | `github.head_ref`, `github.event.pull_request.head.ref/label/title/body`, `github.event.comment.body`, `github.event.review.body`, `github.event.issue.title/body` |
| `workflow_run` | `github.event.workflow_run.head_branch`, `.head_commit.message/author.name/author.email`, `.display_title`, `.pull_requests[*].head.ref` |
| `issues` | `github.event.issue.title/body/user.name` |
| `issue_comment` | `github.event.comment.body/user.name`, `github.event.issue.title/body` |
| `discussion` / `discussion_comment` | `github.event.discussion.title/body/user.name`, `github.event.comment.body/user.name` |

### 4. Dispatch Checkout

Flags `issue_comment` or `workflow_dispatch` workflows that dynamically check out PR code based on an issue or PR number from the event context, allowing an attacker's PR code to run with elevated privileges.

### 5. Execution Patterns

The following commands are considered dangerous execution when found in a job that also checks out untrusted code:

| Category | Commands |
|---|---|
| JavaScript / Node | `npm`, `yarn`, `pnpm`, `npx`, `node`, `deno`, `bun` |
| Python | `pip`, `python`/`python3`, `pytest`, `tox`, `poetry`, `uv run/sync/pip`, `pdm run/install`, `hatch run`, `rye run`, `pixi run`, `pre-commit` |
| Go | `go build/run/test/install/mod` |
| Rust | `cargo`, `rustc` |
| Java / JVM | `mvn`, `gradle`, `ant`, `sbt` (Scala), `lein` (Clojure) |
| Ruby | `bundle`, `gem`, `rake`, `rails` |
| PHP | `composer`, `phpunit` |
| Swift | `swift build/run/test` |
| Elixir | `mix`, `elixir` |
| Haskell | `cabal`, `stack` |
| Shell | `bash`, `sh`, `source`, `. script.sh`, `./` (local scripts/actions) |
| Build systems | `make`, `cmake`, `meson` |
| Containers | `docker build`, `docker-compose`, `podman build` |
| Infrastructure as Code | `terraform`, `terramate`, `pulumi`, `helm`, `kubectl apply`, `ansible`/`ansible-playbook` |
| Nix / devbox | `devbox run`, `nix run/shell/develop`, `nix-shell` |

---

## Protection Level Classification

Each finding is rated by how well it is protected against exploitation:

| Level | Meaning |
|---|---|
| `none` | Fully exploitable — any PR from a fork can trigger |
| `label` | Requires a maintainer to add a label (social-engineering vector, still flagged) |
| `permission` | Requires PR author to have write/admin/maintain access |
| `same_repo` | Only runs for PRs from the same repo (not forks) |
| `actor` | Only runs for specific bot actors (e.g. `dependabot[bot]`) |
| `merged` | Only runs after the PR is merged (code already reviewed) |
| `environment` | Job targets a GitHub environment with deployment protection rules |
| `safe_usage` | Artifact data is extracted safely (e.g. via `jq`) — not exploitable |
| `dispatch_fallback` | Ref falls back to a `workflow_dispatch` input (requires repo write access) |

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
