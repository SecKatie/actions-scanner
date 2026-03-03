# Repository Guidelines

## Project Structure & Module Organization
- `src/actions_scanner/` houses the Python package:
  - `cli/` - Command-line interface entrypoint
  - `core/` - Detection logic and vulnerability patterns
  - `config/` - Settings management via Pydantic
  - `git/` - Repository cloning, worktrees, multi-branch scanning
  - `github/` - GitHub API client and org discovery
  - `reporting/` - CSV, JSON, and Markdown report generation
  - `validation/` - AI-assisted vulnerability confirmation
  - `enrichment/` - GitHub user and LDAP identity lookups
  - `utils/` - Console output, path handling, async helpers
- `tests/` is pytest-based; fixtures live in `tests/fixtures/workflows/`.
- Generated artifacts (CSV/JSON outputs, cloned repos, worktrees) are gitignored.

## Build, Test, and Development Commands
- `uv sync --all-extras` installs all dependencies including dev tools.
- `uv run actions-scanner --help` shows CLI usage and available commands.
- `uv run pytest` runs tests; `uv run pytest -m "not slow"` skips slow suites.
- `uv run ruff check src/ tests/` lints; `uv run ruff format src/ tests/` formats.
- `uv run ty check src/` runs type checking.
- `uv run pre-commit run --all-files` runs all pre-commit hooks.

## Coding Style & Naming Conventions
- Python: 4-space indent, 100-char lines, double quotes (Ruff formatter).
- Use type hints throughout; the package is marked as typed (`py.typed`).
- Names: modules/functions `snake_case`, classes `PascalCase`, constants `UPPER_CASE`.

## Testing Guidelines
- Pytest with markers: `slow`, `integration`.
- Test files are `tests/test_*.py`; sample workflows under `tests/fixtures/workflows/`.
- Pre-commit hooks require all tests to pass before committing.

## Commit & Pull Request Guidelines
- Commit messages are short, imperative, sentence case (e.g., "Add scanner CLI").
- PRs should explain behavior changes, list commands run, and link issues where applicable.
- Pre-commit hooks enforce linting, type checking, and tests.

## Configuration & Secrets
- Common env vars: `GITHUB_TOKEN`, `ANTHROPIC_API_KEY`.
- Configuration via `.actions-scanner.yaml` or environment variables (prefix: `ACTIONS_SCANNER_`).
- Do not commit scan outputs or repo lists; keep them in gitignored paths.

## Lola Skills

These skills are installed by Lola and provide specialized capabilities.
When a task matches a skill's description, read the skill's SKILL.md file
to learn the detailed instructions and workflows.

**How to use skills:**
1. Check if your task matches any skill description below
2. Use `read_file` to read the skill's SKILL.md for detailed instructions
3. Follow the instructions in the SKILL.md file

<!-- lola:skills:start -->
<!-- lola:skills:end -->
