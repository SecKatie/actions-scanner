# Repository Guidelines

## Project Structure & Module Organization
- `src/actions_scanner/` houses the Python package: `cli/` entrypoint, `core/` detection, `config/`, `reporting/`, `utils/`.
- `scripts/` contains end-to-end tooling (repo discovery, cloning, scanning, enrichment).
- `tests/` is pytest-based; fixtures live in `tests/fixtures/workflows/`.
- Generated artifacts land in `scan-output.txt/`, `.worktrees/`, and CSV/JSON outputs (gitignored).

## Build, Test, and Development Commands
- `uv sync --extra dev` installs dev dependencies; `uv sync` for runtime only.
- `uv run actions-scanner --help` shows CLI usage and options.
- `uv run scripts/clone_repos.py repos.txt` clones workflow files; `uv run scripts/scan_repos_async.py` runs the scanner.
- `uv run pytest` runs tests; `uv run pytest -m "not slow"` skips slow suites.
- `uv run ruff check src tests` lints; `uv run ruff format src tests` formats.
- Optional JS helper: `npm install` then `node scripts/analyze-workflows.js`.

## Coding Style & Naming Conventions
- Python: 4-space indent, 100-char lines, double quotes (Ruff formatter).
- Use type hints where practical; keep public API exports in `__init__.py` minimal.
- Names: modules/functions `snake_case`, classes `PascalCase`, constants `UPPER_CASE`.

## Testing Guidelines
- Pytest with markers: `slow`, `integration`.
- Test files are `tests/test_*.py`; sample workflows under `tests/fixtures/workflows/`.

## Commit & Pull Request Guidelines
- Commit messages are short, imperative, sentence case (e.g., "Add scanner CLI").
- PRs should explain behavior changes, list commands run, and link issues where applicable; include sample outputs only when they clarify results.

## Configuration & Secrets
- Common env vars: `GITHUB_TOKEN`, `ANTHROPIC_API_KEY`, `SCAN_WORKERS`, `SCAN_LIMIT`.
- Do not commit scan outputs or repo lists; keep them in gitignored paths/files.
