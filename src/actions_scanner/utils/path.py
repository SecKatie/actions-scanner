"""Path and identifier helpers."""

from pathlib import Path
from urllib.parse import quote, unquote

_BASE_DIR_NAMES = {
    "repos",
    "repos-test",
    "scan-output.txt",
    "scan-output",
    "worktrees",
    "worktree",
    "tmp",
    "output",
}

_COMMON_BRANCHES = {
    "main",
    "master",
    "develop",
    "dev",
    "trunk",
    "default",
    "stable",
    "release",
    "beta",
    "staging",
    "prod",
    "production",
}

_BRANCH_PREFIXES = (
    "feature",
    "feat",
    "fix",
    "bugfix",
    "hotfix",
    "release",
    "dependabot",
    "renovate",
    "chore",
)


def _normalize_path(path_str: str) -> str:
    return path_str.replace("\\", "/")


def _looks_like_branch(name: str) -> bool:
    lower = name.lower()
    if lower in _COMMON_BRANCHES:
        return True
    return any(lower.startswith(prefix) for prefix in _BRANCH_PREFIXES)


def extract_org_repo_from_path(path_str: str) -> tuple[str, str]:
    """Extract org and repo from a workflow path."""
    if not path_str:
        return "", ""

    org, repo, _branch = extract_org_repo_branch_from_path(path_str)
    if org or repo:
        return org, repo

    parts = [p for p in _normalize_path(path_str).split("/") if p]
    for i, part in enumerate(parts):
        if part != ".github":
            continue

        if i >= 1:
            repo_part = parts[i - 1]
            if "__" in repo_part:
                org, repo = repo_part.split("__", 1)
                return org, repo

        if i >= 2:
            repo_part = parts[i - 2]
            if "__" in repo_part:
                org, repo = repo_part.split("__", 1)
                return org, repo

        if i >= 1:
            repo_part = parts[i - 1]
            org_part = parts[i - 2] if i >= 2 else ""
            if "-" in repo_part and org_part in _BASE_DIR_NAMES:
                org, repo = repo_part.split("-", 1)
                return org, repo

        if i >= 2:
            repo_part = parts[i - 2]
            org_part = parts[i - 3] if i >= 3 else ""
            if "-" in repo_part and org_part in _BASE_DIR_NAMES:
                org, repo = repo_part.split("-", 1)
                return org, repo

        if i >= 4 and parts[i - 4] in _BASE_DIR_NAMES:
            return parts[i - 3], parts[i - 2]

        if i >= 3 and _looks_like_branch(parts[i - 1]):
            return parts[i - 3], parts[i - 2]

        if i >= 2:
            return parts[i - 2], parts[i - 1]

        if i >= 1:
            return "", parts[i - 1]

    return "", ""


def encode_branch(branch: str) -> str:
    """Encode a branch name for safe filesystem usage."""
    return quote(branch, safe="")


def decode_branch(encoded: str) -> str:
    """Decode a previously encoded branch name."""
    return unquote(encoded)


def extract_org_repo_branch_from_path(path_str: str) -> tuple[str, str, str]:
    """Extract org, repo, and branch from a workflow or repo path."""
    if not path_str:
        return "", "", ""

    parts = [p for p in _normalize_path(path_str).split("/") if p]
    for i, part in enumerate(parts):
        if part != "code":
            continue

        if i >= 3:
            org = parts[i - 3]
            repo = parts[i - 2]
            branch = decode_branch(parts[i - 1])
            return org, repo, branch

    for i, part in enumerate(parts):
        if part != ".github":
            continue

        if i >= 3:
            candidate_branch = decode_branch(parts[i - 1])
            if _looks_like_branch(candidate_branch) or "%" in parts[i - 1]:
                org = parts[i - 3]
                repo = parts[i - 2]
                return org, repo, candidate_branch

    return "", "", ""


def repo_display_name(path_str: str) -> str:
    """Get a display-friendly repo name from a workflow path."""
    org, repo = extract_org_repo_from_path(path_str)
    if org and repo:
        return f"{org}/{repo}"
    if repo:
        return repo
    return "unknown"


def resolve_repo_dir(
    base_dir: Path, org: str, repo: str, branch: str | None = None
) -> tuple[Path, bool]:
    """Resolve the most likely repo directory under base_dir."""
    candidates: list[Path] = []
    if org and repo:
        if branch:
            encoded = encode_branch(branch)
            candidates.extend(
                [
                    base_dir / org / repo / encoded / "code",
                    base_dir / f"{org}__{repo}" / encoded / "code",
                    base_dir / f"{org}-{repo}" / encoded / "code",
                ]
            )
        candidates.extend(
            [
                base_dir / f"{org}__{repo}",
                base_dir / f"{org}-{repo}",
                base_dir / org / repo,
            ]
        )
        # Also look for branch/code subdirs created by SparseCloner
        # SparseCloner creates: base_dir / org / repo / branch_encoded / code
        org_repo_base = base_dir / org / repo
        if org_repo_base.exists():
            # Check for common default branches
            for branch_name in ("main", "master", "develop", "dev"):
                encoded = encode_branch(branch_name)
                code_dir = org_repo_base / encoded / "code"
                if code_dir.exists():
                    return code_dir, True
            # Check any subdirectory that might be a branch/code dir
            for child in org_repo_base.iterdir():
                if child.is_dir():
                    code_subdir = child / "code"
                    if code_subdir.exists() and (code_subdir / ".github").exists():
                        return code_subdir, True
    if repo:
        candidates.append(base_dir / repo)

    for candidate in candidates:
        if candidate.exists():
            return candidate, True

    if candidates:
        return candidates[0], False

    return base_dir, False


def make_paths_relative(
    paths: list[str],
    working_dir: Path,
    base_dir: Path | None = None,
) -> list[str]:
    """Normalize workflow paths to be relative to working_dir."""
    working_norm = _normalize_path(working_dir.as_posix()).rstrip("/")
    base_norm = _normalize_path(base_dir.as_posix()).rstrip("/") if base_dir else ""
    working_rel = ""
    if base_norm and working_norm.startswith(f"{base_norm}/"):
        working_rel = working_norm[len(base_norm) + 1 :]

    normalized: list[str] = []
    for path_str in paths:
        path_norm = _normalize_path(path_str).lstrip("./")
        rel = None

        if working_norm and path_norm.startswith(f"{working_norm}/"):
            rel = path_norm[len(working_norm) + 1 :]
        elif base_norm and path_norm.startswith(f"{base_norm}/"):
            rel = path_norm[len(base_norm) + 1 :]
            if working_rel and rel.startswith(f"{working_rel}/"):
                rel = rel[len(working_rel) + 1 :]

        normalized.append(rel if rel else path_norm)

    return normalized
