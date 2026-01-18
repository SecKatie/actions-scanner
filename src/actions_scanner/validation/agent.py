"""AI-assisted validation agent for vulnerability confirmation."""
import asyncio
import shlex
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from actions_scanner.utils.path import make_paths_relative, resolve_repo_dir

from .models import ValidationOutput, ValidationResult, ValidationStats
from .prompts import build_validation_prompt


class ValidationAgent:
    """Runs customizable CLI agents to validate vulnerabilities.

    Supports any CLI tool that accepts a prompt, such as:
    - claude --dangerously-skip-permissions -p {}
    - codex -m gpt-4 -p {}
    - opencode -p {}

    Note: The {} placeholder will be replaced with a properly shell-quoted prompt.
    Do NOT include quotes around {} in the template.
    """

    def __init__(
        self,
        command_template: str = "claude --dangerously-skip-permissions -p {}",
        timeout: int = 300,
        custom_prompt_template: str | None = None,
    ):
        """Initialize the validation agent.

        Args:
            command_template: Command template with {} placeholder for prompt.
                             The prompt will be shell-quoted using shlex.quote().
                             Do NOT include quotes around {} - they are added automatically.
            timeout: Timeout for each validation in seconds.
            custom_prompt_template: Optional custom prompt template.
        """
        self.command_template = command_template
        self.timeout = timeout
        self.custom_prompt_template = custom_prompt_template

    def _build_command(self, prompt: str) -> str:
        """Build the full command with the prompt inserted.

        Uses shlex.quote() for proper POSIX shell quoting.
        """
        quoted_prompt = shlex.quote(prompt)
        return self.command_template.format(quoted_prompt)

    async def validate(
        self,
        org: str,
        repo: str,
        workflow_paths: list[str],
        working_dir: Path,
    ) -> ValidationOutput:
        """Run AI agent to validate vulnerabilities in a repo.

        The agent should create one of:
        - confirmed_vulnerable.txt
        - confirmed_weakness.txt
        - not_vulnerable.txt

        Args:
            org: Repository organization
            repo: Repository name
            workflow_paths: List of workflow file paths relative to working_dir
            working_dir: Working directory for the agent

        Returns:
            ValidationOutput with the result
        """
        start_time = time.time()

        # Build prompt
        prompt = build_validation_prompt(
            org=org,
            repo=repo,
            workflow_paths=workflow_paths,
            custom_template=self.custom_prompt_template,
        )

        # Build command
        command = self._build_command(prompt)

        try:
            # Run the command
            proc = await asyncio.create_subprocess_shell(
                command,
                cwd=working_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
            except TimeoutError:
                proc.kill()
                await proc.wait()
                return ValidationOutput(
                    org=org,
                    repo=repo,
                    result=ValidationResult.FAILED,
                    workflow_paths=workflow_paths,
                    error="Validation timed out",
                    duration_seconds=time.time() - start_time,
                )

            # Determine result based on output files
            result, output_file = self._check_output_files(working_dir)

            return ValidationOutput(
                org=org,
                repo=repo,
                result=result,
                workflow_paths=workflow_paths,
                output_file=output_file,
                duration_seconds=time.time() - start_time,
            )

        except Exception as e:
            return ValidationOutput(
                org=org,
                repo=repo,
                result=ValidationResult.FAILED,
                workflow_paths=workflow_paths,
                error=str(e),
                duration_seconds=time.time() - start_time,
            )

    def _check_output_files(self, working_dir: Path) -> tuple[ValidationResult, Path | None]:
        """Check which output file was created by the agent.

        Args:
            working_dir: Directory to check for output files

        Returns:
            Tuple of (ValidationResult, output_file_path)
        """
        vulnerable_file = working_dir / "confirmed_vulnerable.txt"
        weakness_file = working_dir / "confirmed_weakness.txt"
        not_vulnerable_file = working_dir / "not_vulnerable.txt"

        if vulnerable_file.exists():
            return ValidationResult.VULNERABLE, vulnerable_file
        elif weakness_file.exists():
            return ValidationResult.WEAKNESS, weakness_file
        elif not_vulnerable_file.exists():
            return ValidationResult.FALSE_POSITIVE, not_vulnerable_file
        else:
            return ValidationResult.FAILED, None


class BatchValidationRunner:
    """Runs validation across multiple repositories in parallel."""

    def __init__(
        self,
        agent: ValidationAgent,
        concurrency: int = 3,
    ):
        """Initialize the batch runner.

        Args:
            agent: ValidationAgent to use for validation
            concurrency: Maximum concurrent validations
        """
        self.agent = agent
        self.concurrency = concurrency
        self.stats = ValidationStats()

    async def validate_repos(
        self,
        repos: list[dict],
        base_dir: Path,
        on_progress: Callable[..., Any] | None = None,
    ) -> list[ValidationOutput]:
        """Validate multiple repositories.

        Args:
            repos: List of dicts with keys: org, repo, workflow_paths
            base_dir: Base directory containing repo analysis directories
            on_progress: Optional callback(completed, total, result)

        Returns:
            List of ValidationOutput objects
        """
        semaphore = asyncio.Semaphore(self.concurrency)
        results: list[ValidationOutput] = []
        lock = asyncio.Lock()
        completed = 0
        total = len(repos)

        async def validate_with_progress(repo_info: dict) -> ValidationOutput:
            nonlocal completed
            async with semaphore:
                org = repo_info["org"]
                repo = repo_info["repo"]
                workflow_paths = repo_info.get("workflow_paths", [])

                working_dir, found = resolve_repo_dir(base_dir, org, repo)
                if not found and not working_dir.exists():
                    return ValidationOutput(
                        org=org,
                        repo=repo,
                        result=ValidationResult.FAILED,
                        workflow_paths=workflow_paths,
                        error="Repository directory not found",
                    )

                normalized_paths = make_paths_relative(
                    workflow_paths,
                    working_dir=working_dir,
                    base_dir=base_dir,
                )

                result = await self.agent.validate(
                    org=org,
                    repo=repo,
                    workflow_paths=normalized_paths,
                    working_dir=working_dir,
                )

                async with lock:
                    completed += 1
                    self.stats.record(result.result)
                    results.append(result)
                    if on_progress:
                        on_progress(completed, total, result)

                return result

        await asyncio.gather(
            *[validate_with_progress(repo) for repo in repos],
            return_exceptions=True,
        )

        return results

    def get_stats(self) -> ValidationStats:
        """Get validation statistics."""
        return self.stats
