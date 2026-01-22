"""Tests for the validation module.

Tests the AI-assisted validation workflow:
1. ValidationAgent builds prompts and runs CLI agents
2. Agent creates output files (confirmed_vulnerable.txt, etc.)
3. Validator parses output files and extracts frontmatter
4. BatchValidationRunner coordinates parallel validation
"""

import asyncio
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from actions_scanner.validation.agent import BatchValidationRunner, ValidationAgent
from actions_scanner.validation.models import ValidationOutput, ValidationResult, ValidationStats
from actions_scanner.validation.prompts import build_validation_prompt


class TestValidationAgent:
    """Tests for ValidationAgent class."""

    @pytest.fixture
    def agent(self) -> ValidationAgent:
        """Create a validation agent."""
        return ValidationAgent(
            command_template="echo {}",  # Simple mock command
            timeout=10,
        )

    def test_build_command_quotes_prompt(self, agent: ValidationAgent) -> None:
        """Test that prompts are properly shell-quoted."""
        prompt = "Test prompt with 'quotes' and $variables"
        command = agent._build_command(prompt)

        # Should contain the echo command with quoted prompt
        assert command.startswith("echo ")
        # shlex.quote wraps in single quotes and escapes internal quotes
        assert "'" in command

    def test_check_output_files_vulnerable(self, agent: ValidationAgent, tmp_path: Path) -> None:
        """Test detection of confirmed_vulnerable.txt."""
        (tmp_path / "confirmed_vulnerable.txt").write_text("Vulnerable!")

        result, output_file = agent._check_output_files(tmp_path)

        assert result == ValidationResult.VULNERABLE
        assert output_file == tmp_path / "confirmed_vulnerable.txt"

    def test_check_output_files_weakness(self, agent: ValidationAgent, tmp_path: Path) -> None:
        """Test detection of confirmed_weakness.txt."""
        (tmp_path / "confirmed_weakness.txt").write_text("Weakness found")

        result, output_file = agent._check_output_files(tmp_path)

        assert result == ValidationResult.WEAKNESS
        assert output_file == tmp_path / "confirmed_weakness.txt"

    def test_check_output_files_false_positive(
        self, agent: ValidationAgent, tmp_path: Path
    ) -> None:
        """Test detection of not_vulnerable.txt."""
        (tmp_path / "not_vulnerable.txt").write_text("False positive")

        result, output_file = agent._check_output_files(tmp_path)

        assert result == ValidationResult.FALSE_POSITIVE
        assert output_file == tmp_path / "not_vulnerable.txt"

    def test_check_output_files_none(self, agent: ValidationAgent, tmp_path: Path) -> None:
        """Test when no output file exists."""
        result, output_file = agent._check_output_files(tmp_path)

        assert result == ValidationResult.FAILED
        assert output_file is None

    def test_check_output_files_priority(self, agent: ValidationAgent, tmp_path: Path) -> None:
        """Test that vulnerable takes priority over other files."""
        # Create multiple files - vulnerable should win
        (tmp_path / "confirmed_vulnerable.txt").write_text("Vulnerable!")
        (tmp_path / "confirmed_weakness.txt").write_text("Weakness")
        (tmp_path / "not_vulnerable.txt").write_text("False positive")

        result, _output_file = agent._check_output_files(tmp_path)

        assert result == ValidationResult.VULNERABLE

    def test_parse_frontmatter_valid(self, agent: ValidationAgent, tmp_path: Path) -> None:
        """Test parsing valid YAML frontmatter."""
        output_file = tmp_path / "confirmed_vulnerable.txt"
        output_file.write_text("""---
issue_type: vulnerability
cvss: 8.5
cwe: CWE-94
summary: "Command injection via PR title"
confidence: high
---

## Analysis

The workflow is vulnerable because...""")

        frontmatter = agent._parse_frontmatter(output_file)

        assert frontmatter["issue_type"] == "vulnerability"
        assert frontmatter["cvss"] == "8.5"
        assert frontmatter["cwe"] == "CWE-94"
        assert frontmatter["summary"] == "Command injection via PR title"
        assert frontmatter["confidence"] == "high"

    def test_parse_frontmatter_no_frontmatter(self, agent: ValidationAgent, tmp_path: Path) -> None:
        """Test parsing file without frontmatter."""
        output_file = tmp_path / "confirmed_vulnerable.txt"
        output_file.write_text("No frontmatter here, just content.")

        frontmatter = agent._parse_frontmatter(output_file)

        assert frontmatter == {}

    def test_parse_frontmatter_partial(self, agent: ValidationAgent, tmp_path: Path) -> None:
        """Test parsing partial frontmatter."""
        output_file = tmp_path / "confirmed_vulnerable.txt"
        output_file.write_text("""---
issue_type: vulnerability
cvss: 7.0
---

Content here.""")

        frontmatter = agent._parse_frontmatter(output_file)

        assert frontmatter["issue_type"] == "vulnerability"
        assert frontmatter["cvss"] == "7.0"
        assert "cwe" not in frontmatter

    def test_parse_frontmatter_none_file(self, agent: ValidationAgent) -> None:
        """Test parsing when file is None."""
        frontmatter = agent._parse_frontmatter(None)
        assert frontmatter == {}

    def test_parse_cvss_valid(self, agent: ValidationAgent) -> None:
        """Test parsing valid CVSS score."""
        assert agent._parse_cvss("8.5") == 8.5
        assert agent._parse_cvss("10.0") == 10.0
        assert agent._parse_cvss("0") == 0.0

    def test_parse_cvss_invalid(self, agent: ValidationAgent) -> None:
        """Test parsing invalid CVSS score."""
        assert agent._parse_cvss("invalid") is None
        assert agent._parse_cvss(None) is None
        assert agent._parse_cvss("") is None

    def test_issue_type_from_result(self, agent: ValidationAgent) -> None:
        """Test issue type mapping from result."""
        assert agent._issue_type_from_result(ValidationResult.VULNERABLE) == "vulnerability"
        assert agent._issue_type_from_result(ValidationResult.WEAKNESS) == "weakness"
        assert agent._issue_type_from_result(ValidationResult.FALSE_POSITIVE) == "false_positive"
        assert agent._issue_type_from_result(ValidationResult.FAILED) == "unknown"


class TestValidationPrompts:
    """Tests for validation prompt building."""

    def test_build_validation_prompt(self) -> None:
        """Test building a validation prompt."""
        prompt = build_validation_prompt(
            org="test-org",
            repo="test-repo",
            workflow_paths=[".github/workflows/ci.yml", ".github/workflows/release.yml"],
        )

        assert "test-org/test-repo" in prompt
        assert ".github/workflows/ci.yml" in prompt
        assert ".github/workflows/release.yml" in prompt
        assert "confirmed_vulnerable.txt" in prompt
        assert "confirmed_weakness.txt" in prompt
        assert "not_vulnerable.txt" in prompt

    def test_build_validation_prompt_custom_template(self) -> None:
        """Test building prompt with custom template."""
        custom = "Analyze {org}/{repo} workflows:\n{workflow_list}"
        prompt = build_validation_prompt(
            org="my-org",
            repo="my-repo",
            workflow_paths=["workflow.yml"],
            custom_template=custom,
        )

        assert prompt == "Analyze my-org/my-repo workflows:\n  - workflow.yml"


class TestValidationStats:
    """Tests for ValidationStats class."""

    def test_record_vulnerable(self) -> None:
        """Test recording vulnerable result."""
        stats = ValidationStats()
        stats.record(ValidationResult.VULNERABLE)

        assert stats.total == 1
        assert stats.vulnerable == 1
        assert stats.weakness == 0
        assert stats.false_positive == 0
        assert stats.failed == 0

    def test_record_multiple(self) -> None:
        """Test recording multiple results."""
        stats = ValidationStats()
        stats.record(ValidationResult.VULNERABLE)
        stats.record(ValidationResult.VULNERABLE)
        stats.record(ValidationResult.WEAKNESS)
        stats.record(ValidationResult.FALSE_POSITIVE)
        stats.record(ValidationResult.FAILED)

        assert stats.total == 5
        assert stats.vulnerable == 2
        assert stats.weakness == 1
        assert stats.false_positive == 1
        assert stats.failed == 1

    def test_success_rate(self) -> None:
        """Test success rate calculation."""
        stats = ValidationStats()
        stats.record(ValidationResult.VULNERABLE)
        stats.record(ValidationResult.WEAKNESS)
        stats.record(ValidationResult.FALSE_POSITIVE)
        stats.record(ValidationResult.FAILED)

        # 3 successful (non-failed) out of 4 total = 75%
        assert stats.success_rate == 75.0

    def test_success_rate_empty(self) -> None:
        """Test success rate with no results."""
        stats = ValidationStats()
        assert stats.success_rate == 0.0


class TestValidationOutput:
    """Tests for ValidationOutput class."""

    def test_to_dict(self) -> None:
        """Test converting output to dict."""
        output = ValidationOutput(
            org="test-org",
            repo="test-repo",
            branch="main",
            result=ValidationResult.VULNERABLE,
            workflow_paths=[".github/workflows/ci.yml"],
            output_file=Path("/tmp/confirmed_vulnerable.txt"),
            issue_type="vulnerability",
            cvss=8.5,
            cwe="CWE-94",
            summary="Command injection",
            confidence="high",
            duration_seconds=5.5,
        )

        d = output.to_dict()

        assert d["org"] == "test-org"
        assert d["repo"] == "test-repo"
        assert d["branch"] == "main"
        assert d["result"] == "vulnerable"
        assert d["workflow_paths"] == [".github/workflows/ci.yml"]
        assert d["confirmation_file"] == "/tmp/confirmed_vulnerable.txt"
        assert d["issue_type"] == "vulnerability"
        assert d["cvss"] == 8.5
        assert d["cwe"] == "CWE-94"
        assert d["summary"] == "Command injection"
        assert d["confidence"] == "high"
        assert d["duration_seconds"] == 5.5

    def test_to_dict_no_output_file(self) -> None:
        """Test converting output with no file to dict."""
        output = ValidationOutput(
            org="test-org",
            repo="test-repo",
            result=ValidationResult.FAILED,
            error="Timeout",
        )

        d = output.to_dict()

        assert d["confirmation_file"] is None
        assert d["error"] == "Timeout"


class TestBatchValidationRunner:
    """Tests for BatchValidationRunner class."""

    @pytest.fixture
    def mock_agent(self) -> ValidationAgent:
        """Create a mock validation agent."""
        agent = ValidationAgent(command_template="echo {}", timeout=10)
        return agent

    @pytest.mark.asyncio
    async def test_validate_repos_missing_dir(
        self, mock_agent: ValidationAgent, tmp_path: Path
    ) -> None:
        """Test validation when repo directory doesn't exist.

        Note: Current implementation returns early without adding to results list
        when directory is not found. This test documents that behavior.
        """
        runner = BatchValidationRunner(agent=mock_agent, concurrency=1)

        repos = [
            {
                "org": "test-org",
                "repo": "nonexistent-repo",
                "branch": "main",
                "workflow_paths": [".github/workflows/ci.yml"],
            }
        ]

        results = await runner.validate_repos(repos, tmp_path)

        # Current behavior: missing dirs are not included in results
        # (early return doesn't add to results list)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_validate_repos_with_working_dir(
        self, mock_agent: ValidationAgent, tmp_path: Path
    ) -> None:
        """Test validation with explicit working_dir that exists."""
        # Create the repo directory
        repo_dir = tmp_path / "test-org" / "test-repo"
        workflows_dir = repo_dir / ".github" / "workflows"
        workflows_dir.mkdir(parents=True)
        (workflows_dir / "ci.yml").write_text("name: CI\non: push\n")

        runner = BatchValidationRunner(agent=mock_agent, concurrency=1)

        async def mock_validate(*args, **kwargs):
            working_dir = kwargs.get("working_dir") or args[4]
            output_file = working_dir / "confirmed_vulnerable.txt"
            output_file.write_text("---\nissue_type: vulnerability\n---\n")
            return ValidationOutput(
                org="test-org",
                repo="test-repo",
                branch="main",
                result=ValidationResult.VULNERABLE,
                workflow_paths=[".github/workflows/ci.yml"],
                output_file=output_file,
                issue_type="vulnerability",
            )

        with patch.object(mock_agent, "validate", side_effect=mock_validate):
            repos = [
                {
                    "org": "test-org",
                    "repo": "test-repo",
                    "branch": "main",
                    "workflow_paths": [".github/workflows/ci.yml"],
                    "working_dir": repo_dir,
                }
            ]

            results = await runner.validate_repos(repos, tmp_path)

        assert len(results) == 1
        assert results[0].result == ValidationResult.VULNERABLE
        assert results[0].org == "test-org"


class TestValidationE2E:
    """End-to-end tests for the validation workflow."""

    @pytest.fixture
    def mock_repo_with_workflow(self, tmp_path: Path) -> Path:
        """Create a mock repo structure with a vulnerable workflow."""
        repo_dir = tmp_path / "repos" / "test-org" / "test-repo"
        workflows_dir = repo_dir / ".github" / "workflows"
        workflows_dir.mkdir(parents=True)

        # Create a vulnerable workflow
        workflow_content = """name: CI
on:
  pull_request_target:

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm install && npm test
"""
        (workflows_dir / "ci.yml").write_text(workflow_content)
        return repo_dir

    @pytest.fixture
    def vulnerabilities_json(self, tmp_path: Path, mock_repo_with_workflow: Path) -> Path:
        """Create a vulnerabilities JSON file."""
        vuln_file = tmp_path / "vulnerabilities.json"
        workflow_path = str(mock_repo_with_workflow / ".github" / "workflows" / "ci.yml")

        data = {
            "metadata": {
                "scan_base_dir": str(tmp_path / "repos"),
            },
            "vulnerabilities": [
                {
                    "org": "test-org",
                    "repo": "test-repo",
                    "branch": "",
                    "workflow_path": workflow_path,
                    "job_name": "build",
                    "vulnerability_type": "pwnrequest",
                    "protection": "none",
                }
            ],
        }

        vuln_file.write_text(json.dumps(data, indent=2))
        return vuln_file

    @pytest.mark.asyncio
    async def test_e2e_validation_with_mock_agent(
        self, mock_repo_with_workflow: Path, vulnerabilities_json: Path, tmp_path: Path
    ) -> None:
        """E2E test: validate a workflow using a mock agent that creates output files.

        This test simulates the full validation workflow:
        1. Agent receives prompt with workflow paths
        2. Agent analyzes workflows (mocked)
        3. Agent creates confirmed_vulnerable.txt with frontmatter
        4. Validator reads output file and extracts result
        """

        # Create a mock agent that writes output files
        async def mock_validate(
            org: str,
            repo: str,
            branch: str,
            workflow_paths: list[str],
            working_dir: Path,
        ) -> ValidationOutput:
            # Simulate agent creating output file
            output_file = working_dir / "confirmed_vulnerable.txt"
            output_file.write_text("""---
issue_type: vulnerability
cvss: 9.0
cwe: CWE-94
summary: "PwnRequest vulnerability allows code execution"
confidence: high
---

## Workflow: .github/workflows/ci.yml

### Vulnerability Pattern Found
- Line 3: pull_request_target trigger
- Line 9: Checkout of untrusted code (head.sha)
- Line 11: npm install executes attacker code

### Secrets/Permissions at Risk
- GITHUB_TOKEN with default permissions
- Any secrets passed to npm scripts

### Exploitation Steps
1. Fork the repository
2. Create PR with malicious package.json
3. npm install runs attacker's preinstall script
4. Exfiltrate secrets via network request
""")

            return ValidationOutput(
                org=org,
                repo=repo,
                branch=branch,
                result=ValidationResult.VULNERABLE,
                workflow_paths=workflow_paths,
                output_file=output_file,
                issue_type="vulnerability",
                cvss=9.0,
                cwe="CWE-94",
                summary="PwnRequest vulnerability allows code execution",
                confidence="high",
                duration_seconds=2.5,
            )

        # Create agent and runner
        agent = ValidationAgent(command_template="echo {}", timeout=10)
        runner = BatchValidationRunner(agent=agent, concurrency=1)

        # Patch the validate method to use our mock
        with patch.object(agent, "validate", side_effect=mock_validate):
            repos = [
                {
                    "org": "test-org",
                    "repo": "test-repo",
                    "branch": "",
                    "workflow_paths": [".github/workflows/ci.yml"],
                    "working_dir": mock_repo_with_workflow,
                }
            ]

            results = await runner.validate_repos(repos, tmp_path / "repos")

        # Verify results
        assert len(results) == 1
        result = results[0]
        assert result.result == ValidationResult.VULNERABLE
        assert result.org == "test-org"
        assert result.repo == "test-repo"
        assert result.cvss == 9.0
        assert result.cwe == "CWE-94"
        assert result.confidence == "high"
        assert result.output_file.exists()

        # Verify stats
        stats = runner.get_stats()
        assert stats.vulnerable == 1
        assert stats.total == 1

    @pytest.mark.asyncio
    async def test_e2e_validation_false_positive(
        self, mock_repo_with_workflow: Path, tmp_path: Path
    ) -> None:
        """E2E test: validate a workflow that turns out to be a false positive."""

        async def mock_validate_false_positive(
            org: str,
            repo: str,
            branch: str,
            workflow_paths: list[str],
            working_dir: Path,
        ) -> ValidationOutput:
            # Simulate agent determining it's a false positive
            output_file = working_dir / "not_vulnerable.txt"
            output_file.write_text("""---
issue_type: false_positive
summary: "Checkout is of base branch, not PR code"
confidence: high
---

## Workflow: .github/workflows/ci.yml

### Why Scanner Flagged It
Scanner detected pull_request_target with checkout action.

### Why It's Safe
The checkout uses the default ref (base branch), not the PR head.
No untrusted code is ever executed.

### Scanner Improvement
Scanner should verify the ref parameter actually references PR code.
""")

            return ValidationOutput(
                org=org,
                repo=repo,
                branch=branch,
                result=ValidationResult.FALSE_POSITIVE,
                workflow_paths=workflow_paths,
                output_file=output_file,
                issue_type="false_positive",
                summary="Checkout is of base branch, not PR code",
                confidence="high",
                duration_seconds=1.5,
            )

        agent = ValidationAgent(command_template="echo {}", timeout=10)
        runner = BatchValidationRunner(agent=agent, concurrency=1)

        with patch.object(agent, "validate", side_effect=mock_validate_false_positive):
            repos = [
                {
                    "org": "test-org",
                    "repo": "test-repo",
                    "branch": "",
                    "workflow_paths": [".github/workflows/ci.yml"],
                    "working_dir": mock_repo_with_workflow,
                }
            ]

            results = await runner.validate_repos(repos, tmp_path / "repos")

        assert len(results) == 1
        assert results[0].result == ValidationResult.FALSE_POSITIVE
        assert results[0].issue_type == "false_positive"

        stats = runner.get_stats()
        assert stats.false_positive == 1
        assert stats.vulnerable == 0

    @pytest.mark.asyncio
    async def test_e2e_validation_parallel(self, tmp_path: Path) -> None:
        """E2E test: validate multiple repos in parallel."""
        # Create multiple mock repos
        repos_data = []
        for i in range(5):
            repo_dir = tmp_path / "repos" / f"org-{i}" / f"repo-{i}"
            workflows_dir = repo_dir / ".github" / "workflows"
            workflows_dir.mkdir(parents=True)
            (workflows_dir / "ci.yml").write_text("name: CI\non: push\n")

            repos_data.append(
                {
                    "org": f"org-{i}",
                    "repo": f"repo-{i}",
                    "branch": "",
                    "workflow_paths": [".github/workflows/ci.yml"],
                    "working_dir": repo_dir,
                }
            )

        call_count = 0

        async def mock_validate_parallel(
            org: str,
            repo: str,
            branch: str,
            workflow_paths: list[str],
            working_dir: Path,
        ) -> ValidationOutput:
            nonlocal call_count
            call_count += 1

            # Simulate some work
            await asyncio.sleep(0.1)

            # Alternate results
            if int(org.split("-")[1]) % 2 == 0:
                result = ValidationResult.VULNERABLE
                output_file = working_dir / "confirmed_vulnerable.txt"
            else:
                result = ValidationResult.FALSE_POSITIVE
                output_file = working_dir / "not_vulnerable.txt"

            output_file.write_text(f"---\nissue_type: {result.value}\n---\n")

            return ValidationOutput(
                org=org,
                repo=repo,
                branch=branch,
                result=result,
                workflow_paths=workflow_paths,
                output_file=output_file,
                issue_type=result.value,
                duration_seconds=0.1,
            )

        agent = ValidationAgent(command_template="echo {}", timeout=10)
        runner = BatchValidationRunner(agent=agent, concurrency=3)  # 3 parallel workers

        with patch.object(agent, "validate", side_effect=mock_validate_parallel):
            results = await runner.validate_repos(repos_data, tmp_path / "repos")

        assert len(results) == 5
        assert call_count == 5

        stats = runner.get_stats()
        assert stats.total == 5
        assert stats.vulnerable == 3  # org-0, org-2, org-4
        assert stats.false_positive == 2  # org-1, org-3
