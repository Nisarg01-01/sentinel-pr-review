import os
import pytest
from pathlib import Path
from dotenv import load_dotenv
from azure.ai.inference import ChatCompletionsClient
from azure.identity import DefaultAzureCredential

from src.agents.triage_agent import run_triage
from src.agents.vuln_agent import run_vuln_scan
from src.agents.standards_agent import run_standards_check
from src.models import Severity

load_dotenv()

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def client():
    inference_endpoint = os.environ["PROJECT_ENDPOINT"].split("/api/projects")[0] + "/models"
    return ChatCompletionsClient(
        endpoint=inference_endpoint,
        credential=DefaultAzureCredential(),
        credential_scopes=["https://cognitiveservices.azure.com/.default"],
    )


def load_diff(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


class TestTriageAgent:

    def test_triage_runs_vuln_on_hardcoded_secret(self, client):
        diff = load_diff("hardcoded_secret.diff")
        metadata = {"title": "Add database connection", "changed_files": ["src/database.py"],
                    "additions": 12, "deletions": 0}

        result = run_triage(client, metadata, diff)

        assert result.should_run_vuln_scan is True, (
            f"Triage skipped vuln scan on a diff with hardcoded DB_PASSWORD and API_KEY. "
            f"Reason given: {result.reason}"
        )

    def test_triage_skips_vuln_on_docs_only(self, client):
        diff = load_diff("docs_only.diff")
        metadata = {"title": "Update README and architecture docs",
                    "changed_files": ["README.md", "docs/architecture.md"],
                    "additions": 10, "deletions": 1}

        result = run_triage(client, metadata, diff)

        assert result.should_run_vuln_scan is False, (
            f"Triage ran vuln scan on a docs-only PR. Reason given: {result.reason}"
        )

    def test_triage_runs_standards_on_code(self, client):
        diff = load_diff("poor_quality.diff")
        metadata = {"title": "Add utility functions", "changed_files": ["src/stuff.py"],
                    "additions": 22, "deletions": 0}

        result = run_triage(client, metadata, diff)

        assert result.should_run_standards_check is True, (
            f"Triage skipped standards check on a code PR. Reason: {result.reason}"
        )

    def test_triage_produces_valid_risk_level(self, client):
        diff = load_diff("clean_code.diff")
        metadata = {"title": "Add calculator module with tests",
                    "changed_files": ["src/calculator.py", "tests/test_calculator.py"],
                    "additions": 33, "deletions": 0}

        result = run_triage(client, metadata, diff)

        assert result.risk_level in ("LOW", "MEDIUM", "HIGH"), (
            f"Unexpected risk_level value: {result.risk_level}"
        )


class TestVulnAgent:

    def test_detects_hardcoded_password(self, client):
        diff = load_diff("hardcoded_secret.diff")

        report = run_vuln_scan(client, diff, "test/repo")

        assert len(report.findings) >= 1, "Expected at least 1 finding for hardcoded credentials, got 0"
        assert report.has_critical is True, "Expected has_critical=True for hardcoded secrets"
        assert Severity.CRITICAL in {f.severity for f in report.findings}, (
            f"Expected at least one CRITICAL finding, got: {[f.severity for f in report.findings]}"
        )

    def test_detects_sql_injection(self, client):
        diff = load_diff("sql_injection.diff")

        report = run_vuln_scan(client, diff, "test/repo")

        assert len(report.findings) >= 1, "Expected findings for SQL injection, got 0"
        titles_and_cats = " ".join(f.title.lower() + " " + f.category.lower() for f in report.findings)
        assert any(word in titles_and_cats for word in ["sql", "inject", "query"]), (
            f"Expected SQL injection finding, got: {titles_and_cats}"
        )

    def test_clean_code_has_no_critical(self, client):
        report = run_vuln_scan(client, load_diff("clean_code.diff"), "test/repo")
        assert report.has_critical is False, (
            f"Vuln agent raised has_critical=True on clean code. Findings: {report.findings}"
        )

    def test_report_structure_is_valid(self, client):
        report = run_vuln_scan(client, load_diff("hardcoded_secret.diff"), "test/repo")
        for finding in report.findings:
            assert finding.file_path, f"Finding missing file_path: {finding}"
            assert finding.title, f"Finding missing title: {finding}"
            assert finding.description, f"Finding missing description: {finding}"
            assert finding.recommendation, f"Finding missing recommendation: {finding}"


class TestStandardsAgent:

    def test_clean_code_scores_high(self, client):
        report = run_standards_check(client, load_diff("clean_code.diff"))
        assert report.score >= 70, (
            f"Expected score >= 70 for clean code, got {report.score}. Summary: {report.summary}"
        )

    def test_poor_quality_scores_low(self, client):
        report = run_standards_check(client, load_diff("poor_quality.diff"))
        assert report.score < 70, (
            f"Expected score < 70 for poor-quality code, got {report.score}. Summary: {report.summary}"
        )

    def test_poor_quality_has_findings(self, client):
        report = run_standards_check(client, load_diff("poor_quality.diff"))
        assert len(report.findings) >= 2, (
            f"Expected >= 2 quality findings for bad code, got {len(report.findings)}"
        )

    def test_score_is_in_valid_range(self, client):
        report = run_standards_check(client, load_diff("clean_code.diff"))
        assert 0 <= report.score <= 100, f"Score out of range: {report.score}"
