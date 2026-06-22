import os
import pytest
from pathlib import Path
from dotenv import load_dotenv
from openai import AzureOpenAI

from src.agents.vuln_agent import run_vuln_scan
from src.agents.standards_agent import run_standards_check
from src.models import Severity

load_dotenv()

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def client():
    base = os.environ["PROJECT_ENDPOINT"].split("/api/projects")[0]
    return AzureOpenAI(
        azure_endpoint=base,
        api_key=os.environ["AZURE_INFERENCE_KEY"],
        api_version="2025-01-01-preview",
        timeout=900,
    )


def load_diff(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


class TestVulnAgent:

    def test_detects_hardcoded_password(self, client):
        report, _ = run_vuln_scan(client, load_diff("hardcoded_secret.diff"), "test/repo")
        assert len(report.findings) >= 1, "Expected at least 1 finding for hardcoded credentials, got 0"
        assert report.has_critical is True, "Expected has_critical=True for hardcoded secrets"
        assert Severity.CRITICAL in {f.severity for f in report.findings}, (
            f"Expected at least one CRITICAL finding, got: {[f.severity for f in report.findings]}"
        )

    def test_detects_sql_injection(self, client):
        report, _ = run_vuln_scan(client, load_diff("sql_injection.diff"), "test/repo")
        assert len(report.findings) >= 1, "Expected findings for SQL injection, got 0"
        titles_and_cats = " ".join(f.title.lower() + " " + f.category.lower() for f in report.findings)
        assert any(word in titles_and_cats for word in ["sql", "inject", "query"]), (
            f"Expected SQL injection finding, got: {titles_and_cats}"
        )

    def test_clean_code_has_no_critical(self, client):
        report, _ = run_vuln_scan(client, load_diff("clean_code.diff"), "test/repo")
        assert report.has_critical is False, (
            f"Vuln agent raised has_critical=True on clean code. Findings: {report.findings}"
        )

    def test_report_structure_is_valid(self, client):
        report, _ = run_vuln_scan(client, load_diff("hardcoded_secret.diff"), "test/repo")
        for finding in report.findings:
            assert finding.file_path, f"Finding missing file_path: {finding}"
            assert finding.title, f"Finding missing title: {finding}"
            assert finding.description, f"Finding missing description: {finding}"
            assert finding.recommendation, f"Finding missing recommendation: {finding}"


class TestStandardsAgent:

    def test_clean_code_scores_high(self, client):
        report, _ = run_standards_check(client, load_diff("clean_code.diff"), pr_number=0)
        assert report.score >= 70, (
            f"Expected score >= 70 for clean code, got {report.score}. Summary: {report.summary}"
        )

    def test_poor_quality_scores_low(self, client):
        report, _ = run_standards_check(client, load_diff("poor_quality.diff"), pr_number=0)
        assert report.score < 70, (
            f"Expected score < 70 for poor-quality code, got {report.score}. Summary: {report.summary}"
        )

    def test_poor_quality_has_findings(self, client):
        report, _ = run_standards_check(client, load_diff("poor_quality.diff"), pr_number=0)
        assert len(report.findings) >= 2, (
            f"Expected >= 2 quality findings for bad code, got {len(report.findings)}"
        )

    def test_score_is_in_valid_range(self, client):
        report, _ = run_standards_check(client, load_diff("clean_code.diff"), pr_number=0)
        assert 0 <= report.score <= 100, f"Score out of range: {report.score}"
