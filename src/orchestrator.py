import os
from dotenv import load_dotenv
from azure.ai.inference import ChatCompletionsClient
from azure.identity import DefaultAzureCredential

from src.github_client import GitHubClient
from src.agents.triage_agent import run_triage
from src.agents.vuln_agent import run_vuln_scan
from src.agents.drift_agent import run_drift_check
from src.agents.standards_agent import run_standards_check
from src.agents.report_agent import synthesise_review, format_findings_for_github
from src.models import VulnReport, DriftReport, QualityReport

load_dotenv()


def build_inference_client() -> ChatCompletionsClient:
    inference_endpoint = os.environ["PROJECT_ENDPOINT"].split("/api/projects")[0] + "/models"
    return ChatCompletionsClient(
        endpoint=inference_endpoint,
        credential=DefaultAzureCredential(),
        credential_scopes=["https://cognitiveservices.azure.com/.default"],
    )


def run_sentinel(pr_number: int, repo_name: str = None, dry_run: bool = False) -> dict:
    """
    Main entry point. Runs all Sentinel agents on a PR and posts the review to GitHub.

    Args:
        pr_number: GitHub PR number to review
        repo_name: Optional repo override. Defaults to GITHUB_REPO env var.
        dry_run: If True, prints the review but does not post it to GitHub.
    """
    repo_name = repo_name or os.environ["GITHUB_REPO"]

    print(f"\nSentinel starting review for PR #{pr_number} in {repo_name}")
    print("=" * 60)

    client = build_inference_client()
    gh = GitHubClient()

    # Step 1: Fetch PR data
    print("Fetching PR data...")
    metadata = gh.get_pr_metadata(pr_number)
    diff = gh.get_pr_diff(pr_number)
    print(f"  Title:         {metadata['title']}")
    print(f"  Files changed: {len(metadata['changed_files'])}")
    print(f"  +{metadata['additions']} / -{metadata['deletions']}")

    # Step 2: Triage
    print("\nRunning Triage Agent...")
    triage = run_triage(client, metadata, diff)
    print(f"  Risk level: {triage.risk_level}")
    print(f"  Reason:     {triage.reason}")

    # Step 3: Specialist agents based on triage decision
    if triage.should_run_vuln_scan:
        print("\nRunning Vulnerability Agent...")
        vuln_report = run_vuln_scan(client, diff, repo_name)
        print(f"  Findings: {len(vuln_report.findings)} | Critical: {vuln_report.has_critical}")
    else:
        print("\nSkipping vuln scan (triage decision)")
        vuln_report = VulnReport(findings=[], summary="Skipped", has_critical=False)

    if triage.should_run_drift_check:
        print("\nRunning Drift Agent...")
        drift_report = run_drift_check(client, diff)
        print(f"  Violations: {len(drift_report.violations)}")
    else:
        print("\nSkipping drift check (triage decision)")
        drift_report = DriftReport(violations=[], summary="Skipped", adr_references=[])

    if triage.should_run_standards_check:
        print("\nRunning Standards Agent...")
        quality_report = run_standards_check(client, diff)
        print(f"  Score: {quality_report.score}/100")
    else:
        print("\nSkipping standards check (triage decision)")
        quality_report = QualityReport(score=100, findings=[], test_coverage_note="Skipped", summary="Skipped")

    # Step 4: Synthesise final review
    print("\nSynthesising final review...")
    final_review = synthesise_review(vuln_report, drift_report, quality_report)
    print(f"  Verdict:  {final_review.recommendation}")
    print(f"  Severity: {final_review.overall_severity}")

    # Step 5: Post to GitHub
    review_body = format_findings_for_github(final_review)

    if dry_run:
        print("\n[DRY RUN] Review not posted. Preview:")
        print(review_body)
    else:
        print("\nPosting review to GitHub...")
        gh.post_review_comment(
            pr_number=pr_number,
            body=review_body,
            event=final_review.recommendation,
        )

        # Post inline comments for critical/high findings
        inline_candidates = [
            f for f in (vuln_report.findings + drift_report.violations + quality_report.findings)
            if f.severity.value in ["CRITICAL", "HIGH"] and f.line_number > 0
        ]
        if inline_candidates:
            print(f"Posting {min(len(inline_candidates), 5)} inline comment(s)...")
            for finding in inline_candidates[:5]:
                try:
                    gh.post_inline_comment(
                        pr_number=pr_number,
                        path=finding.file_path,
                        line=finding.line_number,
                        body=f"**{finding.severity.value}: {finding.title}**\n\n{finding.description}\n\n**Fix:** {finding.recommendation}",
                    )
                    print(f"  Inline comment posted: {finding.file_path}:{finding.line_number}")
                except Exception as e:
                    print(f"  Inline comment failed (skipping): {e}")

    print("\n" + "=" * 60)
    print("Sentinel review complete!")

    return {
        "pr_number": pr_number,
        "verdict": final_review.recommendation,
        "severity": str(final_review.overall_severity),
        "quality_score": final_review.quality_score,
        "vuln_count": len(vuln_report.findings),
        "drift_count": len(drift_report.violations),
        "quality_findings": len(quality_report.findings),
    }


if __name__ == "__main__":
    import sys
    pr_num = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    dry = "--dry-run" in sys.argv
    result = run_sentinel(pr_num, dry_run=dry)
    print(f"\nResult: {result}")
