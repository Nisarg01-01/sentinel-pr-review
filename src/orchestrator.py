import os
from dotenv import load_dotenv
from openai import AzureOpenAI
from opentelemetry import trace

from src.mcp_client import MCPClient
from src.agents.triage_agent import run_triage
from src.agents.vuln_agent import run_vuln_scan
from src.agents.drift_agent import run_drift_check
from src.agents.standards_agent import run_standards_check
from src.agents.report_agent import synthesise_review, generate_review_narrative, format_findings_for_github
from src.models import VulnReport, DriftReport, QualityReport
from src.telemetry import setup_telemetry

load_dotenv()
tracer = setup_telemetry("sentinel")


def build_inference_client() -> AzureOpenAI:
    base = os.environ["PROJECT_ENDPOINT"].split("/api/projects")[0]
    return AzureOpenAI(
        azure_endpoint=base,
        api_key=os.environ["AZURE_INFERENCE_KEY"],
        api_version="2025-01-01-preview",
        timeout=900,
    )


def run_sentinel(pr_number: int, repo_name: str = None, dry_run: bool = False) -> dict:
    repo_name = repo_name or os.environ["GITHUB_REPO"]

    print(f"\nSentinel starting review for PR #{pr_number} in {repo_name}")
    print("=" * 60)

    client = build_inference_client()
    gh = MCPClient()

    # Model routing — specialist agents can use stronger models via env vars
    default_model = os.environ.get("MODEL", "gpt-4.1-mini")
    vuln_model = os.environ.get("VULN_MODEL", default_model)
    report_model = os.environ.get("REPORT_MODEL", default_model)

    with tracer.start_as_current_span("sentinel.review") as root_span:
        root_span.set_attribute("pr.number", pr_number)
        root_span.set_attribute("pr.repo", repo_name)

        token_totals = {"prompt": 0, "completion": 0}

        # Triage fetches its own context via MCP tools
        print("\nRunning Triage Agent...")
        with tracer.start_as_current_span("triage_agent") as span:
            triage, triage_usage = run_triage(client, pr_number, model=default_model)
            span.set_attribute("triage.risk_level", triage.risk_level)
            span.set_attribute("triage.run_vuln", triage.should_run_vuln_scan)
            span.set_attribute("triage.run_drift", triage.should_run_drift_check)
            span.set_attribute("triage.run_standards", triage.should_run_standards_check)
            span.set_attribute("tokens.prompt", triage_usage.prompt_tokens)
            span.set_attribute("tokens.completion", triage_usage.completion_tokens)
            token_totals["prompt"] += triage_usage.prompt_tokens
            token_totals["completion"] += triage_usage.completion_tokens
        print(f"  Risk level: {triage.risk_level}")
        print(f"  Reason:     {triage.reason}")
        print(f"  Tokens:     {triage_usage.prompt_tokens}p / {triage_usage.completion_tokens}c")

        # Fetch diff once for specialist agents that need it
        print("\nFetching PR diff for specialist agents...")
        diff = gh.get_pr_diff(pr_number)

        if triage.should_run_vuln_scan:
            print("\nRunning Vulnerability Agent...")
            with tracer.start_as_current_span("vuln_agent") as span:
                vuln_report, vuln_usage = run_vuln_scan(
                    client, diff, repo_name, pr_number, model=vuln_model
                )
                span.set_attribute("vuln.findings", len(vuln_report.findings))
                span.set_attribute("vuln.has_critical", vuln_report.has_critical)
                span.set_attribute("tokens.prompt", vuln_usage.prompt_tokens)
                span.set_attribute("tokens.completion", vuln_usage.completion_tokens)
                token_totals["prompt"] += vuln_usage.prompt_tokens
                token_totals["completion"] += vuln_usage.completion_tokens
            print(f"  Findings: {len(vuln_report.findings)} | Critical: {vuln_report.has_critical}")
            print(f"  Tokens:   {vuln_usage.prompt_tokens}p / {vuln_usage.completion_tokens}c")
        else:
            print("\nSkipping vuln scan (triage decision)")
            vuln_report = VulnReport(findings=[], summary="Skipped", has_critical=False)

        if triage.should_run_drift_check:
            print("\nRunning Drift Agent...")
            with tracer.start_as_current_span("drift_agent") as span:
                drift_report, drift_usage = run_drift_check(client, diff, model=default_model)
                span.set_attribute("drift.violations", len(drift_report.violations))
                span.set_attribute("tokens.prompt", drift_usage.prompt_tokens)
                span.set_attribute("tokens.completion", drift_usage.completion_tokens)
                token_totals["prompt"] += drift_usage.prompt_tokens
                token_totals["completion"] += drift_usage.completion_tokens
            print(f"  Violations: {len(drift_report.violations)}")
            print(f"  Tokens:     {drift_usage.prompt_tokens}p / {drift_usage.completion_tokens}c")
        else:
            print("\nSkipping drift check (triage decision)")
            drift_report = DriftReport(violations=[], summary="Skipped", adr_references=[])

        if triage.should_run_standards_check:
            print("\nRunning Standards Agent...")
            with tracer.start_as_current_span("standards_agent") as span:
                quality_report, standards_usage = run_standards_check(
                    client, diff, pr_number, model=default_model
                )
                span.set_attribute("standards.score", quality_report.score)
                span.set_attribute("tokens.prompt", standards_usage.prompt_tokens)
                span.set_attribute("tokens.completion", standards_usage.completion_tokens)
                token_totals["prompt"] += standards_usage.prompt_tokens
                token_totals["completion"] += standards_usage.completion_tokens
            print(f"  Score: {quality_report.score}/100")
            print(f"  Tokens: {standards_usage.prompt_tokens}p / {standards_usage.completion_tokens}c")
        else:
            print("\nSkipping standards check (triage decision)")
            quality_report = QualityReport(score=100, findings=[], test_coverage_note="Skipped", summary="Skipped")

        print("\nSynthesising final review...")
        with tracer.start_as_current_span("synthesise") as span:
            final_review = synthesise_review(vuln_report, drift_report, quality_report)
            span.set_attribute("review.verdict", final_review.recommendation)
            span.set_attribute("review.severity", str(final_review.overall_severity))
        print(f"  Verdict:  {final_review.recommendation}")
        print(f"  Severity: {final_review.overall_severity.value}")

        print("\nGenerating review narrative...")
        with tracer.start_as_current_span("report_agent") as span:
            try:
                review_body, report_usage = generate_review_narrative(client, final_review, model=report_model)
                span.set_attribute("tokens.prompt", report_usage.prompt_tokens)
                span.set_attribute("tokens.completion", report_usage.completion_tokens)
                token_totals["prompt"] += report_usage.prompt_tokens
                token_totals["completion"] += report_usage.completion_tokens
                print(f"  Tokens: {report_usage.prompt_tokens}p / {report_usage.completion_tokens}c")
            except Exception as e:
                print(f"  [REPORT] Narrative generation failed ({e}), using fallback formatter")
                review_body = format_findings_for_github(final_review)

        if dry_run:
            print("\n[DRY RUN] Review not posted. Preview:")
            print(review_body)
        else:
            print("\nPosting review to GitHub...")
            with tracer.start_as_current_span("post_review") as span:
                gh.post_review_comment(
                    pr_number=pr_number,
                    body=review_body,
                    event=final_review.recommendation,
                )
                span.set_attribute("review.posted", True)

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

        root_span.set_attribute("review.vuln_count", len(vuln_report.findings))
        root_span.set_attribute("review.drift_count", len(drift_report.violations))
        root_span.set_attribute("review.quality_score", final_review.quality_score)
        root_span.set_attribute("tokens.total_prompt", token_totals["prompt"])
        root_span.set_attribute("tokens.total_completion", token_totals["completion"])
        root_span.set_attribute("tokens.total", token_totals["prompt"] + token_totals["completion"])
        print(f"\nTotal tokens used: {token_totals['prompt']}p / {token_totals['completion']}c "
              f"({token_totals['prompt'] + token_totals['completion']} total)")

    print("\n" + "=" * 60)
    print("Sentinel review complete!")

    return {
        "pr_number": pr_number,
        "verdict": final_review.recommendation,
        "severity": final_review.overall_severity.value,
        "quality_score": final_review.quality_score,
        "vuln_count": len(vuln_report.findings),
        "drift_count": len(drift_report.violations),
        "quality_findings": len(quality_report.findings),
        "tokens_prompt": token_totals["prompt"],
        "tokens_completion": token_totals["completion"],
        "tokens_total": token_totals["prompt"] + token_totals["completion"],
    }


if __name__ == "__main__":
    import sys
    pr_num = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    dry = "--dry-run" in sys.argv
    result = run_sentinel(pr_num, dry_run=dry)
    print(f"\nResult: {result}")
