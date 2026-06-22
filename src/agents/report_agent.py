import os
import json
from openai import AzureOpenAI
from src.models import FinalReview, VulnReport, DriftReport, QualityReport, Severity, AgentTokenUsage


def synthesise_review(
    vuln_report: VulnReport,
    drift_report: DriftReport,
    quality_report: QualityReport,
) -> FinalReview:
    all_vuln = vuln_report.findings
    all_drift = drift_report.violations
    all_quality = quality_report.findings

    all_severities = (
        [f.severity for f in all_vuln]
        + [f.severity for f in all_drift]
        + [f.severity for f in all_quality]
    )

    if Severity.CRITICAL in all_severities or vuln_report.has_critical:
        overall_severity = Severity.CRITICAL
        recommendation = "REQUEST_CHANGES"
    elif Severity.HIGH in all_severities:
        overall_severity = Severity.HIGH
        recommendation = "REQUEST_CHANGES"
    elif Severity.MEDIUM in all_severities:
        overall_severity = Severity.MEDIUM
        recommendation = "COMMENT"
    elif Severity.LOW in all_severities:
        overall_severity = Severity.LOW
        recommendation = "COMMENT"
    else:
        overall_severity = Severity.INFO
        recommendation = "APPROVE"

    parts = []
    if all_vuln:
        parts.append(f"{len(all_vuln)} security issue(s)")
    if all_drift:
        parts.append(f"{len(all_drift)} architecture violation(s)")
    if quality_report.score < 70:
        parts.append(f"quality score {quality_report.score}/100")

    if parts:
        suffix = "Changes required before merge." if recommendation == "REQUEST_CHANGES" else "Review recommended."
        summary = f"Found: {', '.join(parts)}. {suffix}"
    else:
        summary = "No significant issues found. PR looks good."

    action_items = []
    for f in all_vuln:
        if f.severity in [Severity.CRITICAL, Severity.HIGH]:
            action_items.append(f"Fix {f.title} in `{f.file_path}:{f.line_number}`")
    for f in all_drift:
        action_items.append(f"Resolve ADR violation: {f.title}")
    if quality_report.score < 60:
        action_items.append("Improve test coverage and code quality")

    return FinalReview(
        overall_severity=overall_severity,
        recommendation=recommendation,
        summary=summary,
        vuln_findings=all_vuln,
        drift_findings=all_drift,
        quality_findings=all_quality,
        quality_score=quality_report.score,
        action_items=action_items,
    )


def generate_review_narrative(
    client: AzureOpenAI,
    final_review: FinalReview,
    model: str = None,
) -> tuple[str, AgentTokenUsage]:
    """Uses an LLM to write a coherent GitHub review comment from all findings."""

    findings_summary = {
        "verdict": final_review.recommendation,
        "overall_severity": final_review.overall_severity.value,
        "quality_score": final_review.quality_score,
        "security_findings": [
            {
                "severity": f.severity.value,
                "title": f.title,
                "file": f.file_path,
                "line": f.line_number,
                "description": f.description,
                "fix": f.recommendation,
                "cwe": f.category,
            }
            for f in final_review.vuln_findings
        ],
        "architecture_violations": [
            {
                "severity": f.severity.value,
                "title": f.title,
                "file": f.file_path,
                "description": f.description,
                "fix": f.recommendation,
            }
            for f in final_review.drift_findings
        ],
        "quality_findings": [
            {
                "severity": f.severity.value,
                "title": f.title,
                "description": f.description,
                "fix": f.recommendation,
            }
            for f in final_review.quality_findings
        ],
        "action_items": final_review.action_items,
    }

    response = client.chat.completions.create(
        model=model or os.environ.get("REPORT_MODEL", os.environ["MODEL"]),
        max_tokens=1000,
        messages=[
            {
                "role": "system",
                "content": """You are the Report Agent for Sentinel, writing GitHub PR review comments.

Write a clear, professional review comment in Markdown for a developer to read.
Do not just list findings mechanically — reason about what the combination of findings
means for this PR. If there are multiple issues, explain whether they are related.
If the PR is clean, say why it looks good specifically.

Structure:
1. Opening verdict sentence — direct and specific
2. Security findings section (if any) — each with file:line, what it is, why it matters, how to fix
3. Architecture findings section (if any)
4. Quality section with score and top issues
5. Action items as a checklist
6. One closing sentence

Use markdown headers. Be direct. No generic filler sentences.""",
            },
            {
                "role": "user",
                "content": f"Write the GitHub review comment for this PR based on these findings:\n\n{json.dumps(findings_summary, indent=2)}",
            },
        ],
    )

    usage = AgentTokenUsage(
        agent="report",
        prompt_tokens=response.usage.prompt_tokens if response.usage else 0,
        completion_tokens=response.usage.completion_tokens if response.usage else 0,
    )

    narrative = response.choices[0].message.content.strip()
    return narrative, usage


def format_findings_for_github(review: FinalReview) -> str:
    """Fallback formatter — used if narrative generation fails."""
    severity_emoji = {
        "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"
    }
    rec_emoji = {
        "REQUEST_CHANGES": "🚫", "APPROVE": "✅", "COMMENT": "💬"
    }

    sev = review.overall_severity.value if hasattr(review.overall_severity, 'value') else str(review.overall_severity)
    rec = review.recommendation

    lines = [
        "# Sentinel PR Review",
        "",
        f"**Overall verdict:** {rec_emoji.get(rec, '💬')} {rec}  ",
        f"**Quality score:** {review.quality_score}/100  ",
        f"**Severity:** {severity_emoji.get(sev, '⚪')} {sev}",
        "",
        f"> {review.summary}",
        "",
    ]

    if review.vuln_findings:
        lines += ["## Security Findings", ""]
        for f in review.vuln_findings:
            fsev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
            lines += [
                f"### {severity_emoji.get(fsev, '⚪')} {f.title}",
                f"**File:** `{f.file_path}:{f.line_number}` | **Severity:** {fsev} | **Category:** {f.category}",
                "",
                f.description,
                "",
                f"**Fix:** {f.recommendation}",
                "",
            ]

    if review.drift_findings:
        lines += ["## Architecture Findings", ""]
        for f in review.drift_findings:
            fsev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
            lines += [
                f"### {severity_emoji.get(fsev, '⚪')} {f.title}",
                f"**File:** `{f.file_path}:{f.line_number}`",
                "",
                f.description,
                "",
                f"**Fix:** {f.recommendation}",
                "",
            ]

    if review.quality_findings:
        lines += ["## Code Quality", "", f"**Score: {review.quality_score}/100**", ""]
        for f in review.quality_findings:
            fsev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
            lines += [
                f"- {severity_emoji.get(fsev, '⚪')} **{f.title}** (`{f.file_path}:{f.line_number}`)",
                f"  {f.recommendation}",
            ]
        lines.append("")

    if review.action_items:
        lines += ["## Action Items", ""]
        for item in review.action_items:
            lines.append(f"- [ ] {item}")
        lines.append("")

    lines += ["---", "*Sentinel — Automated review powered by Azure AI Foundry + gpt-4.1-mini*"]
    return "\n".join(lines)
