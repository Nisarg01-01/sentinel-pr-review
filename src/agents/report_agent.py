from src.models import FinalReview, VulnReport, DriftReport, QualityReport, Severity


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


def format_findings_for_github(review: FinalReview) -> str:
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

    lines += ["---", "*Sentinel v1.0 — Automated review powered by Azure AI Foundry + Phi-4*"]
    return "\n".join(lines)
