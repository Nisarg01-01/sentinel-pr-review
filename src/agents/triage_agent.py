import os
import json
from azure.ai.inference import ChatCompletionsClient
from azure.ai.inference.models import SystemMessage, UserMessage
from src.models import TriageDecision
from src.guardrails import sanitize_diff, validate_triage_output

TRIAGE_SYSTEM_PROMPT = """
You are the Triage Agent for Sentinel, an automated PR review system.

Your job is to read a PR diff and decide which specialist review agents to invoke.
You are NOT doing the detailed review yourself — you are deciding who should.

Understand WHY each agent exists, then reason from the diff:

VULNERABILITY AGENT — catches hardcoded secrets, injection flaws, insecure dependencies,
missing auth checks, and sensitive data exposure. It should run whenever there is any
realistic chance that security-relevant code was added or modified. This includes:
- Any file where string literals are assigned to variables (a secret could be hiding there)
- Any file touching authentication, database access, HTTP requests, or file I/O
- Test files are NOT exempt — a hardcoded secret in test_code.py is just as dangerous
  as one in production code because it still gets committed to git history
- Config files, scripts, notebooks — all can contain secrets
- The only case where vuln scan is unnecessary is a PR that exclusively changes
  prose documentation (.md, .txt, .rst) with no code whatsoever

DRIFT AGENT — checks whether new code violates the team's Architecture Decision Records.
Run it when the PR touches core application logic, not for pure test or config changes.

STANDARDS AGENT — evaluates code quality: test coverage, naming, error handling.
Run it on all PRs that include any code changes.

Think through the diff carefully before deciding. Your routing decisions directly
affect whether security issues get caught — err on the side of running more checks.

Respond ONLY with a valid JSON object — no markdown, no explanation.
"""

def run_triage(client: ChatCompletionsClient, pr_metadata: dict, pr_diff: str) -> TriageDecision:
    sanitation = sanitize_diff(pr_diff)
    if sanitation.injection_detected:
        print(f"  [GUARDRAIL] Prompt injection detected in diff ({len(sanitation.flagged_lines)} line(s) redacted)")
        for line in sanitation.flagged_lines:
            print(f"    Flagged: {line[:120]}")
    diff_to_use = sanitation.sanitized_diff

    response = client.complete(
        model=os.environ["MODEL"],
        messages=[
            SystemMessage(TRIAGE_SYSTEM_PROMPT),
            UserMessage(f"""
Please triage this PR and decide which review agents to invoke.

## PR Metadata
{json.dumps(pr_metadata, indent=2)}

## Diff Preview (first 3000 chars)
{diff_to_use[:3000]}

Return a JSON object with this exact structure:
{{
    "should_run_vuln_scan": true,
    "should_run_drift_check": true,
    "should_run_standards_check": true,
    "reason": "brief explanation",
    "risk_level": "LOW"
}}
"""),
        ],
    )

    text = response.choices[0].message.content.strip()
    if "```json" in text:
        text = text.split("```json")[1].split("```")[0].strip()
    elif "```" in text:
        text = text.split("```")[1].split("```")[0].strip()

    validation = validate_triage_output(text, pr_diff)
    if not validation.is_valid:
        print(f"  [GUARDRAIL] Triage output failed validation: {validation.reason}")
        print("  [GUARDRAIL] Defaulting to run all agents (safe fallback)")
        return TriageDecision(
            should_run_vuln_scan=True,
            should_run_drift_check=True,
            should_run_standards_check=True,
            reason=f"Guardrail override: {validation.reason}",
            risk_level="HIGH",
        )

    return TriageDecision(**json.loads(text))
