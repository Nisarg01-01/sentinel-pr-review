import os
import json
from azure.ai.inference import ChatCompletionsClient
from azure.ai.inference.models import SystemMessage, UserMessage
from src.models import TriageDecision

TRIAGE_SYSTEM_PROMPT = """
You are the Triage Agent for Sentinel, an automated PR review system.

Your job is to look at a PR's metadata and diff, then decide which specialist
review agents should be invoked. You are NOT doing the detailed review yourself.

Rules:
- Always run the vuln scan UNLESS the PR only changes documentation (.md, .txt, .rst files)
- Run drift check when the PR touches core application code (not just config or tests)
- Run standards check on all PRs that include code changes
- Set risk_level based on: what files changed, how large the diff is, and whether
  the PR touches security-sensitive areas (auth, payments, data access, dependencies)

Respond ONLY with a valid JSON object — no markdown, no explanation.
"""

def run_triage(client: ChatCompletionsClient, pr_metadata: dict, pr_diff: str) -> TriageDecision:
    response = client.complete(
        model=os.environ["MODEL"],
        messages=[
            SystemMessage(TRIAGE_SYSTEM_PROMPT),
            UserMessage(f"""
Please triage this PR and decide which review agents to invoke.

## PR Metadata
{json.dumps(pr_metadata, indent=2)}

## Diff Preview (first 3000 chars)
{pr_diff[:3000]}

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

    return TriageDecision(**json.loads(text))
