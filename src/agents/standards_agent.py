import os
import json
from openai import AzureOpenAI
from src.models import QualityReport, AgentTokenUsage
from src.guardrails import parse_json_safe

STANDARDS_SYSTEM_PROMPT = """
You are the Standards Agent for Sentinel, a code quality reviewer.

You evaluate code quality based on engineering best practices.

What to check:
1. TEST COVERAGE — are new functions/methods accompanied by tests?
2. DOCSTRINGS — do public functions have docstrings explaining what they do?
3. NAMING — are variables, functions, and classes named clearly?
4. FUNCTION LENGTH — are functions doing too much? (>50 lines is a warning)
5. ERROR HANDLING — are exceptions caught and handled appropriately?

Score the PR 0-100. Report the top 3 most important findings only. Keep descriptions concise (one sentence each).

Respond ONLY with a valid JSON object — no markdown, no explanation.
"""

def run_standards_check(client: AzureOpenAI, pr_diff: str, model: str = None) -> tuple[QualityReport, AgentTokenUsage]:
    response = client.chat.completions.create(
        model=model or os.environ["MODEL"],
        max_tokens=500,
        messages=[
            {"role": "system", "content": STANDARDS_SYSTEM_PROMPT},
            {"role": "user", "content": f"""
Review this PR for code quality and standards compliance.

## PR Diff
{pr_diff}

Return a JSON object with this exact structure:
{{
    "score": 45,
    "findings": [
        {{
            "severity": "MEDIUM",
            "category": "Missing Tests",
            "file_path": "test_code.py",
            "line_number": 1,
            "title": "No tests accompany the new code",
            "description": "A new variable was added but no test file or test function was included in this PR.",
            "recommendation": "Add a test file tests/test_code.py with at least one test covering this code."
        }}
    ],
    "test_coverage_note": "0 tests added for 1 new line of code",
    "summary": "Score: 45/100. Code lacks tests and docstrings."
}}
"""},
        ],
    )

    usage = AgentTokenUsage(
        agent="standards",
        prompt_tokens=response.usage.prompt_tokens if response.usage else 0,
        completion_tokens=response.usage.completion_tokens if response.usage else 0,
    )

    text = response.choices[0].message.content.strip()
    if "```json" in text:
        text = text.split("```json")[1].split("```")[0].strip()
    elif "```" in text:
        text = text.split("```")[1].split("```")[0].strip()

    return QualityReport(**parse_json_safe(text)), usage
