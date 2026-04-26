import os
import json
from azure.ai.inference import ChatCompletionsClient
from azure.ai.inference.models import SystemMessage, UserMessage
from azure.core.credentials import AzureKeyCredential
from azure.search.documents import SearchClient
from src.models import DriftReport

DRIFT_SYSTEM_PROMPT = """
You are the Architecture Drift Agent for Sentinel.

You check whether new code violates the team's Architecture Decision Records (ADRs).
You will be given relevant ADR content and the PR diff to compare against.

Your process:
1. Read the PR diff carefully
2. Compare what the code does against what the ADRs require
3. Flag any violations with specific references to which ADR is violated

Be precise: only flag violations you can clearly see in the diff.
Reference the ADR by name/number when you find a violation.
If no ADRs are violated, return an empty violations list.

Respond ONLY with a valid JSON object — no markdown, no explanation.
"""

def search_relevant_adrs(diff: str, top: int = 3) -> tuple[str, list[str]]:
    """Search Azure AI Search for ADRs relevant to the diff content."""
    endpoint = os.environ["AZURE_SEARCH_ENDPOINT"]
    key = os.environ["AZURE_SEARCH_KEY"]
    index_name = os.environ["AZURE_SEARCH_INDEX"]

    search_client = SearchClient(
        endpoint=endpoint,
        index_name=index_name,
        credential=AzureKeyCredential(key),
    )

    # Extract keywords from diff for search query
    keywords = []
    for line in diff.split("\n"):
        if line.startswith("+") and not line.startswith("+++"):
            if any(w in line.lower() for w in ["password", "secret", "key", "token", "auth", "except", "test"]):
                keywords.append(line[1:].strip())

    query = " ".join(keywords[:5]) if keywords else "security authentication error handling testing"

    results = search_client.search(search_text=query, top=top)
    adr_texts = []
    adr_names = []
    for r in results:
        adr_texts.append(f"### {r['title']}\n{r['content']}")
        adr_names.append(r["filename"])

    return "\n\n".join(adr_texts), adr_names


def run_drift_check(client: ChatCompletionsClient, pr_diff: str) -> DriftReport:
    adr_content, adr_names = search_relevant_adrs(pr_diff)

    response = client.complete(
        model=os.environ["MODEL"],
        messages=[
            SystemMessage(DRIFT_SYSTEM_PROMPT),
            UserMessage(f"""
Check this pull request for architectural violations against our ADRs.

## Relevant ADRs
{adr_content}

## PR Diff
{pr_diff}

Return a JSON object with this exact structure:
{{
    "violations": [
        {{
            "severity": "HIGH",
            "category": "Architecture Violation",
            "file_path": "src/app.py",
            "line_number": 5,
            "title": "Hardcoded secret violates ADR-001",
            "description": "ADR-001 requires secrets to be loaded from environment variables. This line hardcodes a password directly in source code.",
            "recommendation": "Replace with os.environ['PASSWORD'] or load from Azure Key Vault."
        }}
    ],
    "summary": "Found 1 violation of ADR-001 secret management requirements",
    "adr_references": ["ADR-001-secrets.md"]
}}
"""),
        ],
    )

    text = response.choices[0].message.content.strip()
    if "```json" in text:
        text = text.split("```json")[1].split("```")[0].strip()
    elif "```" in text:
        text = text.split("```")[1].split("```")[0].strip()

    return DriftReport(**json.loads(text))
