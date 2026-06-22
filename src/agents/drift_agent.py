import os
import json
from openai import AzureOpenAI
from azure.core.credentials import AzureKeyCredential
from azure.search.documents import SearchClient
from src.models import DriftReport, AgentTokenUsage
from src.guardrails import parse_json_safe

DRIFT_SYSTEM_PROMPT = """
You are the Architecture Drift Agent for Sentinel.

You check whether new code violates the team's Architecture Decision Records (ADRs).
You have a tool to search for relevant ADRs — use it with specific queries based on
what you see in the diff. You can search multiple times with different queries if needed.

Your process:
1. Read the PR diff carefully
2. Identify what concerns the diff raises — auth patterns, error handling, secrets, testing
3. Search for relevant ADRs using specific terms from those concerns
4. Compare the code against the retrieved ADRs
5. Flag violations with specific ADR references

Only flag violations you can clearly see in the diff.
If no ADRs are violated, return an empty violations list.

Respond ONLY with a valid JSON object — no markdown, no explanation:
{
    "violations": [
        {
            "severity": "HIGH",
            "category": "Architecture",
            "file_path": "path/to/file.py",
            "line_number": 42,
            "title": "Short title of the violation",
            "description": "What the violation is and which ADR it breaks",
            "recommendation": "How to fix it"
        }
    ],
    "summary": "...",
    "adr_references": ["ADR-001", "ADR-002"]
}
"""

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "search_adrs",
            "description": "Search the ADR document store for architecture decisions relevant to a query",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search terms based on what you see in the diff — e.g. 'authentication middleware', 'error handling exceptions', 'secret management'"},
                },
                "required": ["query"],
            },
        },
    },
]


def _search_adrs(query: str, top: int = 3) -> str:
    endpoint = os.environ["AZURE_SEARCH_ENDPOINT"]
    key = os.environ["AZURE_SEARCH_KEY"]
    index_name = os.environ["AZURE_SEARCH_INDEX"]

    search_client = SearchClient(
        endpoint=endpoint,
        index_name=index_name,
        credential=AzureKeyCredential(key),
    )

    results = search_client.search(search_text=query, top=top)
    adr_texts = []
    for r in results:
        adr_texts.append(f"### {r['title']}\n{r['content']}")

    return "\n\n".join(adr_texts) if adr_texts else "No ADRs found for this query."


def run_drift_check(client: AzureOpenAI, pr_diff: str, model: str = None) -> tuple[DriftReport, AgentTokenUsage]:
    messages = [
        {"role": "system", "content": DRIFT_SYSTEM_PROMPT},
        {"role": "user", "content": f"""Check this PR for architectural violations.
Search for ADRs relevant to what you see in the diff, then compare.

## PR Diff
{pr_diff}
"""},
    ]

    prompt_tokens = 0
    completion_tokens = 0

    while True:
        response = client.chat.completions.create(
            model=model or os.environ["MODEL"],
            max_tokens=800,
            messages=messages,
            tools=TOOLS,
            tool_choice="auto",
        )

        prompt_tokens += response.usage.prompt_tokens if response.usage else 0
        completion_tokens += response.usage.completion_tokens if response.usage else 0

        msg = response.choices[0].message

        if msg.tool_calls:
            messages.append({"role": "assistant", "tool_calls": [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {"name": tc.function.name, "arguments": tc.function.arguments},
                }
                for tc in msg.tool_calls
            ]})
            for tc in msg.tool_calls:
                args = json.loads(tc.function.arguments)
                query = args.get("query", "")
                print(f"  [DRIFT] Searching ADRs: '{query}'")
                result = _search_adrs(query)
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": result,
                })
        else:
            text = msg.content.strip()
            break

    usage = AgentTokenUsage(
        agent="drift",
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
    )

    if "```json" in text:
        text = text.split("```json")[1].split("```")[0].strip()
    elif "```" in text:
        text = text.split("```")[1].split("```")[0].strip()

    return DriftReport(**parse_json_safe(text)), usage
