import os
import json
from openai import AzureOpenAI
from src.mcp_client import MCPClient
from src.models import QualityReport, AgentTokenUsage
from src.guardrails import parse_json_safe

STANDARDS_SYSTEM_PROMPT = """
You are the Standards Agent for Sentinel, a code quality reviewer.

You evaluate code quality based on engineering best practices.
You have a tool to fetch full file content when the diff alone doesn't give you
enough context — for example to check if tests exist in other files, or to assess
total function length when only part of it is in the diff.

What to check:
1. TEST COVERAGE — are new functions accompanied by tests?
2. DOCSTRINGS — do public functions have docstrings?
3. NAMING — are variables, functions, and classes named clearly?
4. FUNCTION LENGTH — are functions doing too much? (>50 lines is a warning)
5. ERROR HANDLING — are exceptions caught and handled appropriately?

Score the PR 0-100. Report the top 3 most important findings only.

When you have finished your investigation, respond ONLY with a valid JSON object — no markdown, no explanation.
Each finding MUST have exactly these fields: severity, category, file_path, line_number, title, description, recommendation.

{
    "score": 45,
    "findings": [
        {
            "severity": "MEDIUM",
            "category": "Missing Tests",
            "file_path": "src/app.py",
            "line_number": 1,
            "title": "No tests accompany the new code",
            "description": "A new function was added but no test file was included in this PR.",
            "recommendation": "Add a test file covering the new function."
        }
    ],
    "test_coverage_note": "0 tests added for 1 new function",
    "summary": "Score: 45/100. Code lacks tests and docstrings."
}
"""

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_file_content",
            "description": "Fetch the full content of a file to check test coverage, full function length, or context not visible in the diff",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path to the file relative to repo root"},
                    "pr_number": {"type": "integer", "description": "The PR number"},
                },
                "required": ["file_path", "pr_number"],
            },
        },
    },
]


def run_standards_check(
    client: AzureOpenAI,
    pr_diff: str,
    pr_number: int,
    model: str = None,
) -> tuple[QualityReport, AgentTokenUsage]:
    gh = MCPClient()

    messages = [
        {"role": "system", "content": STANDARDS_SYSTEM_PROMPT},
        {"role": "user", "content": f"""Review this PR for code quality and standards compliance.
Fetch full file content if you need more context than the diff provides.

PR: #{pr_number}

## PR Diff
{pr_diff}
"""},
    ]

    prompt_tokens = 0
    completion_tokens = 0
    fetched_files = set()

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
                file_path = args.get("file_path", "")
                if file_path not in fetched_files:
                    fetched_files.add(file_path)
                    effective_pr = args.get("pr_number", pr_number)
                    if effective_pr == 0:
                        content = "[No PR context available — make your judgment from the diff alone.]"
                    else:
                        print(f"  [STANDARDS] Fetching full file for context: {file_path}")
                        try:
                            content = gh.get_file_content(file_path, effective_pr)
                        except Exception as e:
                            content = f"[Could not fetch file: {e}. Make your judgment from the diff alone.]"
                else:
                    content = "[Already fetched this file in this session]"
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": content or "[Empty file]",
                })
        else:
            text = msg.content.strip()
            break

    usage = AgentTokenUsage(
        agent="standards",
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
    )

    if "```json" in text:
        text = text.split("```json")[1].split("```")[0].strip()
    elif "```" in text:
        text = text.split("```")[1].split("```")[0].strip()

    return QualityReport(**parse_json_safe(text)), usage
