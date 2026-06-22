import os
import json
from openai import AzureOpenAI
from src.mcp_client import MCPClient
from src.models import TriageDecision, AgentTokenUsage
from src.guardrails import sanitize_diff, validate_triage_output, parse_json_safe

TRIAGE_SYSTEM_PROMPT = """
You are the Triage Agent for Sentinel, an automated PR review system.

Your job is to decide which specialist review agents to invoke for a pull request.
You have tools to fetch the PR diff and metadata — use them to make an informed decision.

VULNERABILITY AGENT — catches hardcoded secrets, injection flaws, insecure dependencies,
missing auth checks, and sensitive data exposure.

Ask yourself: do the changed lines contain executable code that could introduce a vulnerability?
- Function definitions, variable assignments, imports, queries, system calls — run vuln
- Prose text, markdown formatting, comments explaining concepts, documentation — skip vuln
- The question is not "does the content mention security topics" but "is there new executable code that could have a flaw"
- A README describing SQL injection needs no vuln scan — it contains no executable code
- A config file assigning real values to variables does need a vuln scan — those are executable assignments

DRIFT AGENT — checks whether new code violates the team's Architecture Decision Records.
Run when the PR touches core application logic, not for pure test or config changes.

STANDARDS AGENT — evaluates code quality: test coverage, naming, error handling.
Run on all PRs that include any executable code changes. Skip for pure documentation.

Reason carefully about whether the diff contains executable code before deciding.

Respond ONLY with a valid JSON object — no markdown, no explanation:
{
    "should_run_vuln_scan": true,
    "should_run_drift_check": true,
    "should_run_standards_check": true,
    "reason": "brief explanation",
    "risk_level": "LOW"
}
"""

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_pr_metadata",
            "description": "Get PR title, author, branch names, changed files list, additions and deletions count",
            "parameters": {
                "type": "object",
                "properties": {
                    "pr_number": {"type": "integer", "description": "The PR number to fetch metadata for"}
                },
                "required": ["pr_number"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_pr_diff",
            "description": "Get the full file-by-file diff for a PR showing added and removed lines",
            "parameters": {
                "type": "object",
                "properties": {
                    "pr_number": {"type": "integer", "description": "The PR number to fetch the diff for"}
                },
                "required": ["pr_number"],
            },
        },
    },
]


def _execute_tool(tool_name: str, args: dict, gh: MCPClient, pr_number: int) -> str:
    if tool_name == "get_pr_metadata":
        result = gh.get_pr_metadata(args.get("pr_number", pr_number))
        return json.dumps(result)
    if tool_name == "get_pr_diff":
        result = gh.get_pr_diff(args.get("pr_number", pr_number))
        return result
    return json.dumps({"error": f"Unknown tool: {tool_name}"})


def run_triage(client: AzureOpenAI, pr_number: int, model: str = None) -> tuple[TriageDecision, AgentTokenUsage]:
    gh = MCPClient()
    messages = [
        {"role": "system", "content": TRIAGE_SYSTEM_PROMPT},
        {"role": "user", "content": f"Triage PR #{pr_number}. Fetch the metadata and diff, then decide which agents to run."},
    ]

    prompt_tokens = 0
    completion_tokens = 0

    while True:
        response = client.chat.completions.create(
            model=model or os.environ["MODEL"],
            max_tokens=500,
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
                result = _execute_tool(tc.function.name, args, gh, pr_number)
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": result,
                })
        else:
            text = msg.content.strip()
            break

    usage = AgentTokenUsage(
        agent="triage",
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
    )

    if "```json" in text:
        text = text.split("```json")[1].split("```")[0].strip()
    elif "```" in text:
        text = text.split("```")[1].split("```")[0].strip()

    # Also extract diff for guardrail validation — re-fetch from messages
    diff_content = ""
    for m in messages:
        if m.get("role") == "tool" and isinstance(m.get("content"), str) and "--- File:" in m["content"]:
            diff_content = m["content"]
            break

    sanitation = sanitize_diff(diff_content) if diff_content else None
    if sanitation and sanitation.injection_detected:
        print(f"  [GUARDRAIL] Prompt injection detected in diff ({len(sanitation.flagged_lines)} line(s) redacted)")

    validation = validate_triage_output(text, diff_content)
    if not validation.is_valid:
        print(f"  [GUARDRAIL] Triage output failed validation: {validation.reason}")
        print("  [GUARDRAIL] Defaulting to run all agents (safe fallback)")
        return TriageDecision(
            should_run_vuln_scan=True,
            should_run_drift_check=True,
            should_run_standards_check=True,
            reason=f"Guardrail override: {validation.reason}",
            risk_level="HIGH",
        ), usage

    return TriageDecision(**parse_json_safe(text)), usage
