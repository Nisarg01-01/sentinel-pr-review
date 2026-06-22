import os
import json
from openai import AzureOpenAI
from src.mcp_client import MCPClient
from src.models import VulnReport, Finding, Severity, AgentTokenUsage
from src.guardrails import sanitize_diff, validate_vuln_output, parse_json_safe

VULN_SYSTEM_PROMPT = """
You are the Vulnerability Agent for Sentinel, a security-focused code reviewer.

You analyse git diffs for security vulnerabilities. You have a tool to fetch the full
content of any file if you need more context to confirm or rule out a finding.

What to look for:
1. HARDCODED SECRETS — passwords, API keys, tokens, connection strings in code
2. INJECTION VULNERABILITIES — SQL injection, command injection, path traversal
3. INSECURE DEPENDENCIES — outdated packages with known CVEs
4. AUTHENTICATION ISSUES — missing auth checks, hardcoded credentials, weak crypto
5. SENSITIVE DATA EXPOSURE — logging passwords, printing secrets, unmasked PII

When you spot something suspicious in the diff but cannot tell from the diff alone
whether it is safe (e.g. a query pattern that might be parameterized elsewhere,
a route that might have auth middleware defined in another file), call get_file_content
to fetch the full file before making a judgment.

For each confirmed finding, provide:
- The EXACT file path and line number from the diff
- Severity: CRITICAL (hardcoded secret/direct injection) > HIGH > MEDIUM > LOW
- A clear explanation a junior developer can understand
- A specific recommendation to fix it

Only report REAL issues you can confirm. Do not speculate.
If there are no issues, return an empty findings list.

When you have finished your investigation, respond ONLY with a valid JSON object — no markdown, no explanation.
Each finding MUST have exactly these fields: severity, category, file_path, line_number, title, description, recommendation.

{
    "findings": [
        {
            "severity": "CRITICAL",
            "category": "Hardcoded Secret",
            "file_path": "src/app.py",
            "line_number": 3,
            "title": "Hardcoded API key in source code",
            "description": "An API key is assigned directly in source code and will be visible to anyone with repo access.",
            "recommendation": "Remove the hardcoded value and load it from an environment variable instead."
        }
    ],
    "summary": "Found 1 critical issue: hardcoded API key",
    "has_critical": true
}
"""

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_file_content",
            "description": "Fetch the full content of a file at the PR head commit to get context beyond the diff",
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


def run_vuln_scan(
    client: AzureOpenAI,
    pr_diff: str,
    repo_name: str,
    pr_number: int = 0,
    model: str = None,
) -> tuple[VulnReport, AgentTokenUsage]:
    gh = MCPClient()

    sanitation = sanitize_diff(pr_diff)
    if sanitation.injection_detected:
        print(f"  [GUARDRAIL] Prompt injection detected in diff ({len(sanitation.flagged_lines)} line(s) redacted)")
        for line in sanitation.flagged_lines:
            print(f"    Flagged: {line[:120]}")
    diff_to_use = sanitation.sanitized_diff

    messages = [
        {"role": "system", "content": VULN_SYSTEM_PROMPT},
        {"role": "user", "content": f"""Scan this pull request diff for security vulnerabilities.
Use get_file_content if you need full file context to confirm a finding.

Repository: {repo_name}
PR: #{pr_number}

## Full Diff
{diff_to_use}
"""},
    ]

    prompt_tokens = 0
    completion_tokens = 0
    fetched_files = set()

    while True:
        response = client.chat.completions.create(
            model=model or os.environ.get("VULN_MODEL", os.environ["MODEL"]),
            max_tokens=1000,
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
                        print(f"  [VULN] Fetching full file for context: {file_path}")
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
        agent="vuln",
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
    )

    if "```json" in text:
        text = text.split("```json")[1].split("```")[0].strip()
    elif "```" in text:
        text = text.split("```")[1].split("```")[0].strip()

    validation = validate_vuln_output(text, pr_diff)
    if not validation.is_valid:
        print(f"  [GUARDRAIL] Vuln output failed validation: {validation.reason}")
        guardrail_finding = Finding(
            severity=Severity.HIGH,
            category="Guardrail Alert",
            file_path="unknown",
            line_number=0,
            title="Vuln agent output failed guardrail validation",
            description=validation.reason,
            recommendation="Manually review this PR — automated analysis may have been bypassed.",
        )
        try:
            report = VulnReport(**parse_json_safe(text))
            report.findings.append(guardrail_finding)
            report.has_critical = True
            return _apply_memory_filter(report, repo_name, gh), usage
        except Exception:
            return VulnReport(
                findings=[guardrail_finding],
                summary=f"Guardrail override: {validation.reason}",
                has_critical=True,
            ), usage

    report = VulnReport(**parse_json_safe(text))
    return _apply_memory_filter(report, repo_name, gh), usage


def _apply_memory_filter(report: VulnReport, repo_name: str, gh: MCPClient) -> VulnReport:
    """Suppress findings that have been confirmed as false positives at least twice before."""
    filtered = []
    suppressed = 0
    for finding in report.findings:
        pattern_type = f"{finding.category}:{finding.title[:40]}"
        if gh.is_known_false_positive(repo_name, finding.file_path, pattern_type):
            suppressed += 1
            print(f"  [MEMORY] Suppressed known false positive: {finding.title} in {finding.file_path}")
        else:
            filtered.append(finding)

    if suppressed:
        report.findings = filtered
        report.has_critical = any(f.severity == Severity.CRITICAL for f in filtered)
        report.summary = f"{report.summary} ({suppressed} known false positive(s) suppressed)"

    return report
