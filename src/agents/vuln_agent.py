import os
import json
from azure.ai.inference import ChatCompletionsClient
from azure.ai.inference.models import SystemMessage, UserMessage
from src.models import VulnReport, Finding, Severity
from src.guardrails import sanitize_diff, validate_vuln_output

VULN_SYSTEM_PROMPT = """
You are the Vulnerability Agent for Sentinel, a security-focused code reviewer.

You analyse git diffs for security vulnerabilities. You are thorough and precise.

What to look for:
1. HARDCODED SECRETS — passwords, API keys, tokens, connection strings in code
   Pattern: any variable assignment where the value looks like a secret

2. INJECTION VULNERABILITIES — SQL injection, command injection, path traversal
   Pattern: string concatenation used to build queries or commands with user input

3. INSECURE DEPENDENCIES — outdated packages with known CVEs
   Pattern: version pins in requirements.txt, package.json, pom.xml that are old

4. AUTHENTICATION ISSUES — missing auth checks, hardcoded credentials, weak crypto
   Pattern: routes without auth decorators, MD5/SHA1 for passwords, hardcoded tokens

5. SENSITIVE DATA EXPOSURE — logging passwords, printing secrets, unmasked PII
   Pattern: print/log statements containing password, token, secret, key, ssn, etc.

For each finding, provide:
- The EXACT file path and line number from the diff
- Severity: CRITICAL (hardcoded secret/direct injection) > HIGH > MEDIUM > LOW
- A clear explanation a junior developer can understand
- A specific recommendation to fix it

Only report REAL issues you can see in the diff. Do not speculate.
If there are no issues, return an empty findings list.

Respond ONLY with a valid JSON object — no markdown, no explanation.
"""

def run_vuln_scan(client: ChatCompletionsClient, pr_diff: str, repo_name: str) -> VulnReport:
    sanitation = sanitize_diff(pr_diff)
    if sanitation.injection_detected:
        print(f"  [GUARDRAIL] Prompt injection detected in diff ({len(sanitation.flagged_lines)} line(s) redacted)")
        for line in sanitation.flagged_lines:
            print(f"    Flagged: {line[:120]}")
    diff_to_use = sanitation.sanitized_diff

    response = client.complete(
        model=os.environ["MODEL"],
        messages=[
            SystemMessage(VULN_SYSTEM_PROMPT),
            UserMessage(f"""
Scan this pull request diff for security vulnerabilities.

Repository: {repo_name}

## Full Diff
{diff_to_use}

Return a JSON object with this exact structure:
{{
    "findings": [
        {{
            "severity": "CRITICAL",
            "category": "Hardcoded Secret",
            "file_path": "src/app.py",
            "line_number": 3,
            "title": "Hardcoded password in source code",
            "description": "A plaintext password is assigned directly in the source code and will be visible to anyone with repo access.",
            "recommendation": "Remove the hardcoded value and load it from an environment variable or Azure Key Vault instead."
        }}
    ],
    "summary": "Found 1 critical issue: hardcoded password",
    "has_critical": true
}}
"""),
        ],
    )

    text = response.choices[0].message.content.strip()
    if "```json" in text:
        text = text.split("```json")[1].split("```")[0].strip()
    elif "```" in text:
        text = text.split("```")[1].split("```")[0].strip()

    validation = validate_vuln_output(text, pr_diff)
    if not validation.is_valid:
        print(f"  [GUARDRAIL] Vuln output failed validation: {validation.reason}")
        print("  [GUARDRAIL] Injecting guardrail finding to flag the anomaly")
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
            report = VulnReport(**json.loads(text))
            report.findings.append(guardrail_finding)
            report.has_critical = True
            return report
        except Exception:
            return VulnReport(
                findings=[guardrail_finding],
                summary=f"Guardrail override: {validation.reason}",
                has_critical=True,
            )

    return VulnReport(**json.loads(text))
