import re
import json
from dataclasses import dataclass


_INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above|preceding)\s+instructions?",
    r"disregard\s+(all\s+)?(previous|prior|above)\s+instructions?",
    r"forget\s+(all\s+)?(previous|prior|above)\s+instructions?",
    r"override\s+(all\s+)?instructions?",
    r"you\s+are\s+now\s+(a\s+)?(?:different|new|helpful|another)",
    r"act\s+as\s+(a\s+)?(?:different|new|unrestricted)",
    r"pretend\s+you\s+are",
    r"your\s+new\s+(role|instructions?|purpose|task)\s+is",
    r"from\s+now\s+on\s+you\s+(must|should|will|are)",
    r"output\s+only[:\s]+\{",
    r"respond\s+with[:\s]+\{",
    r"return\s+only[:\s]+\{",
    r"always\s+output[:\s]+\{",
    r"your\s+response\s+must\s+be[:\s]+\{",
    r"has_critical[\"']?\s*:\s*false",
    r"findings[\"']?\s*:\s*\[\s*\]",
    r"(approve|no\s+issues|all\s+clear|safe\s+to\s+merge)\s+this\s+pr",
    r"sentinel\s+(must|should|will)\s+(approve|ignore|skip)",
    r"reveal\s+(your|the)\s+system\s+prompt",
    r"print\s+(your|the)\s+(instructions?|system\s+prompt|prompt)",
    r"what\s+(are\s+)?(your\s+)?instructions",
]

_COMPILED_PATTERNS = [re.compile(p, re.IGNORECASE) for p in _INJECTION_PATTERNS]


@dataclass
class SanitizationResult:
    sanitized_diff: str
    injection_detected: bool
    flagged_lines: list[str]


def sanitize_diff(diff: str) -> SanitizationResult:
    lines = diff.split("\n")
    flagged_lines: list[str] = []
    cleaned_lines: list[str] = []

    for line in lines:
        if line.startswith("+") and not line.startswith("+++"):
            content = line[1:]
            if any(pattern.search(content) for pattern in _COMPILED_PATTERNS):
                flagged_lines.append(line)
                cleaned_lines.append("+[REDACTED: potential prompt injection detected in original line]")
                continue
        cleaned_lines.append(line)

    return SanitizationResult(
        sanitized_diff="\n".join(cleaned_lines),
        injection_detected=len(flagged_lines) > 0,
        flagged_lines=flagged_lines,
    )


@dataclass
class ValidationResult:
    is_valid: bool
    reason: str


def validate_vuln_output(raw_json: str, original_diff: str) -> ValidationResult:
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError as e:
        return ValidationResult(is_valid=False, reason=f"Invalid JSON: {e}")

    required = {"findings", "summary", "has_critical"}
    missing = required - set(data.keys())
    if missing:
        return ValidationResult(is_valid=False, reason=f"Missing required fields: {missing}")

    has_critical_findings = any(
        f.get("severity") == "CRITICAL" for f in data.get("findings", [])
    )
    if data.get("has_critical") is True and not has_critical_findings:
        return ValidationResult(
            is_valid=False,
            reason="has_critical=True but no CRITICAL findings in list — inconsistent output",
        )

    secret_keywords = ["password", "api_key", "secret", "token", "private_key", "passwd"]
    new_lines = [
        l[1:] for l in original_diff.split("\n")
        if l.startswith("+") and not l.startswith("+++")
    ]
    new_code = "\n".join(new_lines).lower()
    assignment_with_secret = any(
        re.search(rf'{kw}\s*=\s*["\']', new_code) for kw in secret_keywords
    )

    if assignment_with_secret and not data.get("findings"):
        return ValidationResult(
            is_valid=False,
            reason=(
                "Diff contains what looks like a secret assignment "
                "but vuln agent returned zero findings — possible injection bypass"
            ),
        )

    return ValidationResult(is_valid=True, reason="Output passed all checks")


def validate_triage_output(raw_json: str, original_diff: str) -> ValidationResult:
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError as e:
        return ValidationResult(is_valid=False, reason=f"Invalid JSON: {e}")

    required = {"should_run_vuln_scan", "should_run_drift_check",
                "should_run_standards_check", "reason", "risk_level"}
    missing = required - set(data.keys())
    if missing:
        return ValidationResult(is_valid=False, reason=f"Missing required fields: {missing}")

    if data.get("risk_level") not in ("LOW", "MEDIUM", "HIGH"):
        return ValidationResult(
            is_valid=False,
            reason=f"Invalid risk_level value: {data.get('risk_level')}",
        )

    new_lines_count = sum(
        1 for l in original_diff.split("\n")
        if l.startswith("+") and not l.startswith("+++")
    )
    all_skipped = (
        not data.get("should_run_vuln_scan")
        and not data.get("should_run_drift_check")
        and not data.get("should_run_standards_check")
    )
    if all_skipped and new_lines_count > 5:
        return ValidationResult(
            is_valid=False,
            reason=(
                f"Triage skipped ALL agents on a diff with {new_lines_count} new lines "
                "— possible injection bypass"
            ),
        )

    return ValidationResult(is_valid=True, reason="Output passed all checks")
