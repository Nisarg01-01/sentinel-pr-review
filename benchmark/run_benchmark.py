"""
Sentinel Vulnerability Detection Benchmark

Evaluates Sentinel's vuln agent against 10 vulnerable and 5 clean Python snippets
extracted directly from OWASP PyGoat. Each snippet is wrapped as a git diff and
passed to run_vuln_scan() — the same function that runs in production.

Ground truth is defined per test case: expected CWE category and minimum severity.
Results are scored for true positive rate (recall), false positive rate, and precision.

Run:
    conda run -n sentinel python benchmark/run_benchmark.py
"""

import os
import sys
import json
import time
from dataclasses import dataclass, field
from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
load_dotenv()

from azure.ai.inference import ChatCompletionsClient
from azure.identity import DefaultAzureCredential
from src.agents.vuln_agent import run_vuln_scan
from src.agents.triage_agent import run_triage


# ---------------------------------------------------------------------------
# Test case definition
# ---------------------------------------------------------------------------

@dataclass
class TestCase:
    id: str
    name: str
    cwe: str
    description: str
    diff: str
    is_vulnerable: bool
    expected_keywords: list[str] = field(default_factory=list)
    expected_min_severity: str = "MEDIUM"


# ---------------------------------------------------------------------------
# Benchmark cases — real code extracted from OWASP PyGoat
# ---------------------------------------------------------------------------

CASES: list[TestCase] = [

    # --- VULNERABLE CASES ---

    TestCase(
        id="V01",
        name="SQL Injection — Login Handler",
        cwe="CWE-89",
        description="String concatenation used to build SQL query with user input",
        expected_keywords=["sql", "inject", "query", "concatenat"],
        expected_min_severity="CRITICAL",
        is_vulnerable=True,
        diff="""\
diff --git a/introduction/views.py b/introduction/views.py
--- a/introduction/views.py
+++ b/introduction/views.py
@@ -155,6 +155,10 @@
+def sql_login(request):
+    name = request.POST.get('user')
+    password = request.POST.get('password')
+    sql_query = "SELECT * FROM introduction_login WHERE user='"+name+"' AND password='"+password+"'"
+    cursor.execute(sql_query)
+    return cursor.fetchone()
""",
    ),

    TestCase(
        id="V02",
        name="SQL Injection — Lab Table",
        cwe="CWE-89",
        description="Second SQL injection via string concatenation in lab handler",
        expected_keywords=["sql", "inject", "query"],
        expected_min_severity="CRITICAL",
        is_vulnerable=True,
        diff="""\
diff --git a/introduction/views.py b/introduction/views.py
--- a/introduction/views.py
+++ b/introduction/views.py
@@ -862,6 +862,8 @@
+def sql_lab(request):
+    name = request.POST.get('name')
+    password = request.POST.get('password')
+    sql_query = "SELECT * FROM introduction_sql_lab_table WHERE id='"+name+"'AND password='"+password+"'"
+    cursor.execute(sql_query)
""",
    ),

    TestCase(
        id="V03",
        name="Command Injection — subprocess.Popen with shell=True",
        cwe="CWE-78",
        description="User-controlled input passed to subprocess.Popen with shell=True",
        expected_keywords=["command", "inject", "shell", "subprocess", "popen"],
        expected_min_severity="CRITICAL",
        is_vulnerable=True,
        diff="""\
diff --git a/introduction/views.py b/introduction/views.py
--- a/introduction/views.py
+++ b/introduction/views.py
@@ -420,6 +420,10 @@
+def cmd_lab(request):
+    domain = request.POST.get('domain')
+    command = "dig {}".format(domain)
+    process = subprocess.Popen(
+        command,
+        shell=True,
+        stdout=subprocess.PIPE,
+        stderr=subprocess.PIPE)
+    stdout, stderr = process.communicate()
""",
    ),

    TestCase(
        id="V04",
        name="Eval Injection — eval() on user input",
        cwe="CWE-95",
        description="eval() called directly on unsanitized user-supplied string",
        expected_keywords=["eval", "inject", "code execution", "arbitrary"],
        expected_min_severity="CRITICAL",
        is_vulnerable=True,
        diff="""\
diff --git a/introduction/views.py b/introduction/views.py
--- a/introduction/views.py
+++ b/introduction/views.py
@@ -456,6 +456,7 @@
+def cmd_lab2(request):
+    val = request.POST.get('val')
+    output = eval(val)
+    return render(request, 'Lab/CMD/cmd_lab2.html', {"output": output})
""",
    ),

    TestCase(
        id="V05",
        name="Path Traversal — user-controlled filename in file write",
        cwe="CWE-22",
        description="User input used to construct file path without sanitization",
        expected_keywords=["path", "traversal", "file", "directory"],
        expected_min_severity="HIGH",
        is_vulnerable=True,
        diff="""\
diff --git a/introduction/views.py b/introduction/views.py
--- a/introduction/views.py
+++ b/introduction/views.py
@@ -990,6 +990,8 @@
+def create_blog(request):
+    id = request.POST.get('id')
+    blog = request.POST.get('blog')
+    dirname = os.path.dirname(__file__)
+    filename = os.path.join(dirname, f"templates/Lab_2021/A3_Injection/Blogs/{id}.html")
+    file = open(filename, "w+")
+    file.write(blog)
+    file.close()
""",
    ),

    TestCase(
        id="V06",
        name="Hardcoded Django SECRET_KEY",
        cwe="CWE-798",
        description="Django SECRET_KEY hardcoded as string literal in settings file",
        expected_keywords=["secret", "hardcoded", "key", "credential"],
        expected_min_severity="CRITICAL",
        is_vulnerable=True,
        diff="""\
diff --git a/pygoat/settings.py b/pygoat/settings.py
--- a/pygoat/settings.py
+++ b/pygoat/settings.py
@@ -23,6 +23,7 @@
+# SECURITY WARNING: keep the secret key used in production secret!
+SECRET_KEY = 'lr66%-a!$km5ed@n5ug!tya5bv!0(yqwa1tn!q%0%3m2nh%oml'
+SENSITIVE_DATA = 'FLAGTHATNEEDSTOBEFOUND'
+DEBUG = True
""",
    ),

    TestCase(
        id="V07",
        name="ImageMath eval injection",
        cwe="CWE-95",
        description="User-controlled function_str passed to ImageMath.eval()",
        expected_keywords=["eval", "inject", "code execution", "image"],
        expected_min_severity="HIGH",
        is_vulnerable=True,
        diff="""\
diff --git a/introduction/views.py b/introduction/views.py
--- a/introduction/views.py
+++ b/introduction/views.py
@@ -580,6 +580,8 @@
+def img_lab(request):
+    file = request.FILES["file"]
+    function_str = request.POST.get("function")
+    img = Image.open(file)
+    output = ImageMath.eval(function_str, img=img)
+    return render(request, "lab.html", {"output": output})
""",
    ),

    TestCase(
        id="V08",
        name="Bare except swallowing all errors",
        cwe="CWE-390",
        description="Bare except: clause suppresses all exceptions silently",
        expected_keywords=["except", "error handling", "bare", "suppress"],
        expected_min_severity="MEDIUM",
        is_vulnerable=True,
        diff="""\
diff --git a/introduction/views.py b/introduction/views.py
--- a/introduction/views.py
+++ b/introduction/views.py
@@ -440,6 +440,8 @@
+def run_command(domain):
+    try:
+        result = subprocess.check_output("ping " + domain, shell=True)
+        return result
+    except:
+        return "Something went wrong"
""",
    ),

    TestCase(
        id="V09",
        name="Hardcoded database credentials",
        cwe="CWE-798",
        description="Database username and password hardcoded in connection string",
        expected_keywords=["hardcoded", "password", "credential", "secret"],
        expected_min_severity="CRITICAL",
        is_vulnerable=True,
        diff="""\
diff --git a/introduction/db.py b/introduction/db.py
--- /dev/null
+++ b/introduction/db.py
@@ -0,0 +1,8 @@
+import psycopg2
+
+DB_PASSWORD = "superSecret123!"
+DB_USER = "admin"
+DB_HOST = "prod-db.pygoat.internal"
+
+def get_connection():
+    return psycopg2.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD)
""",
    ),

    TestCase(
        id="V10",
        name="Missing authentication on sensitive endpoint",
        cwe="CWE-306",
        description="Admin data endpoint accessible without authentication check",
        expected_keywords=["auth", "authentication", "access control", "unauthorized"],
        expected_min_severity="HIGH",
        is_vulnerable=True,
        diff="""\
diff --git a/introduction/views.py b/introduction/views.py
--- a/introduction/views.py
+++ b/introduction/views.py
@@ -1,6 +1,12 @@
+def admin_panel(request):
+    users = User.objects.all().values('username', 'email', 'password')
+    return JsonResponse(list(users), safe=False)
+
+def export_user_data(request):
+    data = UserProfile.objects.all().values()
+    return JsonResponse(list(data), safe=False)
""",
    ),

    # --- CLEAN CASES (should produce 0 critical/high findings) ---

    TestCase(
        id="C01",
        name="Clean — parameterized SQL query",
        cwe="N/A",
        description="SQL query using parameterized placeholders — no injection risk",
        expected_keywords=[],
        is_vulnerable=False,
        diff="""\
diff --git a/introduction/views.py b/introduction/views.py
--- a/introduction/views.py
+++ b/introduction/views.py
@@ -1,6 +1,8 @@
+def get_user(username: str):
+    cursor.execute(
+        "SELECT * FROM users WHERE username = %s",
+        (username,)
+    )
+    return cursor.fetchone()
""",
    ),

    TestCase(
        id="C02",
        name="Clean — subprocess with argument list (no shell=True)",
        cwe="N/A",
        description="subprocess called with argument list, shell=False — safe",
        expected_keywords=[],
        is_vulnerable=False,
        diff="""\
diff --git a/introduction/views.py b/introduction/views.py
--- a/introduction/views.py
+++ b/introduction/views.py
@@ -1,6 +1,7 @@
+def run_ping(host: str):
+    allowed = ["8.8.8.8", "1.1.1.1"]
+    if host not in allowed:
+        raise ValueError("Host not allowed")
+    result = subprocess.run(["ping", "-c", "1", host], capture_output=True)
+    return result.stdout.decode()
""",
    ),

    TestCase(
        id="C03",
        name="Clean — secret loaded from environment variable",
        cwe="N/A",
        description="Secret key loaded from os.environ — not hardcoded",
        expected_keywords=[],
        is_vulnerable=False,
        diff="""\
diff --git a/pygoat/settings.py b/pygoat/settings.py
--- a/pygoat/settings.py
+++ b/pygoat/settings.py
@@ -1,4 +1,6 @@
+import os
+SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY')
+if not SECRET_KEY:
+    raise ValueError('DJANGO_SECRET_KEY environment variable not set')
""",
    ),

    TestCase(
        id="C04",
        name="Clean — safe file path with validation",
        cwe="N/A",
        description="File path constructed with whitelist validation",
        expected_keywords=[],
        is_vulnerable=False,
        diff="""\
diff --git a/introduction/views.py b/introduction/views.py
--- a/introduction/views.py
+++ b/introduction/views.py
@@ -1,8 +1,12 @@
+import re
+
+def read_template(name: str):
+    if not re.match(r'^[a-zA-Z0-9_-]+$', name):
+        raise ValueError("Invalid template name")
+    base = os.path.abspath("templates/")
+    path = os.path.join(base, f"{name}.html")
+    if not path.startswith(base):
+        raise ValueError("Path traversal detected")
+    with open(path) as f:
+        return f.read()
""",
    ),

    TestCase(
        id="C05",
        name="Clean — well-written utility with tests",
        cwe="N/A",
        description="Clean calculator module with docstrings, type hints, error handling",
        expected_keywords=[],
        is_vulnerable=False,
        diff="""\
diff --git a/introduction/utils.py b/introduction/utils.py
--- /dev/null
+++ b/introduction/utils.py
@@ -0,0 +1,20 @@
+def sanitize_username(username: str) -> str:
+    \"\"\"Strip whitespace and lowercase a username.\"\"\"
+    if not isinstance(username, str):
+        raise TypeError(f"Expected str, got {type(username).__name__}")
+    return username.strip().lower()
+
+def is_valid_email(email: str) -> bool:
+    \"\"\"Return True if email contains @ and a domain.\"\"\"
+    if not isinstance(email, str):
+        raise TypeError(f"Expected str, got {type(email).__name__}")
+    parts = email.strip().split("@")
+    return len(parts) == 2 and len(parts[0]) > 0 and "." in parts[1]
""",
    ),
]


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def meets_severity(findings, min_severity: str) -> bool:
    threshold = SEVERITY_RANK.get(min_severity, 0)
    return any(SEVERITY_RANK.get(f.severity.value, 0) >= threshold for f in findings)


def keywords_matched(findings, keywords: list[str]) -> bool:
    if not keywords:
        return True
    text = " ".join(
        f"{f.title} {f.description} {f.category}".lower() for f in findings
    )
    return any(kw.lower() in text for kw in keywords)


@dataclass
class Result:
    case: TestCase
    findings_count: int
    has_critical_or_high: bool
    severity_met: bool
    keywords_matched: bool
    correct: bool
    elapsed: float
    prompt_tokens: int
    completion_tokens: int
    findings_summary: list[str]


def evaluate(client, case: TestCase) -> Result:
    start = time.time()
    report, usage = run_vuln_scan(client, case.diff, "Nisarg01-01/pygoat")
    elapsed = time.time() - start

    critical_or_high = [
        f for f in report.findings
        if f.severity.value in ("CRITICAL", "HIGH")
    ]
    has_crit_high = len(critical_or_high) > 0

    if case.is_vulnerable:
        sev_met = meets_severity(report.findings, case.expected_min_severity)
        kw_met = keywords_matched(report.findings, case.expected_keywords)
        correct = has_crit_high and sev_met
    else:
        sev_met = True
        kw_met = True
        correct = not has_crit_high

    return Result(
        case=case,
        findings_count=len(report.findings),
        has_critical_or_high=has_crit_high,
        severity_met=sev_met,
        keywords_matched=kw_met,
        correct=correct,
        elapsed=elapsed,
        prompt_tokens=usage.prompt_tokens,
        completion_tokens=usage.completion_tokens,
        findings_summary=[
            f"  [{f.severity.value}] {f.title} ({f.file_path}:{f.line_number})"
            for f in report.findings
        ],
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def build_client() -> ChatCompletionsClient:
    endpoint = os.environ["PROJECT_ENDPOINT"].split("/api/projects")[0] + "/models"
    return ChatCompletionsClient(
        endpoint=endpoint,
        credential=DefaultAzureCredential(),
        credential_scopes=["https://cognitiveservices.azure.com/.default"],
    )


TRIAGE_CASES = [
    {
        "id": "T01",
        "name": "Code PR with SQL injection",
        "metadata": {"title": "Add login endpoint", "changed_files": ["views.py"], "additions": 15, "deletions": 0},
        "diff": 'diff --git a/views.py b/views.py\n+sql = "SELECT * FROM users WHERE name=\'" + name + "\'"',
        "expect_vuln": True,
        "expect_standards": True,
    },
    {
        "id": "T02",
        "name": "Docs-only PR (README change)",
        "metadata": {"title": "Update README", "changed_files": ["README.md"], "additions": 5, "deletions": 2},
        "diff": "diff --git a/README.md b/README.md\n+## New section\n+Added documentation.",
        "expect_vuln": False,
        "expect_standards": False,
    },
    {
        "id": "T03",
        "name": "Config-only PR (requirements.txt)",
        "metadata": {"title": "Pin dependency versions", "changed_files": ["requirements.txt"], "additions": 3, "deletions": 3},
        "diff": "diff --git a/requirements.txt b/requirements.txt\n+django==4.2.0\n+requests==2.31.0",
        "expect_vuln": True,
        "expect_standards": False,
    },
    {
        "id": "T04",
        "name": "Auth middleware change",
        "metadata": {"title": "Refactor auth middleware", "changed_files": ["middleware.py"], "additions": 30, "deletions": 20},
        "diff": "diff --git a/middleware.py b/middleware.py\n+def authenticate(request):\n+    token = request.headers.get('Authorization')\n+    return verify_token(token)",
        "expect_vuln": True,
        "expect_standards": True,
    },
    {
        "id": "T05",
        "name": "Test file only",
        "metadata": {"title": "Add unit tests", "changed_files": ["tests/test_views.py"], "additions": 40, "deletions": 0},
        "diff": "diff --git a/tests/test_views.py b/tests/test_views.py\n+def test_login():\n+    response = client.post('/login', data={'user': 'test'})\n+    assert response.status_code == 200",
        "expect_vuln": True,
        "expect_standards": True,
    },
]


def run_triage_benchmark(client) -> dict:
    print("\n" + "=" * 65)
    print("TRIAGE ROUTING ACCURACY")
    print("=" * 65)

    correct = 0
    total = len(TRIAGE_CASES)
    triage_token_totals = {"prompt": 0, "completion": 0}

    print(f"\n  {'ID':<5} {'Name':<40} {'VulnExp':<8} {'VulnGot':<8} {'StdExp':<8} {'StdGot':<8} {'OK'}")
    print(f"  {'-'*5} {'-'*40} {'-'*8} {'-'*8} {'-'*8} {'-'*8} {'-'*4}")

    for tc in TRIAGE_CASES:
        try:
            decision, usage = run_triage(client, tc["metadata"], tc["diff"])
            triage_token_totals["prompt"] += usage.prompt_tokens
            triage_token_totals["completion"] += usage.completion_tokens

            vuln_correct = decision.should_run_vuln_scan == tc["expect_vuln"]
            std_correct = decision.should_run_standards_check == tc["expect_standards"]
            case_correct = vuln_correct and std_correct
            if case_correct:
                correct += 1

            print(f"  {tc['id']:<5} {tc['name']:<40} "
                  f"{'Y' if tc['expect_vuln'] else 'N':<8} "
                  f"{'Y' if decision.should_run_vuln_scan else 'N':<8} "
                  f"{'Y' if tc['expect_standards'] else 'N':<8} "
                  f"{'Y' if decision.should_run_standards_check else 'N':<8} "
                  f"{'✓' if case_correct else '✗'}")
        except Exception as e:
            print(f"  {tc['id']:<5} {tc['name']:<40} ERROR: {e}")

    accuracy = correct / total if total else 0
    avg_prompt = triage_token_totals["prompt"] / total if total else 0
    avg_completion = triage_token_totals["completion"] / total if total else 0

    print(f"\nTriage accuracy  : {correct}/{total} ({accuracy*100:.0f}%)")
    print(f"Avg tokens/call  : {avg_prompt:.0f}p / {avg_completion:.0f}c "
          f"({avg_prompt + avg_completion:.0f} total)")

    return {
        "triage_accuracy": round(accuracy, 3),
        "triage_correct": correct,
        "triage_total": total,
        "triage_avg_prompt_tokens": round(avg_prompt),
        "triage_avg_completion_tokens": round(avg_completion),
    }


def main():
    print("Sentinel Vulnerability Detection Benchmark")
    print("Target: OWASP PyGoat (10 vulnerable + 5 clean cases)")
    print("=" * 65)

    client = build_client()
    results: list[Result] = []

    for case in CASES:
        label = "VULN" if case.is_vulnerable else "CLEAN"
        print(f"\n[{case.id}] {case.name} ({label})")
        print(f"     CWE: {case.cwe}")
        try:
            result = evaluate(client, case)
            results.append(result)
            status = "PASS" if result.correct else "FAIL"
            print(f"     Result: {status} | Findings: {result.findings_count} | "
                  f"Critical/High: {result.has_critical_or_high} | "
                  f"Time: {result.elapsed:.1f}s | "
                  f"Tokens: {result.prompt_tokens}p/{result.completion_tokens}c")
            for line in result.findings_summary:
                print(line)
        except Exception as e:
            print(f"     ERROR: {e}")

    # --- Detection metrics ---
    print("\n" + "=" * 65)
    print("BENCHMARK RESULTS")
    print("=" * 65)

    vuln_cases = [r for r in results if r.case.is_vulnerable]
    clean_cases = [r for r in results if not r.case.is_vulnerable]

    true_positives = sum(1 for r in vuln_cases if r.correct)
    false_negatives = sum(1 for r in vuln_cases if not r.correct)
    true_negatives = sum(1 for r in clean_cases if r.correct)
    false_positives = sum(1 for r in clean_cases if not r.correct)

    total_vuln = len(vuln_cases)
    total_clean = len(clean_cases)

    recall = true_positives / total_vuln if total_vuln else 0
    fpr = false_positives / total_clean if total_clean else 0
    precision = (
        true_positives / (true_positives + false_positives)
        if (true_positives + false_positives) > 0 else 0
    )
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0 else 0
    )
    avg_time = sum(r.elapsed for r in results) / len(results) if results else 0
    total_prompt = sum(r.prompt_tokens for r in results)
    total_completion = sum(r.completion_tokens for r in results)
    avg_prompt = total_prompt / len(results) if results else 0
    avg_completion = total_completion / len(results) if results else 0

    print(f"\nVulnerable cases : {total_vuln}")
    print(f"  True positives : {true_positives} ({recall*100:.0f}% detection rate)")
    print(f"  False negatives: {false_negatives}")
    print(f"\nClean cases      : {total_clean}")
    print(f"  True negatives : {true_negatives}")
    print(f"  False positives: {false_positives} ({fpr*100:.0f}% false positive rate)")
    print(f"\nPrecision        : {precision*100:.0f}%")
    print(f"Recall           : {recall*100:.0f}%")
    print(f"F1 Score         : {f1:.2f}")
    print(f"Avg review time  : {avg_time:.1f}s per case")
    print(f"Avg tokens/call  : {avg_prompt:.0f}p / {avg_completion:.0f}c "
          f"({avg_prompt + avg_completion:.0f} total)")

    print("\nPer-case breakdown:")
    print(f"  {'ID':<5} {'Name':<45} {'Expected':<8} {'Result':<6} {'Pass':<4} {'Tokens'}")
    print(f"  {'-'*5} {'-'*45} {'-'*8} {'-'*6} {'-'*4} {'-'*12}")
    for r in results:
        expected = "VULN" if r.case.is_vulnerable else "CLEAN"
        got = "VULN" if r.has_critical_or_high else "CLEAN"
        status = "✓" if r.correct else "✗"
        tokens = r.prompt_tokens + r.completion_tokens
        print(f"  {r.case.id:<5} {r.case.name:<45} {expected:<8} {got:<6} {status:<4} {tokens}")

    # --- Triage accuracy ---
    triage_stats = run_triage_benchmark(client)

    print("\n" + "=" * 65)

    # Save results to JSON
    output = {
        "model": os.environ.get("MODEL", "Phi-4-1"),
        "total_cases": len(results),
        "true_positives": true_positives,
        "false_negatives": false_negatives,
        "true_negatives": true_negatives,
        "false_positives": false_positives,
        "recall": round(recall, 3),
        "precision": round(precision, 3),
        "f1_score": round(f1, 3),
        "false_positive_rate": round(fpr, 3),
        "avg_review_time_seconds": round(avg_time, 1),
        "avg_prompt_tokens": round(avg_prompt),
        "avg_completion_tokens": round(avg_completion),
        "avg_total_tokens": round(avg_prompt + avg_completion),
        **triage_stats,
        "cases": [
            {
                "id": r.case.id,
                "name": r.case.name,
                "cwe": r.case.cwe,
                "is_vulnerable": r.case.is_vulnerable,
                "correct": r.correct,
                "findings_count": r.findings_count,
                "has_critical_or_high": r.has_critical_or_high,
                "elapsed": round(r.elapsed, 1),
                "prompt_tokens": r.prompt_tokens,
                "completion_tokens": r.completion_tokens,
                "total_tokens": r.prompt_tokens + r.completion_tokens,
                "findings": r.findings_summary,
            }
            for r in results
        ],
    }

    out_path = os.path.join(os.path.dirname(__file__), "benchmark_results.json")
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"Results saved to: {out_path}")


if __name__ == "__main__":
    main()
