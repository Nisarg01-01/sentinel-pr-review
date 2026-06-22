"""
Sentinel Vulnerability Detection Benchmark

Evaluates Sentinel's vuln agent against 10 vulnerable and 5 clean Python snippets
extracted directly from OWASP PyGoat. Each snippet is wrapped as a git diff and
passed to run_vuln_scan() â€” the same function that runs in production.

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

_repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _repo_root)
load_dotenv(os.path.join(_repo_root, ".env"))

from openai import AzureOpenAI
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
# Benchmark cases â€” real code extracted from OWASP PyGoat
# ---------------------------------------------------------------------------

CASES: list[TestCase] = [

    # --- VULNERABLE CASES ---

    TestCase(
        id="V01",
        name="SQL Injection â€” Login Handler",
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
        name="SQL Injection â€” Lab Table",
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
        name="Command Injection â€” subprocess.Popen with shell=True",
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
        name="Eval Injection â€” eval() on user input",
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
        name="Path Traversal â€” user-controlled filename in file write",
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

    TestCase(
        id="V11",
        name="SQL Injection â€” f-string formatting",
        cwe="CWE-89",
        description="f-string used to interpolate user input directly into SQL query",
        expected_keywords=["sql", "inject", "f-string", "format"],
        expected_min_severity="CRITICAL",
        is_vulnerable=True,
        diff="""\
diff --git a/introduction/views.py b/introduction/views.py
--- a/introduction/views.py
+++ b/introduction/views.py
@@ -1,6 +1,8 @@
+def get_user_by_id(request):
+    user_id = request.GET.get('id')
+    query = f"SELECT * FROM users WHERE id={user_id}"
+    cursor.execute(query)
+    return cursor.fetchone()
""",
    ),

    TestCase(
        id="V12",
        name="Hardcoded secret inside config dict",
        cwe="CWE-798",
        description="API key hardcoded as a value inside a configuration dictionary",
        expected_keywords=["hardcoded", "secret", "api_key", "credential"],
        expected_min_severity="CRITICAL",
        is_vulnerable=True,
        diff="""\
diff --git a/pygoat/config.py b/pygoat/config.py
--- /dev/null
+++ b/pygoat/config.py
@@ -0,0 +1,6 @@
+SERVICES = {
+    "stripe": {
+        "api_key": "sk_live_EXAMPLE_PLACEHOLDER_NOT_REAL",
+        "webhook_secret": "whsec_EXAMPLE_PLACEHOLDER_NOT_REAL",
+    }
+}
""",
    ),

    TestCase(
        id="V13",
        name="Command injection via os.system",
        cwe="CWE-78",
        description="User input passed directly to os.system without sanitization",
        expected_keywords=["command", "inject", "os.system", "shell"],
        expected_min_severity="CRITICAL",
        is_vulnerable=True,
        diff="""\
diff --git a/introduction/views.py b/introduction/views.py
--- a/introduction/views.py
+++ b/introduction/views.py
@@ -1,5 +1,7 @@
+import os
+
+def run_diagnostic(request):
+    host = request.POST.get('host')
+    os.system("ping -c 1 " + host)
+    return HttpResponse("Done")
""",
    ),

    # --- CLEAN CASES (should produce 0 critical/high findings) ---

    TestCase(
        id="C01",
        name="Clean â€” parameterized SQL query",
        cwe="N/A",
        description="SQL query using parameterized placeholders â€” no injection risk",
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
        name="Clean â€” subprocess with argument list (no shell=True)",
        cwe="N/A",
        description="subprocess called with argument list, shell=False â€” safe",
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
        name="Clean â€” secret loaded from environment variable",
        cwe="N/A",
        description="Secret key loaded from os.environ â€” not hardcoded",
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
        name="Clean â€” safe file path with validation",
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
        name="Clean â€” well-written utility with tests",
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

    TestCase(
        id="C06",
        name="Clean â€” Django ORM query (not raw SQL)",
        cwe="N/A",
        description="Django ORM filter with user input â€” parameterized by the ORM, not raw SQL",
        expected_keywords=[],
        is_vulnerable=False,
        diff="""\
diff --git a/introduction/views.py b/introduction/views.py
--- a/introduction/views.py
+++ b/introduction/views.py
@@ -1,6 +1,10 @@
+from django.contrib.auth.models import User
+from django.http import JsonResponse
+
+def search_users(request):
+    username = request.GET.get('username', '')
+    users = User.objects.filter(username__icontains=username).values('id', 'username')
+    return JsonResponse(list(users), safe=False)
""",
    ),

    # --- NOISY DIFF CASES â€” vulnerability hidden in large legitimate change ---

    TestCase(
        id="N01",
        name="Noisy â€” SQL injection buried in 60-line feature addition",
        cwe="CWE-89",
        description="One SQL injection line hidden among 60 lines of legitimate Django view code",
        expected_keywords=["sql", "inject", "query", "concatenat"],
        expected_min_severity="CRITICAL",
        is_vulnerable=True,
        diff="""\
diff --git a/introduction/views.py b/introduction/views.py
--- a/introduction/views.py
+++ b/introduction/views.py
@@ -1,6 +1,65 @@
+import os
+import json
+import logging
+from django.shortcuts import render, redirect
+from django.http import JsonResponse, HttpResponse
+from django.contrib.auth.decorators import login_required
+from django.views.decorators.csrf import csrf_protect
+from django.core.paginator import Paginator
+from django.utils import timezone
+
+logger = logging.getLogger(__name__)
+
+@login_required
+@csrf_protect
+def user_dashboard(request):
+    \"\"\"Render the main user dashboard with activity feed.\"\"\"
+    context = {
+        'user': request.user,
+        'timestamp': timezone.now(),
+        'notifications': get_user_notifications(request.user),
+    }
+    return render(request, 'dashboard/index.html', context)
+
+def get_user_notifications(user):
+    \"\"\"Return unread notifications for a user.\"\"\"
+    from .models import Notification
+    return Notification.objects.filter(user=user, read=False).order_by('-created_at')[:10]
+
+@login_required
+def update_profile(request):
+    \"\"\"Handle profile update form submission.\"\"\"
+    if request.method != 'POST':
+        return redirect('profile')
+    name = request.POST.get('display_name', '').strip()
+    bio = request.POST.get('bio', '').strip()
+    if len(name) > 100:
+        return JsonResponse({'error': 'Name too long'}, status=400)
+    request.user.profile.display_name = name
+    request.user.profile.bio = bio
+    request.user.profile.save()
+    logger.info(f"Profile updated for user {request.user.id}")
+    return JsonResponse({'status': 'ok'})
+
+@login_required
+def search_activity_log(request):
+    \"\"\"Search activity logs by username â€” admin only.\"\"\"
+    if not request.user.is_staff:
+        return HttpResponse(status=403)
+    query = request.GET.get('username', '')
+    sql = "SELECT * FROM activity_log WHERE username='" + query + "'"
+    from django.db import connection
+    with connection.cursor() as cursor:
+        cursor.execute(sql)
+        rows = cursor.fetchall()
+    return JsonResponse({'results': rows})
+
+@login_required
+def export_report(request):
+    \"\"\"Export user activity report as JSON.\"\"\"
+    from .models import ActivityLog
+    logs = ActivityLog.objects.filter(user=request.user).values(
+        'action', 'timestamp', 'ip_address'
+    )
+    return JsonResponse(list(logs), safe=False)
""",
    ),

    TestCase(
        id="N02",
        name="Noisy â€” hardcoded secret among 50 lines of config",
        cwe="CWE-798",
        description="One hardcoded API key hidden among 50 lines of legitimate configuration",
        expected_keywords=["hardcoded", "secret", "api_key", "credential"],
        expected_min_severity="CRITICAL",
        is_vulnerable=True,
        diff="""\
diff --git a/pygoat/settings.py b/pygoat/settings.py
--- a/pygoat/settings.py
+++ b/pygoat/settings.py
@@ -1,6 +1,55 @@
+import os
+from pathlib import Path
+
+BASE_DIR = Path(__file__).resolve().parent.parent
+
+SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY')
+if not SECRET_KEY:
+    raise ValueError('DJANGO_SECRET_KEY not set')
+
+DEBUG = os.environ.get('DEBUG', 'False') == 'True'
+
+ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', '').split(',')
+
+INSTALLED_APPS = [
+    'django.contrib.admin',
+    'django.contrib.auth',
+    'django.contrib.contenttypes',
+    'django.contrib.sessions',
+    'django.contrib.messages',
+    'django.contrib.staticfiles',
+    'introduction',
+]
+
+MIDDLEWARE = [
+    'django.middleware.security.SecurityMiddleware',
+    'django.contrib.sessions.middleware.SessionMiddleware',
+    'django.middleware.common.CommonMiddleware',
+    'django.middleware.csrf.CsrfViewMiddleware',
+    'django.contrib.auth.middleware.AuthenticationMiddleware',
+]
+
+DATABASES = {
+    'default': {
+        'ENGINE': 'django.db.backends.sqlite3',
+        'NAME': BASE_DIR / 'db.sqlite3',
+    }
+}
+
+STATIC_URL = '/static/'
+MEDIA_URL = '/media/'
+MEDIA_ROOT = BASE_DIR / 'media'
+
+LOGGING = {
+    'version': 1,
+    'disable_existing_loggers': False,
+    'handlers': {'console': {'class': 'logging.StreamHandler'}},
+    'root': {'handlers': ['console'], 'level': 'WARNING'},
+}
+
+THIRD_PARTY_INTEGRATIONS = {
+    'sendgrid': {
+        'api_key': 'SG.realkey_abcdefghijklmnopqrstuvwxyz123456789',
+        'from_email': os.environ.get('SENDGRID_FROM_EMAIL'),
+    },
+    'sentry_dsn': os.environ.get('SENTRY_DSN'),
+}
""",
    ),

    TestCase(
        id="N03",
        name="Noisy â€” clean large refactor with no vulnerabilities",
        cwe="N/A",
        description="80-line refactor extracting helper functions â€” no vulnerabilities, tests false positive resistance on large diffs",
        expected_keywords=[],
        is_vulnerable=False,
        diff="""\
diff --git a/introduction/utils.py b/introduction/utils.py
--- /dev/null
+++ b/introduction/utils.py
@@ -0,0 +1,80 @@
+\"\"\"Utility functions for input validation and sanitization.\"\"\"
+import re
+import hashlib
+import logging
+from typing import Optional
+
+logger = logging.getLogger(__name__)
+
+
+def validate_username(username: str) -> bool:
+    \"\"\"Return True if username matches allowed pattern.\"\"\"
+    if not isinstance(username, str):
+        return False
+    return bool(re.match(r'^[a-zA-Z0-9_]{3,32}$', username))
+
+
+def validate_email(email: str) -> bool:
+    \"\"\"Return True if email is structurally valid.\"\"\"
+    if not isinstance(email, str):
+        return False
+    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
+    return bool(re.match(pattern, email.strip()))
+
+
+def sanitize_filename(filename: str) -> Optional[str]:
+    \"\"\"Strip path components and dangerous characters from a filename.\"\"\"
+    if not isinstance(filename, str):
+        return None
+    basename = re.sub(r'[^a-zA-Z0-9._-]', '', filename.split('/')[-1].split('\\\\')[-1])
+    if not basename or basename.startswith('.'):
+        return None
+    return basename
+
+
+def hash_value(value: str, salt: str) -> str:
+    \"\"\"Return a SHA-256 hex digest of value+salt.\"\"\"
+    combined = f"{salt}{value}".encode('utf-8')
+    return hashlib.sha256(combined).hexdigest()
+
+
+def paginate(queryset, page: int, per_page: int = 20) -> dict:
+    \"\"\"Return a page slice and pagination metadata.\"\"\"
+    page = max(1, int(page))
+    total = queryset.count()
+    total_pages = max(1, (total + per_page - 1) // per_page)
+    page = min(page, total_pages)
+    start = (page - 1) * per_page
+    return {
+        'items': list(queryset[start:start + per_page]),
+        'page': page,
+        'total_pages': total_pages,
+        'total': total,
+        'has_next': page < total_pages,
+        'has_prev': page > 1,
+    }
+
+
+def parse_int(value: str, default: int = 0) -> int:
+    \"\"\"Safely parse an integer from a string.\"\"\"
+    try:
+        return int(value)
+    except (ValueError, TypeError):
+        return default
+
+
+def mask_sensitive(value: str, visible_chars: int = 4) -> str:
+    \"\"\"Mask all but the last N characters of a sensitive string.\"\"\"
+    if not isinstance(value, str) or len(value) <= visible_chars:
+        return '***'
+    return '*' * (len(value) - visible_chars) + value[-visible_chars:]
+
+
+def get_client_ip(request) -> str:
+    \"\"\"Extract client IP from request, checking forwarded headers.\"\"\"
+    forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
+    if forwarded:
+        return forwarded.split(',')[0].strip()
+    return request.META.get('REMOTE_ADDR', '')
""",
    ),

    TestCase(
        id="C07",
        name="Clean â€” placeholder key in config template",
        cwe="N/A",
        description="Example/placeholder API key in a config template â€” not a real secret",
        expected_keywords=[],
        is_vulnerable=False,
        diff="""\
diff --git a/pygoat/settings.example.py b/pygoat/settings.example.py
--- /dev/null
+++ b/pygoat/settings.example.py
@@ -0,0 +1,8 @@
+# Copy this file to settings.py and fill in real values
+# Never commit settings.py to version control
+
+SECRET_KEY = 'your-secret-key-here'
+STRIPE_API_KEY = 'your-stripe-api-key'
+DATABASE_PASSWORD = 'your-database-password'
+DEBUG = False
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

def build_client() -> AzureOpenAI:
    base = os.environ["PROJECT_ENDPOINT"].split("/api/projects")[0]
    return AzureOpenAI(
        azure_endpoint=base,
        api_key=os.environ["AZURE_INFERENCE_KEY"],
        api_version="2025-01-01-preview",
        timeout=900,
    )


# Triage benchmark uses real PRs from Nisarg01-01/pygoat â€” triage agent fetches
# its own context via MCP tools (ReAct loop), so no synthetic diff/metadata needed.
TRIAGE_CASES = [
    {"id": "T01", "name": "SQL injection in views.py",          "pr_number": 1, "expect_vuln": True,  "expect_standards": True},
    {"id": "T02", "name": "Whitespace change near login handler","pr_number": 2, "expect_vuln": True,  "expect_standards": True},
    {"id": "T03", "name": "Input sanitization utilities added",  "pr_number": 3, "expect_vuln": True,  "expect_standards": True},
    {"id": "T04", "name": "Docs-only README change",            "pr_number": 7, "expect_vuln": False, "expect_standards": False},
]


def run_triage_benchmark(client) -> dict:
    print("\n" + "=" * 65)
    print("TRIAGE ROUTING ACCURACY  (real PRs from Nisarg01-01/pygoat)")
    print("=" * 65)

    correct = 0
    total = len(TRIAGE_CASES)
    triage_token_totals = {"prompt": 0, "completion": 0}

    print(f"\n  {'ID':<5} {'Name':<40} {'VulnExp':<8} {'VulnGot':<8} {'StdExp':<8} {'StdGot':<8} {'OK'}")
    print(f"  {'-'*5} {'-'*40} {'-'*8} {'-'*8} {'-'*8} {'-'*8} {'-'*4}")

    original_repo = os.environ.get("GITHUB_REPO")
    os.environ["GITHUB_REPO"] = "Nisarg01-01/pygoat"

    for tc in TRIAGE_CASES:
        try:
            decision, usage = run_triage(client, tc["pr_number"])
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
                  f"{'âœ“' if case_correct else 'âœ—'}")
        except Exception as e:
            print(f"  {tc['id']:<5} {tc['name']:<40} ERROR: {e}")

    if original_repo:
        os.environ["GITHUB_REPO"] = original_repo

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
    print("Target: OWASP PyGoat + adversarial + noisy diff cases (15 vulnerable + 8 clean)")
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
        status = "âœ“" if r.correct else "âœ—"
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
