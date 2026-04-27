# Sentinel

Automated PR security reviewer that runs on every pull request and posts findings directly to GitHub.

When a PR is opened, Sentinel fetches the diff, routes it through specialist agents, and posts a structured review comment — flagging hardcoded secrets, SQL injection, architecture violations, and code quality issues before they get merged.

---

## How it works

```
PR opened
    │
    ▼
Triage Agent          reads the diff, decides which checks to run
    │
    ├──► Vulnerability Agent   hardcoded secrets, SQL injection, insecure deps
    ├──► Drift Agent           ADR violations (via Azure AI Search RAG)
    └──► Standards Agent       test coverage, naming, error handling score
              │
              ▼
         Report Agent          merges all findings → GitHub PR comment + inline comments
```

Each agent is a single `ChatCompletionsClient.complete()` call with a structured prompt. The model returns JSON that gets validated by Pydantic before anything downstream uses it. The triage step skips agents that aren't relevant — a docs-only PR doesn't run a vulnerability scan.

All diffs are sanitized for prompt injection before reaching the model. The output is validated for logical consistency after — if the model returns zero findings on a diff with a secret assignment, that's treated as a guardrail failure and flagged.

---

## Architecture

```
GitHub PR
    │
    │  diff + metadata
    ▼
┌─────────────────────────────────────────────────────┐
│  Orchestrator  (src/orchestrator.py)                │
│                                                     │
│  ┌─────────────┐   ┌──────────────┐                │
│  │ Triage      │   │ Guardrails   │ sanitize_diff() │
│  │ Agent       │   │ (src/        │ validate_*()    │
│  └──────┬──────┘   │ guardrails)  │                │
│         │          └──────────────┘                │
│    ┌────┴────┐                                     │
│    │         │                                     │
│  ┌─▼──┐  ┌──▼──┐  ┌──────────┐                   │
│  │Vuln│  │Drift│  │Standards │                    │
│  │    │  │     │  │          │                    │
│  └──┬─┘  └──┬──┘  └────┬─────┘                   │
│     └────────┴──────────┘                         │
│                  │                                 │
│           ┌──────▼──────┐                         │
│           │ Report Agent │                         │
│           └──────┬───────┘                         │
└──────────────────┼──────────────────────────────────┘
                   │
          ┌────────┴────────┐
          │                 │
    PR review comment   Inline comments
    (GitHub API)        on CRITICAL/HIGH lines
```

**Azure services used:**

| Service | Role |
|---|---|
| Azure AI Foundry | Hosts Phi-4, serves inference endpoint |
| Phi-4 (Phi-4-1) | Model powering all five agents |
| Azure AI Search | Stores ADR documents, retrieved per-diff via RAG |
| Application Insights | Receives OpenTelemetry traces from every run |
| Azure Entra Service Principal | CI identity used by GitHub Actions |

---

## Setup

### Prerequisites

- Python 3.11+
- An Azure account with AI Foundry access and a deployed Phi-4 model
- A GitHub repo with a fine-grained PAT (pull-requests: read/write, contents: read)
- Azure AI Search service with an index named `sentinel-adrs`
- Application Insights resource (optional — telemetry is skipped if not configured)

### Local

```bash
git clone https://github.com/Nisarg01-01/sentinel-pr-review
cd sentinel-pr-review
conda create -n sentinel python=3.11
conda activate sentinel
pip install -r requirements.txt
az login
```

Copy `.env.example` to `.env` and fill in your values:

```
PROJECT_ENDPOINT=https://<resource>.services.ai.azure.com/api/projects/<project>
MODEL=Phi-4-1
GITHUB_TOKEN=<your PAT>
GITHUB_REPO=<owner/repo>
AZURE_SEARCH_ENDPOINT=https://<service>.search.windows.net
AZURE_SEARCH_INDEX=sentinel-adrs
AZURE_SEARCH_KEY=<admin key>
APPLICATIONINSIGHTS_CONNECTION_STRING=<optional>
```

Upload ADR documents to the search index:

```bash
python setup_search.py
```

Run against a PR:

```bash
python -m src.orchestrator 1 --dry-run   # preview without posting
python -m src.orchestrator 1             # post the review
```

### GitHub Actions

Add these secrets to your repository (Settings → Secrets → Actions):

| Secret | Value |
|---|---|
| `AZURE_FOUNDRY_ENDPOINT` | Your `PROJECT_ENDPOINT` value |
| `AZURE_CLIENT_ID` | Service principal app ID |
| `AZURE_TENANT_ID` | Azure tenant ID |
| `AZURE_CLIENT_SECRET` | Service principal password |
| `SENTINEL_GITHUB_TOKEN` | GitHub PAT |
| `AZURE_SEARCH_ENDPOINT` | Azure AI Search URL |
| `AZURE_SEARCH_KEY` | Azure AI Search admin key |

Create the service principal:

```bash
az ad sp create-for-rbac \
  --name "sentinel-github-actions" \
  --role "Cognitive Services User" \
  --scopes /subscriptions/<id>/resourceGroups/<rg>
```

The workflow at `.github/workflows/sentinel.yml` triggers on `pull_request` (opened, synchronize, reopened) against `main`/`master`.

---

## Agents

### Triage Agent
Reads the PR diff and metadata, decides which specialist agents to run. A docs-only PR skips the vulnerability scan. A config-only change skips the drift check. Outputs a `TriageDecision` with routing flags and a risk level.

### Vulnerability Agent
Scans for: hardcoded secrets (passwords, API keys, tokens), SQL/command injection via string concatenation, insecure dependency versions, missing auth checks, and sensitive data in logs. Returns a `VulnReport` with per-finding severity, file path, line number, and fix recommendation.

### Drift Agent
Retrieves the three most relevant ADR documents from Azure AI Search using keywords extracted from the diff, then checks whether the new code violates any of them. Returns a `DriftReport` with ADR references.

### Standards Agent
Scores the PR 0–100 on: test coverage, docstrings, naming quality, function length, error handling, and magic numbers. Returns a `QualityReport` with per-finding suggestions.

### Report Agent
Pure Python — no LLM call. Merges all three reports into a `FinalReview`, determines the overall verdict (APPROVE / COMMENT / REQUEST_CHANGES) by severity, and formats the GitHub comment in Markdown with emoji severity indicators and an action item checklist.

---

## Guardrails

PR diffs are user-controlled input. `src/guardrails.py` provides two layers of protection:

**Input sanitization** — `sanitize_diff()` scans every new line in the diff for prompt injection patterns (instruction overrides, role hijacking, direct JSON injection). Flagged lines are replaced with `[REDACTED]` before the diff reaches the model.

**Output validation** — `validate_vuln_output()` and `validate_triage_output()` check the model's response for logical inconsistencies. If the vuln agent returns empty findings on a diff with a secret variable assignment, or if triage skips all agents on a 20-line code diff, these are treated as guardrail failures. The agents fail safe: triage defaults to running everything, vuln injects a HIGH finding flagging the anomaly for manual review.

---

## Tests

```bash
# Fast unit tests — no LLM calls (~8 seconds)
conda run -n sentinel pytest tests/test_guardrails.py -v

# Integration tests — calls Phi-4 for real (~90 seconds)
conda run -n sentinel pytest tests/test_eval.py -v

# Everything
conda run -n sentinel pytest -v
```

The eval suite (`test_eval.py`) uses synthetic `.diff` fixtures with known issues baked in and asserts the agent catches them. These are integration tests against the real model — mocking the LLM would only test JSON parsing, not whether the prompts actually work.

---

## Benchmark Results

Evaluated against 15 test cases extracted from OWASP PyGoat — an intentionally vulnerable Django application (4,000+ GitHub stars). 10 vulnerable cases cover distinct CWE categories; 5 clean cases measure false positive rate. Each case calls `run_vuln_scan()` directly against a real git diff.

| Metric | Score |
|---|---|
| **Recall (detection rate)** | **100%** — 10/10 vulnerable cases caught |
| **Precision** | **83%** — 10/12 positive flags were true positives |
| **F1 Score** | **0.91** |
| **False positive rate** | 40% (2/5 clean cases) |
| **Triage routing accuracy** | **100%** — 5/5 routing decisions correct |
| **Avg review time** | 4.2 seconds per case |
| **Avg tokens per vuln scan** | 756 (595 prompt / 160 completion) |
| **Avg tokens per triage** | 590 (504 prompt / 87 completion) |

Vulnerable cases covered: SQL injection (×2, CWE-89), command injection (CWE-78), eval injection (CWE-95), path traversal (CWE-22), hardcoded secrets (CWE-798, ×2), ImageMath eval (CWE-95), bare except (CWE-390), missing authentication (CWE-306). All 10 detected at CRITICAL severity.

False positives: `subprocess` with argument list (no `shell=True`) flagged as command injection; `os.path.join` with whitelisted input flagged as path traversal. Both are model over-sensitivity to pattern presence without full data-flow context — a known limitation of diff-scope analysis.

Full results: `benchmark/benchmark_results.json`. Benchmark runner: `benchmark/run_benchmark.py`.

---

## Real-World GitHub Actions Test

Installed as a composite action on a fork of OWASP PyGoat. Three PRs submitted; Sentinel ran end-to-end via GitHub Actions (Actions → orchestrator → Phi-4 → GitHub PR comment).

| Metric | Result |
|---|---|
| **Detection rate** | 1/1 — caught real SQL injection at exact line (`introduction/views.py:159`) |
| **False positive rate** | 0 on clean utility code — COMMENT, not REQUEST_CHANGES |
| **ADR cross-reference** | 3 architecture violations traced to ADR-002 (auth) and ADR-003 (error handling) |
| **Verdict accuracy** | REQUEST_CHANGES on vulnerable PR, COMMENT on clean PR |
| **Guardrail effectiveness** | Caught `risk_level: NONE` invalid enum, triggered safe fallback, pipeline did not crash |

### PR 1 — SQL Injection in OWASP PyGoat

Modified `introduction/views.py:159` — a real string-concatenation SQL query. Sentinel returned:

```
Verdict:  REQUEST_CHANGES
Severity: CRITICAL
Findings: 1 security issue, 3 architecture violations
```

Finding: `"SELECT * FROM introduction_login WHERE user='"+name+"'"` flagged CRITICAL with parameterized query recommendation, cross-referenced against ADR-002 and ADR-003.

### PR 2 — Clean Utility Code

Added `introduction/utils.py` with two typed, documented utility functions. Sentinel returned:

```
Verdict:  COMMENT
Severity: LOW
Security findings: 0
Quality score: 80/100
```

### PR 3 — Docs-Only PR (Guardrail Test)

Changed only `README.md`. Triage returned `risk_level: NONE` (invalid enum). Guardrail caught it, defaulted to running all agents, pipeline completed without crashing.

**Average review time:** ~45–60 seconds per PR (includes GitHub API round-trips).

---

## How Sentinel differs from GitHub Copilot code review

GitHub Copilot code review is a general-purpose reviewer — one model pass over the diff producing prose suggestions. Sentinel is purpose-built for security and compliance enforcement with a different architecture.

| Capability | GitHub Copilot review | Sentinel |
|---|---|---|
| **Architectural memory** | None — no knowledge of team decisions | RAG over your ADR documents — violations traced to specific ADR by name |
| **Agent specialization** | Single general-purpose pass | Separate agents for security, architecture, and quality — each with a focused prompt |
| **Triage / cost efficiency** | Same review on every PR | Triage agent skips irrelevant checks — docs-only PR costs one fast call |
| **Output format** | Prose comments | Pydantic-validated JSON — severity, CWE, file, line, recommendation |
| **Merge gating** | Suggestion only | Structured verdict (APPROVE / COMMENT / REQUEST\_CHANGES) by severity |
| **Guardrails on model output** | None | Output validated for logical consistency — invalid responses trigger safe fallback |
| **Observability** | None | Per-agent token counts and findings exported to Application Insights via OpenTelemetry |

**Where Copilot is stronger:** it sees the full file context (not diff-only), uses a more capable model (fewer false positives), and integrates into the IDE. Sentinel's 40% false positive rate on clean code reflects the diff-scope limitation and smaller model.

**Where Sentinel fills a gap:** teams with compliance requirements (specific ADRs, security policies, merge gates by severity) need a reviewer that knows their rules — not just generic best practices. Sentinel's RAG-based drift detection and structured output are designed for that use case.

---

## Project structure

```
sentinel-pr-review/
├── src/
│   ├── orchestrator.py        entry point, wires all agents together
│   ├── guardrails.py          prompt injection sanitization + output validation
│   ├── telemetry.py           OpenTelemetry setup → Application Insights
│   ├── models.py              Pydantic models for all agent outputs
│   ├── github_client.py       PR diff fetching, review posting, inline comments
│   └── agents/
│       ├── triage_agent.py
│       ├── vuln_agent.py
│       ├── drift_agent.py
│       ├── standards_agent.py
│       └── report_agent.py
├── tests/
│   ├── test_eval.py           agent behaviour tests (integration)
│   ├── test_guardrails.py     guardrail unit + integration tests
│   └── fixtures/              synthetic .diff files used by tests
├── adr_documents/             ADR markdown files uploaded to Azure AI Search
├── benchmark/
│   ├── run_benchmark.py       15-case precision/recall/F1 evaluation script
│   └── benchmark_results.json results from last run
├── setup_search.py            uploads ADRs to the search index
├── action.yml                 reusable GitHub Actions composite action
└── .github/workflows/
    └── sentinel.yml           GitHub Actions trigger
```
