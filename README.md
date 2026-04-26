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
├── setup_search.py            uploads ADRs to the search index
└── .github/workflows/
    └── sentinel.yml           GitHub Actions trigger
```
