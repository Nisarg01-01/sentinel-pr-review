# Sentinel

Automated PR security reviewer. When a pull request opens, Sentinel fetches the diff, routes it through specialist agents, and posts a structured review — flagging hardcoded secrets, SQL injection, architecture violations, and code quality issues before they get merged.

---

## How it works

The triage agent reads the diff and decides which specialist agents to run. A docs-only PR skips the vulnerability scan entirely. Each specialist agent makes one LLM call and returns structured JSON. The report agent merges all results and posts a GitHub review.

Guardrails run on both sides: `sanitize_diff()` strips prompt injection patterns before the diff reaches any agent, and `validate_output()` checks responses for logical inconsistencies — zero findings on a diff containing a hardcoded secret triggers a safe fallback instead of silently passing.

| Agent | What it does |
|---|---|
| Triage | Reads diff + metadata, decides which agents to run |
| Vulnerability | Scans for hardcoded secrets, SQL/command injection, insecure deps, missing auth |
| Drift | Retrieves relevant ADRs from Azure AI Search, checks diff for violations |
| Standards | Scores PR 0–100 on tests, naming, docstrings, error handling |
| Report | Pure Python — merges all reports, determines verdict, formats GitHub comment |

The GitHub API layer is a separate Azure Function that implements the [MCP (Model Context Protocol)](https://spec.modelcontextprotocol.io/specification/2025-03-26/) over JSON-RPC 2.0. Any MCP-compliant client — Claude Desktop, Cursor, or custom code — can connect to it and call `get_pr_diff`, `get_pr_metadata`, `get_file_content`, `post_review_comment`, and `post_inline_comment`.

---

## Results

### Benchmark — 15 cases from OWASP PyGoat

Model: gpt-4.1-mini, selected after benchmarking against Phi-4-1 and Phi-4-mini-instruct on the same 15 cases.

| Metric | Result |
|---|---|
| Recall | 100% — 10/10 vulnerable cases caught |
| Precision | 91% — 10/11 flags were true positives |
| F1 Score | 0.95 |
| False positive rate | 20% (1/5 clean cases) |
| Triage routing accuracy | 80% — 4/5 routing decisions correct |
| Avg review time | 2.5s per case |

CWEs covered: SQL injection (CWE-89), command injection (CWE-78), eval injection (CWE-95), path traversal (CWE-22), hardcoded secrets (CWE-798), bare except (CWE-390), missing auth (CWE-306).

### Live test — OWASP PyGoat on GitHub Actions

| PR | Change | Verdict |
|---|---|---|
| 1 | SQL injection in `views.py:159` | `REQUEST_CHANGES` · CRITICAL — exact line flagged, ADR-002 + ADR-003 cited |
| 2 | Clean utility functions | `COMMENT` · LOW — 0 security findings, quality 80/100 |
| 3 | README only | `COMMENT` — guardrail caught invalid triage output, safe fallback |

---

## Add Sentinel to your repo

Sentinel is a reusable GitHub Actions composite action. Add this workflow:

```yaml
# .github/workflows/sentinel.yml
name: Sentinel PR Review
on:
  pull_request:
    types: [opened, synchronize, reopened]
    branches: [main, master]

jobs:
  sentinel:
    runs-on: ubuntu-latest
    steps:
      - uses: Nisarg01-01/sentinel-pr-review@master
        with:
          project-endpoint: ${{ secrets.AZURE_FOUNDRY_ENDPOINT }}
          azure-inference-key: ${{ secrets.AZURE_INFERENCE_KEY }}
          azure-client-id: ${{ secrets.AZURE_CLIENT_ID }}
          azure-tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          azure-client-secret: ${{ secrets.AZURE_CLIENT_SECRET }}
          github-token: ${{ secrets.SENTINEL_GITHUB_TOKEN }}
          azure-search-endpoint: ${{ secrets.AZURE_SEARCH_ENDPOINT }}
          azure-search-key: ${{ secrets.AZURE_SEARCH_KEY }}
```

Add the 8 secrets under Settings → Secrets → Actions (see [Setup](#setup) for values).

---

## Setup

### Prerequisites

- Python 3.11+
- Azure AI Foundry with a deployed `gpt-4.1-mini` model
- GitHub fine-grained PAT (pull-requests: read/write, contents: read)
- Azure AI Search service with an index named `sentinel-adrs`

### Local

```bash
git clone https://github.com/Nisarg01-01/sentinel-pr-review
cd sentinel-pr-review
conda create -n sentinel python=3.11
conda activate sentinel
pip install -r requirements.txt
az login
```

Copy `.env.example` to `.env`:

```
PROJECT_ENDPOINT=https://<resource>.services.ai.azure.com/api/projects/<project>
AZURE_INFERENCE_KEY=<API key from Azure AI Foundry → Deployments → your model>
MODEL=gpt-4.1-mini
GITHUB_TOKEN=<your PAT>
GITHUB_REPO=<owner/repo>
AZURE_SEARCH_ENDPOINT=https://<service>.search.windows.net
AZURE_SEARCH_INDEX=sentinel-adrs
AZURE_SEARCH_KEY=<admin key>
APPLICATIONINSIGHTS_CONNECTION_STRING=<optional>
```

```bash
python setup_search.py                    # upload ADRs to search index
python -m src.orchestrator 1 --dry-run   # preview review without posting
python -m src.orchestrator 1             # post review to PR #1
```

### GitHub Actions

Add repository secrets under Settings → Secrets → Actions:

| Secret | Value |
|---|---|
| `AZURE_FOUNDRY_ENDPOINT` | `PROJECT_ENDPOINT` value |
| `AZURE_INFERENCE_KEY` | API key from Azure AI Foundry → Deployments → your model |
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

---

## Tests

```bash
# Unit tests — no LLM calls (~8s)
conda run -n sentinel pytest tests/test_guardrails.py -v

# Integration tests — calls gpt-4.1-mini (~90s)
conda run -n sentinel pytest tests/test_eval.py -v

# Full suite
conda run -n sentinel pytest -v
```

---

## Project structure

```
sentinel-pr-review/
├── src/
│   ├── orchestrator.py        entry point — wires all agents
│   ├── guardrails.py          prompt injection sanitization + output validation
│   ├── telemetry.py           OpenTelemetry → Application Insights
│   ├── models.py              Pydantic models for all agent I/O
│   ├── mcp_client.py          MCP JSON-RPC 2.0 client for the Azure Function
│   └── agents/
│       ├── triage_agent.py
│       ├── vuln_agent.py
│       ├── drift_agent.py
│       ├── standards_agent.py
│       └── report_agent.py
├── tests/
│   ├── test_eval.py           integration tests against real model
│   ├── test_guardrails.py     guardrail unit tests
│   └── fixtures/              synthetic .diff files
├── adr_documents/             ADR markdown files uploaded to Azure AI Search
├── benchmark/
│   ├── run_benchmark.py       precision/recall/F1 evaluation
│   └── benchmark_results.json
├── mcp_server/
│   ├── function_app.py        MCP server (JSON-RPC 2.0 over Azure Functions HTTP trigger)
│   └── requirements.txt
├── setup_search.py
├── action.yml                 reusable GitHub Actions composite action
└── .github/workflows/
    └── sentinel.yml
```
