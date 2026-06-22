# Sentinel

Automated PR security reviewer. When a pull request opens, Sentinel fetches the diff, routes it through specialist agents, and posts a structured review flagging hardcoded secrets, SQL injection, architecture violations, and code quality issues before they get merged.

---

## How it works

The triage agent fetches the PR diff and metadata via MCP tools, decides which specialist agents to run, and skips agents that are not relevant. A docs-only PR skips the vulnerability scan entirely. Each specialist agent runs a ReAct loop - it reasons about what it sees, calls tools to fetch additional context when needed, and returns structured findings. The report agent reasons over all findings and writes a coherent GitHub review comment.

Guardrails run on both sides: `sanitize_diff()` strips prompt injection patterns before the diff reaches any agent, and `validate_output()` checks responses for logical inconsistencies. Zero findings on a diff containing a hardcoded secret triggers a safe fallback instead of silently passing.

| Agent | What it does |
|---|---|
| Triage | Fetches PR context via MCP tools, decides which agents to run |
| Vulnerability | Scans for hardcoded secrets, SQL/command injection, insecure deps, missing auth. Calls `get_file_content` when it needs full file context to confirm a finding |
| Drift | Searches ADRs dynamically based on what it sees in the diff, checks for violations |
| Standards | Scores PR 0-100 on tests, naming, docstrings, error handling. Fetches full files when diff context is insufficient |
| Report | LLM call that reasons over all findings and writes a narrative GitHub review comment |

The GitHub API layer is a separate Azure Function implementing the [MCP (Model Context Protocol)](https://spec.modelcontextprotocol.io/specification/2025-03-26/) over JSON-RPC 2.0. Any MCP-compliant client can connect to it and call `get_pr_diff`, `get_pr_metadata`, `get_file_content`, `post_review_comment`, and `post_inline_comment`.

---

## Results

### Benchmark

23 cases: 15 vulnerable patterns across 7 CWE categories + 8 clean cases including adversarial patterns (Django ORM queries, placeholder keys, large noisy diffs with one hidden vulnerability).

Vuln agent uses gpt-4.1, triage and standards use gpt-4.1-mini.

| Metric | Result |
|---|---|
| Recall | 100% - 15/15 vulnerable cases caught |
| Precision | 94% - 1 false positive on a realistic-looking placeholder key |
| F1 Score | 0.97 |
| Triage routing accuracy | 100% - 4/4 real PRs including docs-only case |
| Avg review time | 1.8s per case |

CWEs covered: SQL injection (CWE-89), command injection (CWE-78), eval injection (CWE-95), path traversal (CWE-22), hardcoded secrets (CWE-798), bare except (CWE-390), missing auth (CWE-306).

The one false positive was a config template with realistically-formatted placeholder keys (SendGrid API key format). Conservative behavior - a tool that flags realistic-looking placeholders is safer than one that lets them through.

### Live test on OWASP PyGoat

| PR | Change | Verdict |
|---|---|---|
| 1 | SQL injection in `views.py:159` | `REQUEST_CHANGES` CRITICAL - exact line flagged, ADR-002 + ADR-003 cited |
| 2 | Clean utility functions | `COMMENT` LOW - 0 security findings, quality 80/100 |
| 3 | README only | `COMMENT` - guardrail caught invalid triage output, safe fallback |

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

Add the 8 secrets under Settings -> Secrets -> Actions (see [Setup](#setup) for values).

---

## Setup

### Prerequisites

- Python 3.11+
- Azure AI Foundry with deployed `gpt-4.1` and `gpt-4.1-mini` models
- GitHub fine-grained PAT (pull-requests: read/write, contents: read)
- Azure AI Search service with an index named `sentinel-adrs`
- Azure Storage account (for finding memory across PRs)

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
AZURE_INFERENCE_KEY=<API key from Azure AI Foundry>
MODEL=gpt-4.1-mini
VULN_MODEL=gpt-4.1
REPORT_MODEL=gpt-4.1
GITHUB_TOKEN=<your PAT>
GITHUB_REPO=<owner/repo>
AZURE_SEARCH_ENDPOINT=https://<service>.search.windows.net
AZURE_SEARCH_INDEX=sentinel-adrs
AZURE_SEARCH_KEY=<admin key>
MCP_FUNCTION_URL=<Azure Function URL>
MCP_FUNCTION_KEY=<Azure Function host key>
AZURE_STORAGE_CONNECTION_STRING=<Azure Storage connection string>
APPLICATIONINSIGHTS_CONNECTION_STRING=<optional>
```

```bash
python setup_search.py                    # upload ADRs to search index
python -m src.orchestrator 1 --dry-run   # preview review without posting
python -m src.orchestrator 1             # post review to PR #1
```

### GitHub Actions

Add repository secrets under Settings -> Secrets -> Actions:

| Secret | Value |
|---|---|
| `AZURE_FOUNDRY_ENDPOINT` | `PROJECT_ENDPOINT` value |
| `AZURE_INFERENCE_KEY` | API key from Azure AI Foundry |
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
# Unit tests - no LLM calls (~8s)
conda run -n sentinel pytest tests/test_guardrails.py -v

# Integration tests - calls gpt-4.1-mini (~90s)
conda run -n sentinel pytest tests/test_eval.py -v

# Full suite
conda run -n sentinel pytest -v
```

---

## Project structure

```
sentinel-pr-review/
├── src/
│   ├── orchestrator.py        entry point - wires all agents
│   ├── guardrails.py          prompt injection sanitization + output validation
│   ├── telemetry.py           OpenTelemetry -> Application Insights
│   ├── models.py              Pydantic models for all agent I/O
│   ├── mcp_client.py          MCP JSON-RPC 2.0 client + finding memory layer
│   └── agents/
│       ├── triage_agent.py    ReAct agent - fetches own context via MCP
│       ├── vuln_agent.py      ReAct agent - calls get_file_content when needed
│       ├── drift_agent.py     ReAct agent - constructs own ADR search queries
│       ├── standards_agent.py ReAct agent - fetches full files for quality scoring
│       └── report_agent.py    LLM narrative generation
├── tests/
│   ├── test_eval.py           integration tests against real model
│   ├── test_guardrails.py     guardrail unit tests
│   └── fixtures/              synthetic .diff files
├── adr_documents/             ADR markdown files uploaded to Azure AI Search
├── benchmark/
│   ├── run_benchmark.py       precision/recall/F1 evaluation (23 cases)
│   └── benchmark_results.json
├── mcp_server/
│   ├── function_app.py        MCP server (JSON-RPC 2.0 over Azure Functions HTTP trigger)
│   └── requirements.txt
├── setup_search.py
├── action.yml                 reusable GitHub Actions composite action
└── .github/workflows/
    └── sentinel.yml
```
