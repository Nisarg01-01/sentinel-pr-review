# ADR-001: Secret Management

## Status: Accepted

## Decision
Secrets, passwords, API keys, and tokens MUST never be hardcoded in source code.
All secrets must be loaded from environment variables or Azure Key Vault.

## Rationale
Hardcoded secrets get committed to git history and are visible to anyone with repo access,
including in public repositories. Even in private repos, rotating a hardcoded secret requires
a code change and deployment.

## Consequences
- All new code must use os.environ or a secrets client to retrieve credentials
- Code reviews must reject any PR that hardcodes a secret value
- Tests must use dummy/mock values, never real credentials
- Variables named password, token, secret, key, api_key must never have literal string values
