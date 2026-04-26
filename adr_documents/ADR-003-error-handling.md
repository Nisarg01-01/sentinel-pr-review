# ADR-003: Error Handling

## Status: Accepted

## Decision
All exceptions must be caught and handled explicitly. Bare except clauses are prohibited.
Errors must be logged with context, not silently swallowed.

## Rationale
Silent failures are harder to debug than loud ones. Bare except clauses catch
SystemExit and KeyboardInterrupt, masking real problems.

## Consequences
- Use specific exception types: except ValueError, except requests.HTTPError, etc.
- Never use bare except: or except Exception: without logging
- Log the exception with enough context to reproduce it
- Re-raise or return structured error responses — never return None on failure silently
