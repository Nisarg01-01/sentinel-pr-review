# ADR-002: Authentication Pattern

## Status: Accepted

## Decision
All routes and functions that access user data or perform privileged operations MUST
use the @require_auth decorator or equivalent authentication middleware.
Direct access to user data without authentication is prohibited.

## Rationale
Prevents accidental exposure of user data through unprotected endpoints.
Authentication must be enforced at the framework level, not left to individual developers.

## Consequences
- All new routes must import and apply authentication middleware
- Tests must mock authentication appropriately
- Never bypass auth with hardcoded user IDs or admin flags in code
- Auth failures must return 401, not 403 or 200
