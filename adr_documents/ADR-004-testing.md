# ADR-004: Testing Requirements

## Status: Accepted

## Decision
Every new public function or class must have at least one corresponding unit test.
PRs that add logic without tests will be rejected.

## Rationale
Untested code accumulates technical debt and makes refactoring dangerous.
The test suite is the primary safety net for the codebase.

## Consequences
- New functions must have tests in the same PR
- Test files must mirror the source structure: src/foo.py -> tests/test_foo.py
- Tests must cover the happy path and at least one error/edge case
- Mocking external services is acceptable; mocking the database is not
