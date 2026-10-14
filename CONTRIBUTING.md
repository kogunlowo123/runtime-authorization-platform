# Contributing

## Setup

```bash
uv sync
make check
```

## Requirements for every change

- `make check` passes: ruff, black, mypy `--strict`, bandit, contract drift,
  policy unit tests with full rule coverage, tests with at least 90% branch
  coverage.
- New behaviour has tests. Security controls need adversarial cases in
  `tests/security`.
- Policy changes add or update cases in `policies/tests/` for every changed
  rule (see `docs/runbooks/policy-change.md`).
- Public API changes are recorded in `CHANGELOG.md` and the committed
  contracts are regenerated (`python -m runtime_authorization_platform.contracts`).
- Architecturally significant decisions get an ADR in
  `docs/architecture/adr/`.
- No credentials, customer data or PHI in code, tests or fixtures. Use
  synthetic data only.

## Commit messages

Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`,
`chore:`). Breaking changes use `!` and a `BREAKING CHANGE:` footer.

## Review

Changes to `src/runtime_authorization_platform/security`, `policies/` or `deployments/` need approval
from a member of the security code owners group (see `CODEOWNERS`).
