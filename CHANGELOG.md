# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [0.1.0] - 2026-10-14

### Added

- Decision endpoint with code-enforced action controls (action catalog, risk
  tiers, action blocks), classification ceiling and the agentic-core policy
  engine; every decision written to the decision log and the signed audit chain.
- Intent declaration with prompt-injection and secret screening, PII
  redaction, four-eyes approval and atomic metered consumption.
- Microsoft Entra ID access-token validation and agent identity fabric
  integration (introspection, `/v1/authorize`, jwt-bearer token provider).
- Policy information points (HTTP and static) with TTL, negative caching,
  single flight, bounded stale-if-error and LRU.
- Policy authoring API with unit tests and rule coverage, four-eyes
  activation, rollback, replica convergence; `authz-policy-test` CLI.
- Partial evaluation for list filtering with a SQLAlchemy push-down compiler.
- OPA/Rego compatibility: Rego export with verified parity, OPA Data API
  engine in `opa`, `combined` and `shadow` modes.
- MCP server (four tools) and A2A Agent Card with JSON-RPC `message/send`.
- Helm chart, Kubernetes namespace and secret sync, Terraform for Azure
  (with Entra app registration and app roles), AWS and GCP.
- CI: lint, types, SAST, contract drift, policy tests, tests (unit, security,
  chaos, performance, e2e), PostgreSQL and OPA integration, Helm/kubeconform,
  Terraform validate, Trivy, Syft, Grype, Semgrep, container smoke test.
