# Configuration reference

All settings are `AUTHZ_*` environment variables (see
`src/runtime_authorization_platform/config.py`). Lists and maps are JSON. The
service refuses to start with incomplete or inconsistent configuration.

| Variable | Required | Default | Description |
|---|---|---|---|
| `AUTHZ_ENVIRONMENT` | no | `production` | `production` forbids ephemeral audit keys and http PIPs |
| `AUTHZ_PUBLIC_URL` | yes | | Public base URL (A2A Agent Card, MCP host check) |
| `AUTHZ_DATABASE_URL` | yes | | SQLAlchemy async URL (`postgresql+asyncpg://...`) |
| `AUTHZ_ENTRA_TENANT_IDS` | yes | | JSON list of allowed tenant ids |
| `AUTHZ_ENTRA_AUDIENCES` | yes | | JSON list of accepted `aud` values |
| `AUTHZ_ENTRA_AUTHORITY` | no | `https://login.microsoftonline.com` | Sovereign clouds: `https://login.microsoftonline.us` etc. |
| `AUTHZ_ENTRA_ACCEPT_V1_TOKENS` | no | `true` | Accept `https://sts.windows.net/<tid>/` issuers |
| `AUTHZ_ENTRA_ALLOWED_CLIENT_IDS` | no | `[]` | Optional allow list of calling app ids (`azp`/`appid`) |
| `AUTHZ_FABRIC_URL` / `AUTHZ_FABRIC_ISSUER` | together | | Agent identity fabric base URL and token issuer |
| `AUTHZ_FABRIC_CLIENT_ID` | no | | This service's agent id at the fabric (for PIP calls) |
| `AUTHZ_FABRIC_WORKLOAD_TOKEN_FILE` | with client id | | Projected service-account token exchanged at the fabric |
| `AUTHZ_FABRIC_INTROSPECTION_CACHE_S` | no | `10` | 0–60; revocation lag for fabric tokens |
| `AUTHZ_POLICY_FILE` | no | `policies/runtime-authorization.yaml` | Bootstrap policy (first start only) |
| `AUTHZ_POLICY_TESTS_FILE` | no | `policies/tests/runtime-authorization.tests.yaml` | Its tests (must pass) |
| `AUTHZ_ACTION_CATALOG_FILE` | no | `policies/actions.yaml` | Registered actions |
| `AUTHZ_SERVICE_ACCESS_POLICY_FILE` | no | `policies/service-access.yaml` | Role → operation policy |
| `AUTHZ_REQUIRE_RULE_COVERAGE` | no | `true` | Every rule must decide a test case |
| `AUTHZ_POLICY_REFRESH_S` | no | `5` | Replica convergence on activation |
| `AUTHZ_ACTION_BLOCK_REFRESH_S` | no | `2` | Action-block propagation |
| `AUTHZ_ENGINE_MODE` | no | `local` | `local`, `opa`, `combined`, `shadow` |
| `AUTHZ_OPA_URL` | unless local | | OPA base URL |
| `AUTHZ_OPA_DECISION_PATH` | no | `rap/authz/result` | Data API path |
| `AUTHZ_OPA_TOKEN` | no | | Bearer token for OPA's token authentication |
| `AUTHZ_OPA_TIMEOUT_S` | no | `2` | Per-request timeout for OPA decisions |
| `AUTHZ_PIPS` | no | `{}` | JSON map: entity type → `{url, auth: none|fabric, ttl_s, stale_s, max_entries}`; `url` contains `{id}` (and optionally `{type}`); entity type `principal` enriches subjects |
| `AUTHZ_PIP_STATIC_FILE` | no | | YAML `{entity_type: {id: {attribute: value}}}` reviewed attribute source |
| `AUTHZ_DEFAULT_CLEARANCE` | no | `1` (INTERNAL) | Subject clearance when no PIP value |
| `AUTHZ_DEFAULT_SUBJECT_RISK` | no | `2` | Subject risk tier when no PIP value |
| `AUTHZ_DEFAULT_RESOURCE_CLASSIFICATION` | no | `1` | Resource classification when neither PIP nor request gives one |
| `AUTHZ_INTENT_DEFAULT_TTL_S` / `AUTHZ_INTENT_MAX_TTL_S` | no | `900` / `28800` | Intent lifetime |
| `AUTHZ_INJECTION_THRESHOLD` | no | `0.5` | Justification injection score that rejects an intent |
| `AUTHZ_AUDIT_LOG_PATH` | no | `/var/lib/runtime-authorization/audit/audit.jsonl` | Audit chain file (per pod in Kubernetes) |
| `AUTHZ_AUDIT_KEY_FILE` | yes* | | Ed25519 PEM; file stem is the key id |
| `AUTHZ_DEV_EPHEMERAL_AUDIT_KEY` | no | `false` | In-memory key, non-production only (replaces *) |
| `AUTHZ_DECISION_LOG_RETENTION_DAYS` | no | `400` | Decision-log rows older than this are purged |
| `AUTHZ_MAINTENANCE_INTERVAL_S` | no | `300` | Intent expiry and log purge sweep |
| `AUTHZ_MCP_ENABLED` | no | `true` | Mount the MCP server at `/mcp` |
| `AUTHZ_HTTP_TIMEOUT_S` | no | `5` | Outbound HTTP timeout (JWKS, fabric, PIPs) |
| `AUTHZ_LOG_LEVEL` | no | `INFO` | |
| `AUTHZ_OTLP_ENDPOINT` | no | | OTLP gRPC endpoint for traces |
| `AUTHZ_HOST` / `AUTHZ_PORT` | no | `127.0.0.1` / `8080` | The image sets host `0.0.0.0` |
| `AUTHZ_FORWARDED_ALLOW_IPS` | no | `127.0.0.1` | Proxies trusted for `X-Forwarded-*` |
