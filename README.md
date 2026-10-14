# Runtime Authorization Platform

The policy decision point for AI agents. Before an agent sends the email,
deletes the record or executes the payment, the gateway in front of the tool
asks this platform. The answer depends on what the action is, what the
resource is (attributes fetched from authoritative sources, not taken from
the caller), what the agent declared it was about to do and why, whether a
human approved that declaration, and the active, tested, approved policy
version. Every answer is logged with the policy digest that produced it.

```
Intent ─▶ Policy ─▶ Resource ─▶ Authorization ─▶ Decision
```

## Capabilities

| Capability | Implementation |
|---|---|
| Action-level controls | Reviewed action catalog with risk tiers and intent requirements; unregistered actions denied before policy; emergency action blocks (kill switch) |
| Intent declaration | Agents declare action, resource, justification and purpose; justification screened for prompt injection and secrets (agentic-core), PII redacted; four-eyes approval; metered, atomic, single-use by default |
| Entra ID token validation | RS256, tenant allow list before key fetch, tenant JWKS with rate-limited refresh, v2/v1 issuers, audience, injected-clock time checks, app roles |
| Agent identity fabric | Typed client (`/oauth2/token` jwt-bearer, `/oauth2/introspect`, `/v1/authorize`); fabric credentials validated by introspection, fabric principals authorized by the fabric |
| ABAC with PIPs | Resource and principal attributes from HTTP or static policy information points; TTL cache, negative caching, single flight, bounded stale-if-error, LRU; caller attributes ignored where a PIP is configured |
| Policy authoring with tests | Policy versions submitted with unit tests; every rule must decide a case; author cannot activate; rollback by re-activation; CLI `authz-policy-test` runs in CI |
| Decision logs | Every decision (including control-stage denials) in PostgreSQL and the signed agentic-core audit chain; query API for auditors |
| Partial evaluation | `POST /v1/filter` returns a residual condition over `resource.*` and/or allowed candidate ids; SQLAlchemy push-down compiler |
| OPA/Rego compatibility | Rego export with verified decision parity; OPA Data API engine in `opa`, `combined` or `shadow` mode |
| MCP and A2A | MCP server (official SDK, streamable HTTP) with four tools; A2A Agent Card and JSON-RPC `message/send` |
| Observability | Prometheus metrics, OpenTelemetry traces, JSON logs with correlation IDs, SLO alerts, Grafana dashboard |

Shared controls (policy engine, audit chain, content security, logging,
telemetry) come from [agentic-core](https://github.com/kogunlowo123/agentic-core).
Agent identities can come from
[agent-identity-fabric](https://github.com/kogunlowo123/agent-identity-fabric).

## Quick start (local)

No API keys or cloud credentials are needed to build and test:

```bash
uv sync
make check        # ruff, black, mypy --strict, bandit, contracts, policy tests, pytest (coverage >= 90%)
```

To run the stack (PostgreSQL, OPA in shadow mode, OTel collector), point it
at a development Entra app registration:

```bash
ENTRA_TENANT_ID=<tenant-guid> ENTRA_AUDIENCE=api://<client-id> docker compose up --build
curl -s localhost:8080/.well-known/agent-card.json | jq .skills
```

## Development

| Suite | Content |
|---|---|
| `tests/unit` | Domain, engines, partial evaluation (property-based), Rego export, PIP cache, Entra validation, fabric client, persistence, SQL push-down, services |
| `tests/security` | Attacks mapped to the threat model (T1–T13) |
| `tests/chaos` | Database, audit, OPA, PIP and JWKS failures |
| `tests/performance` | Latency budgets; `locustfile.py` for load |
| `tests/e2e` | Full HTTP flows (intents and approval, policy lifecycle, filtering, kill switch, MCP, A2A) and a schemathesis contract test |
| `tests/integration` | PostgreSQL (atomic intent consumption) and real-OPA Rego parity |

```bash
make policy-test                      # policy unit tests and rule coverage
make integration                      # needs AUTHZ_TEST_DATABASE_URL and/or AUTHZ_TEST_OPA_URL
uv run authz-policy-test rego policies/runtime-authorization.yaml
```

## API

| Endpoint | Caller (Entra app role) | Purpose |
|---|---|---|
| `POST /v1/decisions` | Gateway (`Authz.Decide`) with `subject_token`; agent (`Authz.Agent`) for a dry-run self-check | Decision |
| `POST /v1/filter` | Gateway or agent | Residual condition and allowed candidates |
| `POST /v1/intents`, `GET /v1/intents/{id}` | Agent | Declare and track intents |
| `POST /v1/intents/{id}/approve` | `Authz.IntentApprover` | Approve (not the declarer) |
| `POST /v1/intents/{id}/revoke` | Declarer or `Authz.SecurityOfficer` | Revoke |
| `POST /v1/policies/test`, `POST /v1/policies` | `Authz.PolicyAuthor` | Test and submit policy versions |
| `POST /v1/policies/{id}/activate` | `Authz.PolicyApprover` | Activate or roll back (not the author) |
| `GET /v1/policies`, `/active`, `/{id}`, `/{id}/rego` | Authors, approvers, auditors | Versions and Rego export |
| `GET /v1/actions`, `POST/DELETE /v1/action-blocks` | Security officer | Catalog and kill switch |
| `GET /v1/decision-logs` | `Authz.Auditor`, security officer | Decision log queries |
| `/mcp` | Agents | MCP tools: `declare_intent`, `check_authorization`, `filter_resources`, `get_intent` |
| `GET /.well-known/agent-card.json`, `POST /a2a` | Agents | A2A discovery and `message/send` |

Full contract: [docs/api/openapi.json](docs/api/openapi.json); JSON Schemas in [schemas/](schemas/).

## Deployment

| Layer | Location |
|---|---|
| Container image | `Dockerfile` (non-root uid 10001, read-only root filesystem compatible) |
| Helm chart | `deployments/helm/runtime-authorization-platform` (StatefulSet for per-replica audit chains, PDB, HPA, NetworkPolicy, ServiceMonitor, Ingress, Azure Workload Identity) |
| Namespace and secret sync | `deployments/kubernetes` (restricted Pod Security, External Secrets) |
| Cloud infrastructure | `deployments/terraform/azure` (primary: Entra app registration with app roles, PostgreSQL Flexible Server, Key Vault, immutable audit storage, workload identity), plus `aws` and `gcp` equivalents |

See the [startup runbook](docs/runbooks/startup.md).

## Documentation

- [Architecture](docs/architecture/overview.md) and [agent specification](docs/architecture/agent-specification.md)
- ADRs: [action controls](docs/architecture/adr/0001-code-enforced-action-controls-before-policy.md), [intents](docs/architecture/adr/0002-intent-declaration-and-approval.md), [partial evaluation](docs/architecture/adr/0003-partial-evaluation-on-the-shared-engine.md), [OPA compatibility](docs/architecture/adr/0004-opa-compatibility-by-export-and-shadowing.md), [token routing](docs/architecture/adr/0005-token-routing-entra-and-fabric.md), [audit chains](docs/architecture/adr/0006-per-replica-audit-chains.md)
- [Threat model and risk register](docs/security/threat-model.md)
- [Compliance control mapping](docs/compliance/control-mapping.md)
- Runbooks: [startup](docs/runbooks/startup.md), [monitoring](docs/runbooks/monitoring.md), [incident response](docs/runbooks/incident-response.md), [policy change](docs/runbooks/policy-change.md), [OPA](docs/runbooks/opa-migration.md), [rollback](docs/runbooks/rollback.md), [disaster recovery](docs/runbooks/disaster-recovery.md)
- [Configuration reference](docs/operations/configuration.md)

## License

Apache-2.0
