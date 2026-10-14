# Agent specification

The platform is a privileged service that every agent depends on. This
document states its own mandate in the terms it imposes on agents, and
defines what agents and enforcement points must send it.

## Role and mission

- **Purpose:** decide, per action and at the moment of action, whether an
  agent may do what it is about to do, and record why.
- **Business objective:** let agents act on business systems with authority
  that is narrow, explained, approved where it matters, and auditable.
- **Protected resources:** policy versions, intents, the action catalog and
  blocks, decision logs, the audit chain.
- **Operating boundaries:** decides; never executes actions; never stores
  credentials; never accepts a subject without that subject's valid token.
- **Delegated responsibility:** the authorization rules themselves belong to
  the policy owners (AI governance and security); the platform enforces the
  active, tested, approved version.

## Delegated scope

| Allowed | Disallowed | Risk | Escalation |
|---|---|---|---|
| Decide for a subject whose token the caller presents | Decide for a named subject without a token | Low | 403 / 400 to the caller |
| Deny unregistered or blocked actions | Let policy re-enable a blocked action | Low | Security officer lifts the block |
| Require a declared intent for registered high-risk actions | Accept intents with injected instructions or secrets | Moderate | Intent-rejection alert pages security |
| Return `require_approval` | Approve on anyone's behalf; let a declarer approve itself | High | Approver role in Entra ID |
| Activate tested policy versions approved by a second person | Activate untested or self-authored versions | High | Policy-activation alert |
| Fail closed on PIP, OPA or audit outages | Decide without evidence being written | — | Readiness probe, error-budget alert |

Risk tiers of actions are data (`policies/actions.yaml`): LOW 1, MODERATE 2,
HIGH 3, CRITICAL 4. HIGH and CRITICAL actions require an approved intent
under the shipped policy; CRITICAL actions are never allowed on delegated
authority.

## Objectives

| Type | Definition | Target |
|---|---|---|
| SLO availability | Non-5xx share of `/v1/decisions` and `/v1/filter` | 99.95% over 30 days |
| SLO latency | p99 `/v1/decisions` | < 50 ms |
| SLO latency | p99 `/v1/filter` | < 150 ms |
| SLI | `authz:request_errors:ratio_5m`, latency histograms | Prometheus |
| KPI | Share of HIGH/CRITICAL agent actions preceded by an approved intent | 100% (enforced) |
| KPI | Policy versions activated with full rule coverage | 100% (enforced) |
| KPI | Time from action block to denial on every replica | ≤ 2 s (block refresh) |
| Completion | A decision is complete when it is in the decision log and the signed audit chain | Enforced: write failure fails the request |

## Permissions

| Mechanism | Use |
|---|---|
| Identity | Entra ID access tokens (v2 and optionally v1, RS256); agent identity fabric credentials (EdDSA, validated by introspection) |
| RBAC | Entra app roles `Authz.Decide`, `Authz.Agent`, `Authz.PolicyAuthor`, `Authz.PolicyApprover`, `Authz.IntentApprover`, `Authz.SecurityOfficer`, `Authz.Auditor`; mapping in `policies/service-access.yaml` |
| ABAC | `policies/runtime-authorization.yaml` over subject, resource, action risk and environment facts |
| OAuth / OIDC | Bearer tokens (RFC 6750); fabric jwt-bearer (RFC 7523), introspection (RFC 7662) |
| Workload identity | Azure Workload Identity (federated credential), IRSA, GKE Workload Identity for the platform's own cloud access; projected service-account token for the fabric |

## Policy facts

Every decision evaluates one request document (the OPA `input` is identical):

| Path | Source |
|---|---|
| `subject.id`, `kind`, `roles`, `tenant`, `issuer`, `app_id` | Validated token |
| `subject.scopes`, `action_in_scope` | `scp` (delegated) or app roles (app-only); fabric `scope` |
| `subject.delegated`, `delegation_depth`, `delegation_chain` | Fabric `act` chain |
| `subject.clearance`, `subject.risk`, other attributes | `principal` PIP, defaults from settings |
| `resource.type`, `resource.id` | Request |
| `resource.classification` and attributes | Resource-type PIP when configured, otherwise the request |
| `risk` | Action catalog |
| `environment.*` | Request (except reserved keys) |
| `environment.intent` | Platform: `{declared, approved, id, purpose, uses, max_uses}` |
| `environment.time` | Platform clock: `{hour, weekday, date}` (UTC) |

## Inputs and outputs

All bodies are Pydantic models with JSON Schemas in `schemas/`; inputs reject
unknown fields.

| Contract | Schema |
|---|---|
| Decision request / response | `decision.request`, `decision.response` |
| Filter request / response | `filter.request`, `filter.response` |
| Intent request / response | `intent.request`, `intent.response` |
| Policy submission, version, test report, test suite | `policy-submission.request`, `policy-version.response`, `policy-test-report.response`, `policy-test-suite` |
| Action catalog | `action-catalog` |
| Decision-log record | `decision-log.record` |

## Validation

- Actions match `resource:verb[:qualifier]` without wildcards; resource types
  match `[A-Za-z0-9][A-Za-z0-9_.:/-]{0,199}`.
- Environment: at most 50 keys; `intent` and `time` are reserved.
- Intents: justification 20–2000 characters, purpose 3–200; TTL capped (8 h
  default maximum); `max_uses` capped by the catalog entry.
- Resource attributes named `type`, `id` or `classification` are dropped;
  subject attributes named `id`, `kind` or `roles` are dropped.
- Unparseable classification labels from a PIP are treated as RESTRICTED.

## Provenance and audit metadata

Each decision response and decision-log row carries: decision id, timestamp,
caller, subject, action, resource, decision, reason, stage (`control` or
`policy`), matched rules, policy name/version/digest (or action-catalog
version/digest for control-stage decisions), engine, intent id, dry-run flag,
latency, correlation id, attribute sources (`pip:<source>[:stale]`, `request`,
`token+pip:<source>`) and classification. The signed audit event repeats the
identifiers plus the delegation chain. Intent, policy, and action-block
changes each produce an audit event with the actor.

## What an enforcement point must do

1. Authenticate the agent as usual and keep its bearer token.
2. `POST /v1/decisions` with `subject_token`, action, resource (type, id) and
   environment (e.g. `purpose_of_use`) and, if the agent supplied one, the
   intent id.
3. Execute only on `allow`. On `require_approval`, surface the obligations
   (`declare_intent`, `approve_intent`) to the agent. On `deny`, refuse.
4. Do not cache `allow` for intent-bearing actions: each allowed decision
   consumed an intent use.
