# Threat model

## Assets

| Asset | Impact if compromised |
|---|---|
| Active policy and action catalog | Agents gain or lose access to business systems |
| Intents and approvals | High-risk actions proceed without genuine human approval |
| Action blocks | An incident containment is silently lifted |
| Decision log and audit chains | Loss of accountability; regulatory breach |
| Audit signing key | Forged audit evidence |
| Caller tokens in transit | Impersonation of gateways, agents or approvers |

## Trust boundaries

1. Callers (agents, gateways, people) → platform API, MCP and A2A endpoints.
2. Platform → Entra ID JWKS, agent identity fabric, policy information points, OPA.
3. Platform → PostgreSQL and Key Vault.
4. Platform → audit storage.
5. Intent justifications: text produced by models, possibly from untrusted content.

## STRIDE

| ID | Threat | Category | Control | Test |
|---|---|---|---|---|
| T1 | Forged token, token from another tenant or for another API | Spoofing | RS256 only; keys only from allowed tenants' JWKS; signature verified before any claim is read; tenant, issuer, audience and time checks | `tests/security::test_t1_*`, `tests/unit/test_entra.py` |
| T2 | Gateway decides for a subject it holds no token for | Spoofing | Subjects are only ever authenticated tokens; no subject-id parameter exists | `test_t2_subject_token_cannot_be_forged_or_omitted_for_others` |
| T3 | Agent requests decisions for other agents | Elevation | `authz:decide` requires `Authz.Decide`; agents only `decide:self` (dry run) | `test_t3_agent_cannot_decide_for_others` |
| T4 | Caller supplies attributes to pass ABAC (owner, classification) | Tampering | PIP attributes replace caller attributes for configured types; reserved keys dropped | `test_t4_caller_attributes_cannot_override_pip` |
| T5 | Caller asserts `intent.approved` or time through the environment | Tampering | `intent` and `time` reserved; set by the platform | `test_t5_reserved_environment_keys_rejected` |
| T6 | Use, read or revoke another principal's intent | Elevation / repudiation | Intents bound to the declaring principal | `test_t6_intent_is_bound_to_its_principal` |
| T7 | Injected instructions or secrets in a justification | Tampering / disclosure | agentic-core injection detector and secret scanner reject; PII redacted | `test_t7_*` |
| T8 | Self-approval of intents or policies | Elevation | Four-eyes on intent approval and policy activation | `test_t8_self_approval_and_four_eyes`, `test_policy_authoring_four_eyes_and_rollback` |
| T9 | Scope grants reach data above clearance | Disclosure | Classification ceiling enforced outside policy | `test_t9_classification_ceiling_beats_scopes` |
| T10 | Agent invokes an action nobody reviewed | Elevation | Action catalog; unknown actions denied at control stage | `test_t10_unregistered_and_blocked_actions` |
| T11 | Critical action on delegated authority | Elevation | Policy rule `deny-critical-under-delegation` | `test_t11_critical_actions_never_under_delegation` |
| T12 | Missing function-level authorization on admin endpoints | Elevation | Every operation checked against `service-access.yaml` | `test_t12_role_checks_on_administration` |
| T13 | Error bodies leak internals | Disclosure | OAuth-style error bodies; no tracebacks | `test_t13_error_bodies_do_not_leak` |
| T14 | Intent replayed after use | Elevation | Atomic metered consumption; TTL | `test_intent_approval_flow`, `tests/integration/test_postgres.py` |
| T15 | PIP, OPA or JWKS outage turns into allow | DoS / elevation | Fail closed; bounded stale-if-error for PIPs only | `tests/chaos/test_dependency_failures.py` |
| T16 | Decision without evidence | Repudiation | Audit or decision-log write failure fails the request | `test_audit_failure_blocks_decisions`, `test_database_error_during_decision_is_503` |
| T17 | PIP id used for path traversal / SSRF | Tampering | Ids percent-encoded (`safe=""`); no redirects followed; https required in production | `test_http_source_encodes_ids`, `test_http_source_failures` |
| T18 | Policy change ships untested rules | Tampering | Submission requires passing tests and every rule decisive; activation alert | `test_failures_and_coverage_are_reported` |

## MITRE ATT&CK (Enterprise)

| Technique | Mitigation |
|---|---|
| T1078.004 Valid Accounts: Cloud Accounts | Tenant and client allow lists; app roles; per-action decisions |
| T1528 Steal Application Access Token | Subject tokens validated per call; fabric credentials short-lived |
| T1550.001 Application Access Token | Introspection for fabric tokens; Entra signature and audience checks |
| T1098 Account Manipulation | Policy and role changes audited; activation alert |
| T1562.001 Impair Defenses: Disable or Modify Tools | Action blocks and policy versions are audited state; no silent removal |
| T1565 Data Manipulation | Signed audit chains in immutable storage |

## MITRE ATLAS

| Technique | Mitigation |
|---|---|
| AML.T0051 LLM Prompt Injection (direct and indirect) | Agents cannot exceed catalog, policy and clearance regardless of instructions; justifications screened |
| AML.T0053 LLM Plugin Compromise | Tool actions must be registered and authorized per call |
| AML.T0057 LLM Data Leakage | Classification ceiling; restricted data needs purpose of use |
| AML.T0048 External Harms | HIGH/CRITICAL actions require human-approved intents |

## OWASP Top 10 for LLM Applications (2025)

| Risk | Relevance | Control |
|---|---|---|
| LLM06 Excessive Agency | Primary | Action catalog, intents, approval, metered use, kill switch |
| LLM01 Prompt Injection | Agents may be steered | Authorization does not depend on model output; justification screening |
| LLM02 Sensitive Information Disclosure | Data access | Clearance ceiling, purpose-of-use rule, PII redaction in intents |
| LLM05 Improper Output Handling | Model text stored as justification | Treated as data; screened; never evaluated |
| LLM10 Unbounded Consumption | Decision API load | HPA, body limits, candidate cap (1,000), environment key cap |

## OWASP API Security Top 10 (2023)

| Risk | Control |
|---|---|
| API1 Broken Object Level Authorization | Intents readable and revocable only by owner or privileged roles |
| API2 Broken Authentication | Full JWT validation; fabric introspection |
| API3 Broken Object Property Level Authorization | `extra="forbid"`; reserved attribute and environment keys |
| API4 Unrestricted Resource Consumption | Paging limits, list caps, HPA |
| API5 Broken Function Level Authorization | Per-operation service-access policy |
| API6 Unrestricted Access to Sensitive Business Flows | Intents metered and approved; atomic consumption |
| API7 Server Side Request Forgery | PIP URLs from configuration only; ids encoded; tenant JWKS only for allowed tenants |
| API8 Security Misconfiguration | Production refuses ephemeral audit keys and http PIPs; Helm `required` values |
| API10 Unsafe Consumption of APIs | PIP, OPA and fabric responses validated; failures fail closed |

## Risk register

| ID | Risk | Likelihood | Impact | Owner | Treatment | Residual |
|---|---|---|---|---|---|---|
| R1 | Overly broad policy activated | Medium | High | AI Governance | Tests with rule coverage, four-eyes, activation alert, rollback by re-activation | Low |
| R2 | PIP returns stale or wrong attributes | Medium | High | Data owners | TTL and bounded staleness, `:stale` marked in decision log, alert on stale/error | Medium |
| R3 | Approver rubber-stamps intents | Medium | High | Business owners | Intent shows exact action, resource, justification; approvals audited and reportable | Medium |
| R4 | Entra tenant misconfiguration admits another tenant | Low | Critical | Platform | Tenant allow list checked before signature; tests | Low |
| R5 | OPA and local engine disagree after migration | Medium | Medium | Platform | Shadow mode with mismatch alert before cut-over; CI parity tests | Low |
| R6 | PostgreSQL outage | Low | High | Platform | Zone-redundant HA, readiness probe, 503 instead of unaudited decisions | Low |
| R7 | Up to 10 s of fabric revocation lag | Medium | Low | Platform | Introspection cache bounded at 10 s; set to 0 for strict environments | Low |
