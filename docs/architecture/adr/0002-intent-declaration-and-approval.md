# ADR-0002: Intent declaration with screening, four-eyes approval and metered use

- Status: Accepted
- Date: 2026-10-14

## Context

Agents act on instructions that may come from untrusted content. For
consequential actions we want the agent to state, before acting, exactly what
it will do, to which resource, and why, so that a human can approve the
specific action rather than a broad scope, and so the record exists even if
the action is later disputed.

## Decision

- `POST /v1/intents` records action, resource (or `*` for any of the type),
  justification and purpose with a TTL (15 min default, 8 h max) and a use
  limit capped by the catalog (`max_intent_uses`, 1 for destructive actions).
- The justification is untrusted text: it is rejected if the agentic-core
  `PromptInjectionDetector` scores it at or above 0.5 or the `SecretScanner`
  finds credentials, and it is stored with PII redacted.
- Policy sees `environment.intent.{declared, approved}`; the shipped policy
  returns `require_approval` for HIGH and CRITICAL actions until approved.
- Approval requires the `Authz.IntentApprover` role and a principal other
  than the declarer.
- An ALLOW that references an intent consumes one use atomically in the
  database (`UPDATE ... WHERE uses < max_uses`); losing a race turns the
  decision into DENY.
- Self-checks (no subject token, the MCP `check_authorization` tool, A2A
  without `subject_token`) are dry runs and never consume uses.

## Consequences

- Approval is per action and resource, not per agent, which keeps human
  review meaningful.
- Replay of an approved intent is bounded by `max_uses` and the TTL.
- Agents make one extra call before high-risk actions; low-risk actions do
  not need intents.
