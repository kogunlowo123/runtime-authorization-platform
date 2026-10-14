# Runbook: incident response

## Contain a misbehaving agent or action (kill switch)

Block the action pattern; every replica denies matching decisions within 2 s:

```bash
curl -s -X POST "$AUTHZ/v1/action-blocks" -H "Authorization: Bearer $SECOPS_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"pattern": "payments:*", "reason": "INC-1234 suspected fraudulent transfers"}'
```

Revoke the agent's outstanding intents (`POST /v1/intents/{id}/revoke`), and
if the agent uses fabric credentials, suspend it at the agent identity fabric
(its tokens stop introspecting as active within 10 s). For Entra-identified
agents, remove the `Authz.Agent` app-role assignment.

Lift the block with `DELETE /v1/action-blocks/{block_id}` once resolved.

## Elevated 5xx

1. `/readyz` on each pod: `database: false` means PostgreSQL is unreachable;
   follow the database provider's runbook. Decisions return 503 rather than
   unaudited answers, which is intended.
2. `opa: false` in `opa`/`combined` mode: decisions are failing closed
   (DENY, not 5xx). Restore OPA or switch to `local` via a Helm upgrade.
3. Audit volume full: pods log `audit_write_failed`; expand the PVC and
   confirm the log shipper is draining.

## Deny spike

Break down `authz_decisions_total` by `stage`. `control` denials point at the
catalog, blocks, intents or attribute sources; `policy` denials at the
active policy. Query the decision log for the top reasons. If a recent
activation caused it, roll back (`docs/runbooks/rollback.md`).

## Intent rejections

Rejected intents mean agents are submitting justifications that look like
prompt injection or contain secrets. Query audit events with
`action = intent.declare` and `outcome = rejected` for the agent; treat a
sustained rate as a compromised agent or poisoned input source and contain
it as above.

## PIP outage

Decisions for the affected entity type fail closed after the stale window
(`stale_s`). Restore the attribute source; do not lengthen `stale_s` during
an incident without a security decision, because stale attributes may grant
access that has since been removed.

## Replicas down

Fewer than two replicas scraped: check node pressure, PVC binding (each
replica needs its audit volume) and recent rollouts.

## Evidence

Export the relevant audit chains from immutable storage and verify them:

```python
from agentic_core.audit import AuditEvent, verify_chain
events = [AuditEvent.model_validate_json(l) for l in open("authz-0.jsonl")]
verify_chain(events, {"audit-2026-10": public_key})
```
