# Runbook: running with Open Policy Agent

## Load the policy into OPA

Every release attaches `runtime-authorization.rego` (also available per
version at `GET /v1/policies/{version_id}/rego`). Load it as a bundle or via
the Policy API:

```bash
curl -s -X PUT "$OPA/v1/policies/runtime-authorization" \
  -H 'Content-Type: text/plain' --data-binary @runtime-authorization.rego
```

The decision document is at `rap/authz/result` (`AUTHZ_OPA_DECISION_PATH`).

## Migrate with shadow mode

1. `helm upgrade ... --set authz.engineMode=shadow --set authz.opa.url=$OPA`.
2. Watch `authz_opa_shadow_comparisons_total{outcome="mismatch"}`; the
   `AuthzOpaShadowMismatch` alert fires on any mismatch in an hour. Each
   mismatch is logged as `shadow_decision_mismatch` with the action and both
   decisions.
3. After at least a full business cycle with zero mismatches and zero
   errors, switch to `opa` (OPA decides) or `combined` (both must allow).

## Behaviour by mode

| Mode | Decides | OPA unavailable | Partial evaluation |
|---|---|---|---|
| `local` | agentic-core engine | not used | yes |
| `shadow` | agentic-core engine | counted, ignored | yes |
| `combined` | most restrictive of both | DENY | candidates only |
| `opa` | OPA | DENY | candidates only |

Action controls, intents and the classification ceiling are enforced by the
platform in every mode.

## Keeping policies in sync

When OPA decides, a policy activated through the platform API must also be
loaded into OPA. Activate in the platform first, export its Rego, then push
it to OPA; run in `combined` mode during the change so the stricter version
wins.
