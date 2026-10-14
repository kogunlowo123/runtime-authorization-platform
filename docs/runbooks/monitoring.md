# Runbook: monitoring

Dashboard: `configs/grafana/runtime-authorization-platform.json`. Alerts:
`configs/prometheus/alerts.yaml`.

## Signals

| Metric | Meaning |
|---|---|
| `authz_http_request_duration_seconds` | Request latency by route and status |
| `authz_decisions_total{decision,stage,engine}` | Outcomes; `stage=control` means denied before policy |
| `authz_decision_duration_seconds` | Time to decide, including attribute lookups |
| `authz_intent_events_total{event}` | declared, rejected, approved, used, revoked |
| `authz_pip_lookups_total{entity_type,outcome}` | hit, miss, not_found, stale, error |
| `authz_opa_shadow_comparisons_total{outcome}` | match, mismatch, error |
| `authz_active_policy_info{name,version,digest}` | Policy each replica is enforcing |
| `authz_protocol_calls_total{protocol,operation,outcome}` | MCP tools and A2A skills |
| `authz_maintenance_rows_last{task}` | Intents expired and decision-log rows purged per sweep |

## Latency

1. Compare `/v1/decisions` latency with `authz_decision_duration_seconds`. If
   both are high, look at PIP outcomes: a falling hit ratio means a PIP is
   slow or its TTL is too short for the traffic.
2. If only HTTP latency is high, check PostgreSQL (decision-log inserts) and
   CPU throttling (HPA at max replicas).
3. In `opa` or `combined` mode, check OPA latency; consider `shadow` while
   investigating.

## Policy consistency

All replicas should report the same `authz_active_policy_info` digest within
`AUTHZ_POLICY_REFRESH_S` (5 s) of an activation. A replica that does not
converge cannot reach the database; it will also fail readiness.

## Decision-log queries

```bash
curl -s -H "Authorization: Bearer $AUDITOR_TOKEN" \
  "$AUTHZ/v1/decision-logs?subject=<oid>&decision=deny&since=2026-10-14T00:00:00Z" | jq '.items[] | {action, resource_id, reason, policy_digest}'
```
