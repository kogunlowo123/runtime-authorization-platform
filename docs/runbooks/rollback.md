# Runbook: rollback

## Policy rollback (most common)

Policy versions are kept. Rolling back is activating the previous version,
done by a policy approver:

```bash
curl -s -H "Authorization: Bearer $APPROVER_TOKEN" "$AUTHZ/v1/policies?limit=5" \
  | jq '.items[] | {version_id, version, status, digest}'
curl -s -X POST -H "Authorization: Bearer $APPROVER_TOKEN" \
  "$AUTHZ/v1/policies/<previous version_id>/activate"
```

Confirm every replica reports the restored digest
(`authz_active_policy_info`) within 5 s and that `policy.digest` in new
decisions matches.

## Application rollback

The schema is additive within a minor version (`schema_version` table), so
rolling back the application within 0.x does not require database changes.

```bash
helm -n runtime-authorization history authz
helm -n runtime-authorization rollback authz <revision> --wait
kubectl -n runtime-authorization rollout status statefulset/authz-runtime-authorization-platform
curl -sf "$AUTHZ/readyz"
```

## Engine-mode rollback

If `opa` or `combined` mode misbehaves, upgrade with
`--set authz.engineMode=local` (or `shadow` to keep comparing).
