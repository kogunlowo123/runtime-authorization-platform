# Runbook: disaster recovery

| Component | Protection | RPO | RTO |
|---|---|---|---|
| PostgreSQL (intents, policies, decision log, blocks) | Zone-redundant HA, geo-redundant backups, PITR | 5 min (PITR) | 1 h |
| Audit chains | Per-pod volumes shipped to geo-redundant immutable storage | Shipping interval | n/a (evidence) |
| Audit key | Key Vault (soft delete, purge protection) | 0 | Minutes |
| Configuration | Git (chart values), Terraform state | 0 | Minutes |

## Region loss

1. Restore PostgreSQL to the paired region from geo-redundant backup
   (`az postgres flexible-server geo-restore`).
2. Apply Terraform for the secondary region with the restored server; update
   the `runtime-authorization-database-url` secret.
3. Install the chart in the secondary cluster with the same values; replicas
   load the active policy from the restored database.
4. Point the gateways' PDP URL at the new ingress.

Intents created after the restore point are lost; agents re-declare them.
Decisions made after the restore point remain in the shipped audit chains.

## Database corruption or bad migration

Restore to a point in time before the event into a new server, switch the
secret, restart pods (`kubectl rollout restart`). Verify the active policy
digest matches the last known-good activation in the audit chain.

## Lost audit key

Generate a new key (new `kid`, startup runbook step 3), roll it out, and keep
the old public key for verifying existing chains. Chains signed with a
compromised key are re-anchored by recording the new key id in a signed
change record.
