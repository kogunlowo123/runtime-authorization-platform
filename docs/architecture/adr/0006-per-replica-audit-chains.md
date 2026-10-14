# ADR-0006: Per-replica signed audit chains and a queryable decision log

- Status: Accepted
- Date: 2026-10-14

## Context

Auditors need tamper evidence (proof that no decision was altered or removed)
and queries (all denials for an agent last week). A single global hash chain
serializes every replica on one writer; a database table alone is mutable by
anyone with write access.

## Decision

- Each replica appends to its own agentic-core `AuditLog` (hash-chained,
  Ed25519-signed) on a per-pod volume, so the Helm chart uses a StatefulSet.
  A log shipper copies chains to immutable storage (Azure immutable blob,
  S3 Object Lock, GCS retention lock).
- Every decision is also written to the `decision_log` table for queries
  (`GET /v1/decision-logs`) and purged after the retention period (400 days
  by default).
- A failed audit write or decision-log write fails the request with 503. No
  decision is returned without evidence.

## Consequences

- Verification is per chain (`agentic_core.audit.verify_chain`); the audit
  key lives in Key Vault, never in Terraform state.
- Scaling out adds chains rather than contention.
