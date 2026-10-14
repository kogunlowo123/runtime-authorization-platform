# ADR-0004: OPA/Rego compatibility through export, the Data API and shadow mode

- Status: Accepted
- Date: 2026-10-14

## Context

Many enterprises already run Open Policy Agent and have Rego skills; some
want one policy runtime. Others are moving from OPA to the agentic-core
model. Both directions are needed without two sources of truth.

## Decision

- `policy/rego.py` exports any policy set to a Rego v1 module whose `result`
  matches `PolicyEngine.evaluate` (decision, matched rules, policy name,
  version, digest). Globs become anchored RE2 expressions; missing
  attributes make conditions false; ordering comparisons are type-guarded
  because Rego orders mixed types where Python raises.
- `OpaClient` calls the OPA Data API (`POST /v1/data/<path>` with
  `{"input": facts}`); the input document is exactly `PolicyRequest.facts()`.
  Results may be the full document, `{"allow": bool}` or a boolean; undefined
  or malformed results deny.
- Engine modes: `local`, `opa`, `combined` (most restrictive wins) and
  `shadow` (local decides; OPA is compared and counted). OPA failures deny in
  `opa` and `combined` and are only counted in `shadow`.
- Action controls, intents and the classification ceiling stay in the
  platform in every mode.
- CI starts a real OPA, loads the exported Rego and checks decision and
  matched-rule parity for both shipped policies over several hundred
  requests. Releases attach the exported Rego.

## Consequences

- Teams can run OPA as the engine without rewriting policies, or migrate by
  running `shadow` until the mismatch counter stays at zero
  (`docs/runbooks/opa-migration.md`).
- Hand-written Rego is supported through the generic result shapes, but
  partial evaluation is only available when the local engine decides.
