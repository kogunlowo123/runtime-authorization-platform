# ADR-0003: Partial evaluation over the shared agentic-core policy model

- Status: Accepted
- Date: 2026-10-14

## Context

Listing endpoints ("which documents may this agent read?") cannot afford one
decision per row, and filtering after fetching leaks counts and wastes work.
OPA offers partial evaluation through its Compile API, but the primary engine
is the agentic-core `PolicyEngine`, and a second evaluator would drift from
the first.

## Decision

Implement partial evaluation directly on agentic-core `PolicySet`s
(`policy/partial.py`). With everything except the resource known, each rule
reduces to TRUE, FALSE or a conjunction of residual `Condition`s over
`resource.*`; `eq_attr` conditions between a known and an unknown path are
substituted into `eq`. The combining algorithm becomes
`NOT any(deny) AND NOT any(require_approval) AND any(allow)`, simplified. The
classification ceiling and an intent's resource restriction are conjoined.

Residual conditions are evaluated with agentic-core's own
`Condition.evaluate`, so filtering and deciding share code.
`infrastructure/sql_filter.py` compiles residuals to SQLAlchemy predicates,
wrapping each comparison in `IS NOT NULL` so NULL (missing) behaves like the
engine's "missing attribute is false" under negation.

When an external engine has a say (`opa`, `combined`), no residual is
returned and candidates are evaluated individually.

## Consequences

- Property-based tests check residual equals full evaluation over generated
  policies, and SQL push-down equals full evaluation row by row.
- Callers that cannot push down still get `allowed_ids` for up to 1,000
  candidates per call.
