# ADR-0001: Code-enforced action controls before policy evaluation

- Status: Accepted
- Date: 2026-10-14

## Context

Policies are data that authors change through an API. A policy mistake (a
broad `allow` with `actions: ["*"]`) must not be able to authorize an action
nobody registered, an action a security officer has stopped during an
incident, a high-risk action without a declared intent, or access above a
principal's clearance.

## Decision

Every decision runs a fixed pipeline before the policy engine:

1. the action must be in the reviewed action catalog (`policies/actions.yaml`);
2. it must not match an active action block;
3. attributes are resolved (PIP for the resource type when configured);
4. referenced intents must belong to the subject, be active, have uses left
   and match the request; actions marked `intent: required` are denied
   without one;
5. the resource classification must not exceed the subject's clearance.

Each failure is a DENY with `stage: control`, logged and audited like any
other decision. The catalog also supplies the action's risk tier, which the
policy reads as the `risk` fact.

## Consequences

- Policy edits cannot widen agents' reach beyond the catalog; adding an
  action is a reviewed repository change (CODEOWNERS on `policies/`).
- An action block takes effect on every replica within the block refresh
  interval (2 s) without a policy change.
- Policies stay small: they express business rules, not plumbing.
