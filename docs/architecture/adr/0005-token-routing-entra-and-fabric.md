# ADR-0005: Entra ID as primary identity, the agent identity fabric as a peer

- Status: Accepted
- Date: 2026-10-14

## Context

The primary cloud is Azure, where callers (gateways, people and agents with
workload identities) hold Entra ID access tokens. The portfolio's agent
identity fabric issues short-lived agent credentials with delegation chains.
Both must be accepted without either becoming an "accept anything" path.

## Decision

- A bearer token is routed by its header algorithm only: RS256 tokens are
  Entra ID tokens; EdDSA tokens go to fabric introspection when a fabric is
  configured (which applies the fabric's revocation and credential-epoch
  checks; results cached for at most 10 s). No claim is read before the
  token is validated, so routing cannot be steered by forged claims.
- Entra validation: RS256 only; the signing key is looked up only in the
  JWKS of allowed tenants (cached, rate-limited refresh on unknown `kid`), so
  a token cannot make the service fetch arbitrary key sets; after the
  signature verifies, `tid` must be allowed and the issuer must match it
  (v2.0, optionally v1.0); audience; `exp`, `nbf` and `iat` against the
  injected clock with 60 s skew; `oid` required; optional client-application
  allow list.
- Operation access: Entra principals are checked by the local agentic-core
  engine over `policies/service-access.yaml`; fabric principals by the
  fabric's `/v1/authorize`, which knows their scopes and chains.
- MCP uses the official `mcp` SDK at its current major version (2.x, where
  `FastMCP` became `MCPServer`), mounted as a stateless streamable-HTTP
  route.

## Consequences

- One platform serves both identity planes; neither can grant access to the
  other's operations.
- Fabric revocation takes effect within the 10 s introspection cache.
