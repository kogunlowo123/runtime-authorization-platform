# ADR-0005: Entra ID as primary identity, the agent identity fabric as a peer

- Status: Accepted
- Date: 2026-10-14

## Context

The primary cloud is Azure, where callers (gateways, people and agents with
workload identities) hold Entra ID access tokens. The portfolio's agent
identity fabric issues short-lived agent credentials with delegation chains.
Both must be accepted without either becoming an "accept anything" path.

## Decision

- A bearer token is routed by its unverified `iss`: the configured fabric
  issuer goes to fabric introspection (which applies the fabric's revocation
  and credential-epoch checks; results cached for at most 10 s); every other
  token must be a valid Entra ID token.
- Entra validation: RS256 only; `tid` checked against the allow list before
  any key fetch; signature against the tenant JWKS (cached, rate-limited
  refresh on unknown `kid`); issuer must match the tenant (v2.0, optionally
  v1.0); audience; `exp`, `nbf` and `iat` against the injected clock with
  60 s skew; `oid` required; optional client-application allow list.
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
