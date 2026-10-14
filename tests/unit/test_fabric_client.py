"""agent-identity-fabric client against the fabric's recorded wire shapes."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest
from agentic_core.domain.classification import DataClassification, Decision

from runtime_authorization_platform.domain.errors import (
    AuthzError,
    FabricUnavailableError,
    UnauthorizedError,
)
from runtime_authorization_platform.integrations.fabric import (
    JWT_BEARER,
    FabricClient,
    FabricTokenProvider,
)

AGENT_URI = "spiffe://agents.corp.test/agent/finance/assistant"

# Shapes recorded from agent-identity-fabric v0.1.0 (docs/api/openapi.json there).
TOKEN_RESPONSE = {
    "access_token": "eyJhbGciOiJFZERTQSJ9.payload.signature",
    "token_type": "Bearer",
    "expires_in": 600,
    "scope": "authz:decide:self documents:read",
    "issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
}
INTROSPECTION = {
    "active": True,
    "sub": AGENT_URI,
    "scope": "documents:read",
    "exp": 4_102_444_800,
    "iat": 4_102_444_200,
    "jti": "f0e1d2c3",
    "iss": "https://identity.corp.test",
    "aud": "agent-platform",
    "act": {"sub": "spiffe://agents.corp.test/agent/ops/orchestrator"},
    "agent_status": "active",
}
DECISION = {
    "decision": "allow",
    "agent": AGENT_URI,
    "action": "authz:decide:self",
    "resource": "runtime-authorization:decide:self",
    "matched_rules": ["allow-scoped-actions"],
    "policy_version": "2026.10.0",
    "policy_digest": "sha256:abc",
    "reason": "explicit allow",
    "delegation_chain": [],
}


def fabric(handler: Any) -> FabricClient:
    return FabricClient(
        "https://identity.corp.test/",
        http=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )


async def test_wire_formats() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            200,
            json={
                "/oauth2/token": TOKEN_RESPONSE,
                "/oauth2/introspect": INTROSPECTION,
                "/v1/authorize": DECISION,
            }[request.url.path],
        )

    client = fabric(handler)
    issued = await client.token(AGENT_URI, "workload.jwt.token", scope="documents:read")
    assert issued.expires_in == 600
    form = parse_qs(seen[0].content.decode())
    assert form == {
        "grant_type": [JWT_BEARER],
        "client_id": [AGENT_URI],
        "assertion": ["workload.jwt.token"],
        "scope": ["documents:read"],
    }

    introspection = await client.introspect("agent.jwt")
    assert introspection.act is not None
    assert introspection.act.subjects() == ["spiffe://agents.corp.test/agent/ops/orchestrator"]
    assert parse_qs(seen[1].content.decode()) == {"token": ["agent.jwt"]}

    decision = await client.authorize(
        "agent.jwt",
        action="authz:decide:self",
        resource_type="runtime-authorization",
        resource_id="decide:self",
        classification=DataClassification.CONFIDENTIAL,
        attributes={"k": "v"},
        environment={"purpose_of_use": "x"},
    )
    assert decision.decision is Decision.ALLOW
    body = json.loads(seen[2].content)
    assert body["resource_classification"] == 2
    assert body["resource_attributes"] == {"k": "v"}
    assert seen[2].headers["authorization"] == "Bearer agent.jwt"


@pytest.mark.parametrize(
    ("response", "error"),
    [
        (httpx.Response(503), FabricUnavailableError),
        (httpx.Response(200, content=b"oops"), FabricUnavailableError),
        (httpx.Response(200, json=[]), FabricUnavailableError),
        (httpx.Response(200, json={"unexpected": True}), FabricUnavailableError),
        (
            httpx.Response(401, json={"error": "unauthorized", "error_description": "no"}),
            UnauthorizedError,
        ),
        (
            httpx.Response(400, json={"error": "invalid_grant", "error_description": "bad"}),
            AuthzError,
        ),
    ],
)
async def test_error_mapping(response: httpx.Response, error: type[Exception]) -> None:
    with pytest.raises(error):
        await fabric(lambda _: response).token(AGENT_URI, "assertion")


async def test_transport_error() -> None:
    def broken(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timeout", request=request)

    with pytest.raises(FabricUnavailableError):
        await fabric(broken).introspect("t")


async def test_token_provider_caches_until_near_expiry(tmp_path: Path) -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(parse_qs(request.content.decode())["assertion"][0])
        return httpx.Response(200, json={**TOKEN_RESPONSE, "access_token": f"tok-{len(calls)}"})

    projected = tmp_path / "token"
    projected.write_text("workload-1\n", encoding="utf-8")
    now = [datetime(2026, 10, 14, tzinfo=UTC)]
    provider = FabricTokenProvider(
        fabric(handler),
        client_id=AGENT_URI,
        workload_token_file=projected,
        clock=lambda: now[0],
    )
    assert await provider() == "tok-1"
    assert await provider() == "tok-1"
    now[0] += timedelta(seconds=545)  # inside the 60 s refresh margin
    projected.write_text("workload-2\n", encoding="utf-8")
    assert await provider() == "tok-2"
    assert calls == ["workload-1", "workload-2"]
