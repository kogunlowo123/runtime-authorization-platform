"""Authentication routing (Entra ID vs identity fabric) and service access control."""

from __future__ import annotations

import json
import time
from typing import Any

import httpx
import jwt
import pytest
from agentic_core.policy import PolicyEngine, PolicySet
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from runtime_authorization_platform.domain.errors import ForbiddenError, UnauthorizedError
from runtime_authorization_platform.domain.models import PrincipalKind
from runtime_authorization_platform.integrations.fabric import FabricClient
from runtime_authorization_platform.security.access import ServiceAccess
from runtime_authorization_platform.security.authn import Authenticator, bearer_token
from runtime_authorization_platform.security.entra import EntraIdValidator
from runtime_authorization_platform.security.jwks import StaticJwks
from runtime_authorization_platform.security.roles import Operation, Role
from tests.conftest import AUDIENCE, ROOT, TENANT, FakeClock, FakeEntra, FakeTicker, principal

FABRIC_ISSUER = "https://identity.corp.test"
AGENT_URI = "spiffe://agents.corp.test/agent/finance/assistant"


FABRIC_KEY = Ed25519PrivateKey.generate()


def fabric_token(**claims: Any) -> str:
    """Shape of a fabric credential (EdDSA); the fabric itself verifies it on introspection."""
    body = {"iss": FABRIC_ISSUER, "sub": AGENT_URI, "exp": int(time.time()) + 600, **claims}
    return jwt.encode(body, FABRIC_KEY, algorithm="EdDSA", headers={"kid": "2026-10"})


class FakeFabric:
    def __init__(self) -> None:
        self.introspections = 0
        self.active = True
        self.decision = "allow"
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.path == "/oauth2/introspect":
            self.introspections += 1
            if not self.active:
                return httpx.Response(200, json={"active": False})
            return httpx.Response(
                200,
                json={
                    "active": True,
                    "sub": AGENT_URI,
                    "scope": "documents:read authz:intent:declare",
                    "exp": int(time.time()) + 600,
                    "jti": "j1",
                    "act": {"sub": "spiffe://agents.corp.test/agent/ops/orchestrator"},
                },
            )
        return httpx.Response(
            200,
            json={
                "decision": self.decision,
                "agent": AGENT_URI,
                "action": json.loads(request.content)["action"],
                "resource": "runtime-authorization",
            },
        )


def build(
    entra: FakeEntra, clock: FakeClock, fake: FakeFabric | None = None, cache_s: float = 10.0
) -> tuple[Authenticator, ServiceAccess, FakeTicker]:
    http = httpx.AsyncClient(
        transport=httpx.MockTransport(fake.handler if fake else lambda _: httpx.Response(500))
    )
    ticker = FakeTicker()
    validator = EntraIdValidator(
        tenants=frozenset({TENANT}),
        audiences=frozenset({AUDIENCE}),
        http=http,
        resolvers={TENANT: StaticJwks(entra.jwks())},
        clock=clock.now,
    )
    client = FabricClient(FABRIC_ISSUER, http=http) if fake else None
    authn = Authenticator(
        validator,
        fabric=client,
        fabric_issuer=FABRIC_ISSUER + "/" if fake else None,
        introspection_cache_s=cache_s,
        max_cache_entries=1,
        clock=clock.now,
        monotonic=ticker,
    )
    access = ServiceAccess(
        PolicyEngine(PolicySet.from_file(ROOT / "policies" / "service-access.yaml")),
        authenticator=authn,
        fabric=client,
    )
    return authn, access, ticker


def test_bearer_token_parsing() -> None:
    assert bearer_token("Bearer abc") == "abc"
    assert bearer_token("bearer   abc  ") == "abc"
    for value in (None, "", "Basic abc", "Bearer ", "Bearer"):
        with pytest.raises(UnauthorizedError):
            bearer_token(value)


async def test_entra_route(entra: FakeEntra, clock: FakeClock) -> None:
    authn, _, _ = build(entra, clock)
    found = await authn.authenticate(entra.token("oid-1", Role.AGENT))
    assert found.kind is PrincipalKind.AGENT
    assert authn.fabric_issuer is None
    assert not authn.is_fabric_principal(found)
    with pytest.raises(UnauthorizedError, match="malformed"):
        await authn.authenticate("garbage")
    with pytest.raises(UnauthorizedError):
        await authn.authenticate(fabric_token())  # fabric not configured: not trusted


async def test_fabric_route_and_cache(entra: FakeEntra, clock: FakeClock) -> None:
    fake = FakeFabric()
    authn, _, ticker = build(entra, clock, fake)
    token = fabric_token()
    found = await authn.authenticate(token)
    assert found.id == AGENT_URI
    assert found.kind is PrincipalKind.AGENT
    assert found.delegation_chain == ("spiffe://agents.corp.test/agent/ops/orchestrator",)
    assert found.scopes == frozenset({"documents:read", "authz:intent:declare"})
    assert authn.is_fabric_principal(found)
    await authn.authenticate(token)
    assert fake.introspections == 1
    ticker.advance(11)
    await authn.authenticate(token)
    assert fake.introspections == 2
    await authn.authenticate(fabric_token(jti="other"))  # evicts the first (max 1 entry)
    await authn.authenticate(token)
    assert fake.introspections == 4

    fake.active = False
    ticker.advance(11)
    with pytest.raises(UnauthorizedError, match="not active"):
        await authn.authenticate(token)


async def test_fabric_expired_introspection(entra: FakeEntra, clock: FakeClock) -> None:
    fake = FakeFabric()
    authn, _, _ = build(entra, clock, fake, cache_s=0)
    clock.advance(3600)
    with pytest.raises(UnauthorizedError, match="expired"):
        await authn.authenticate(fabric_token())


async def test_local_service_access(entra: FakeEntra, clock: FakeClock) -> None:
    _, access, _ = build(entra, clock)
    gateway = principal("gw", Role.DECIDE, kind=PrincipalKind.SERVICE)
    await access.require(gateway, "t", Operation.DECIDE)
    assert not await access.check(gateway, "t", Operation.POLICY_ACTIVATE)
    with pytest.raises(ForbiddenError, match="authz:policy:activate"):
        await access.require(gateway, "t", Operation.POLICY_ACTIVATE)
    delegated = principal("approver", Role.POLICY_APPROVER, chain=("orchestrator",))
    assert not await access.check(delegated, "t", Operation.POLICY_ACTIVATE)
    assert access.policy.policy.name == "service-access"


async def test_fabric_service_access(entra: FakeEntra, clock: FakeClock) -> None:
    fake = FakeFabric()
    authn, access, _ = build(entra, clock, fake)
    token = fabric_token()
    agent = await authn.authenticate(token)
    assert await access.check(agent, token, Operation.INTENT_DECLARE)
    sent = json.loads(fake.requests[-1].content)
    assert sent["action"] == "authz:intent:declare"
    assert sent["resource_type"] == "runtime-authorization"
    assert fake.requests[-1].headers["authorization"] == f"Bearer {token}"
    fake.decision = "require_approval"
    assert not await access.check(agent, token, Operation.INTENT_DECLARE)
    # Entra principals still use the local policy when the fabric is configured.
    entra_agent = await authn.authenticate(entra.token("oid-9", Role.AGENT))
    count = len(fake.requests)
    assert await access.check(entra_agent, "t", Operation.DECIDE_SELF)
    assert len(fake.requests) == count
