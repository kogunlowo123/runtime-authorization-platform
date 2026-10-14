"""Microsoft Entra ID access-token validation."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import httpx
import jwt
import pytest

from runtime_authorization_platform.domain.errors import UnauthorizedError
from runtime_authorization_platform.domain.models import PrincipalKind
from runtime_authorization_platform.security.entra import EntraIdValidator
from runtime_authorization_platform.security.jwks import RemoteJwks, StaticJwks
from runtime_authorization_platform.security.roles import Role
from tests.conftest import AUDIENCE, OTHER_TENANT, TENANT, FakeClock, FakeEntra, FakeTicker


def validator(entra: FakeEntra, clock: FakeClock, **kw: Any) -> EntraIdValidator:
    return EntraIdValidator(
        tenants=frozenset({TENANT}),
        audiences=frozenset({AUDIENCE}),
        http=httpx.AsyncClient(),
        resolvers={TENANT: StaticJwks(entra.jwks())},
        clock=clock.now,
        **kw,
    )


async def test_app_token(entra: FakeEntra, clock: FakeClock) -> None:
    principal = await validator(entra, clock).validate(
        entra.token("oid-1", Role.DECIDE, "documents:read")
    )
    assert principal.id == "oid-1"
    assert principal.kind is PrincipalKind.SERVICE
    assert principal.tenant == TENANT
    assert principal.app_id == "client-oid-1"
    assert principal.scopes == frozenset({Role.DECIDE, "documents:read"})
    assert principal.token_id is not None


async def test_agent_and_user_tokens(entra: FakeEntra, clock: FakeClock) -> None:
    v = validator(entra, clock)
    agent = await v.validate(entra.token("oid-2", Role.AGENT))
    assert agent.kind is PrincipalKind.AGENT
    user = await v.validate(entra.token("oid-3", Role.AUDITOR, scp="user_impersonation Files.Read"))
    assert user.kind is PrincipalKind.USER
    assert user.scopes == frozenset({"user_impersonation", "Files.Read"})
    assert user.roles == frozenset({Role.AUDITOR})


async def test_v1_tokens_and_toggle(entra: FakeEntra, clock: FakeClock) -> None:
    claims = entra.claims("oid-4", iss=f"https://sts.windows.net/{TENANT}/", appid="app-4")
    claims.pop("azp")
    token = entra.sign(claims)
    assert (await validator(entra, clock).validate(token)).app_id == "app-4"
    with pytest.raises(UnauthorizedError, match="issuer"):
        await validator(entra, clock, accept_v1_tokens=False).validate(token)


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"aud": "api://someone-else"}, "InvalidAudienceError"),
        ({"tid": OTHER_TENANT}, "tenant not allowed"),
        ({"iss": f"https://login.microsoftonline.com/{OTHER_TENANT}/v2.0"}, "issuer"),
        ({"oid": None}, "MissingRequiredClaimError"),
        ({"exp": "soon"}, "invalid exp"),
    ],
)
async def test_claim_rejections(
    entra: FakeEntra, clock: FakeClock, overrides: dict[str, Any], message: str
) -> None:
    claims = entra.claims("oid-5")
    for key, value in overrides.items():
        if value is None:
            claims.pop(key)
        else:
            claims[key] = value
    with pytest.raises(UnauthorizedError, match=message):
        await validator(entra, clock).validate(entra.sign(claims))


async def test_time_checks_use_injected_clock(entra: FakeEntra, clock: FakeClock) -> None:
    v = validator(entra, clock)
    token = entra.token("oid-6", ttl=300)
    clock.advance(300 + 30)  # within 60 s leeway
    await v.validate(token)
    clock.advance(60)
    with pytest.raises(UnauthorizedError, match="expired"):
        await v.validate(token)
    future = entra.sign(entra.claims("oid-6", now=clock.now() + timedelta(minutes=10)))
    with pytest.raises(UnauthorizedError, match="not yet valid"):
        await v.validate(future)
    claims = entra.claims("oid-6", now=clock.now() + timedelta(minutes=10))
    claims.pop("nbf")
    with pytest.raises(UnauthorizedError, match="future"):
        await v.validate(entra.sign(claims))


async def test_algorithm_and_key_rejections(entra: FakeEntra, clock: FakeClock) -> None:
    v = validator(entra, clock)
    claims = entra.claims("oid-7")
    with pytest.raises(UnauthorizedError, match="algorithm"):
        await v.validate(
            jwt.encode(
                claims,
                "shared-secret-value-long-enough-32b",
                algorithm="HS256",
                headers={"kid": entra.kid},
            )
        )
    with pytest.raises(UnauthorizedError, match="algorithm"):
        await v.validate(jwt.encode(claims, None, algorithm="none"))
    with pytest.raises(UnauthorizedError, match="unknown signing key"):
        await v.validate(entra.sign(claims, kid="rotated-away"))
    attacker = FakeEntra()
    with pytest.raises(UnauthorizedError, match="InvalidSignatureError"):
        await v.validate(attacker.sign(claims))
    with pytest.raises(UnauthorizedError, match="malformed"):
        await v.validate("not.a.jwt")


async def test_client_allow_list(entra: FakeEntra, clock: FakeClock) -> None:
    v = validator(entra, clock, allowed_client_ids=frozenset({"client-oid-ok"}))
    await v.validate(entra.token("oid-ok"))
    with pytest.raises(UnauthorizedError, match="client application"):
        await v.validate(entra.token("oid-other"))


def test_configuration(entra: FakeEntra, clock: FakeClock) -> None:
    with pytest.raises(ValueError, match="tenant"):
        EntraIdValidator(tenants=frozenset(), audiences=frozenset({"a"}), http=httpx.AsyncClient())
    v = validator(entra, clock)
    assert v.accepts_issuer(f"https://login.microsoftonline.com/{TENANT}/v2.0")
    assert not v.accepts_issuer("https://evil.test/")
    assert v.issuers_for(TENANT) == {
        f"https://login.microsoftonline.com/{TENANT}/v2.0",
        f"https://sts.windows.net/{TENANT}/",
    }


async def test_remote_jwks_fetch_refresh_and_failure(entra: FakeEntra) -> None:
    calls: list[str] = []
    healthy = [True]

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, json=entra.jwks()) if healthy[0] else httpx.Response(503)

    ticker = FakeTicker()
    jwks = RemoteJwks(
        f"https://login.microsoftonline.com/{TENANT}/discovery/v2.0/keys",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        ttl_s=100,
        min_refresh_interval_s=10,
        clock=ticker,
    )
    assert await jwks.key_for(entra.kid) is not None
    with pytest.raises(UnauthorizedError, match="unknown signing key"):
        await jwks.key_for("unknown")  # refresh rate-limited
    assert len(calls) == 1
    ticker.advance(11)
    with pytest.raises(UnauthorizedError, match="unknown signing key"):
        await jwks.key_for("unknown")
    assert len(calls) == 2
    healthy[0] = False
    ticker.advance(200)
    assert await jwks.key_for(entra.kid) is not None  # stale keys survive an outage
    with pytest.raises(UnauthorizedError, match="cannot fetch"):
        await jwks.key_for("new-key")


async def test_jwks_skips_unusable_keys() -> None:
    jwks = StaticJwks({"keys": [{"kid": "x", "kty": "nonsense"}, {"no": "kid"}]})
    with pytest.raises(UnauthorizedError):
        await jwks.key_for("x")
    with pytest.raises(ValueError, match="JWKS"):
        StaticJwks({"keys": "nope"})
