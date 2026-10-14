"""Shared fixtures: an in-process Entra ID tenant, a platform wired to SQLite, and an app."""

from __future__ import annotations

import os
import time
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import jwt
import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from runtime_authorization_platform.api.app import create_app
from runtime_authorization_platform.config import Settings
from runtime_authorization_platform.domain.models import Principal, PrincipalKind
from runtime_authorization_platform.runtime.container import Container, build_container
from runtime_authorization_platform.security.jwks import StaticJwks
from runtime_authorization_platform.security.roles import Role

ROOT = Path(__file__).resolve().parents[1]
TENANT = "9b1c5e7a-1d2f-4c3b-8a6e-0f1e2d3c4b5a"
OTHER_TENANT = "1e2d3c4b-5a6f-4e7d-9c8b-a1b2c3d4e5f6"
AUDIENCE = "api://runtime-authorization.test"
AUTHORITY = "https://login.microsoftonline.com"
PUBLIC_URL = "http://testserver"

AGENT = "agent-oid-finance-assistant"
GATEWAY = "gateway-oid-api-gateway"
APPROVER = "user-oid-approver"
AUTHOR = "user-oid-policy-author"
POLICY_APPROVER = "user-oid-policy-approver"
SECURITY = "user-oid-security-officer"
AUDITOR = "user-oid-auditor"

STATIC_ATTRIBUTES: dict[str, dict[str, dict[str, Any]]] = {
    "document": {
        "doc-own": {"classification": 1, "owner": AGENT, "department": "legal"},
        "doc-finance": {"classification": "confidential", "department": "finance"},
        "doc-legal": {"classification": 2, "department": "legal", "owner": "someone-else"},
        "doc-restricted": {"classification": 3, "department": "finance"},
        "doc-quarantined": {"classification": 1, "department": "finance", "quarantined": True},
        "doc-bad-label": {"classification": "top-secret-ish", "department": "finance"},
    },
    "principal": {
        AGENT: {"department": "finance", "clearance": "confidential", "risk": 2},
    },
}


@dataclass
class FakeEntra:
    """Minimal Entra ID tenant: RS256 key, JWKS and v2.0 access tokens."""

    tenant: str = TENANT
    kid: str = "entra-key-1"
    key: rsa.RSAPrivateKey = field(
        default_factory=lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048)
    )

    def jwks(self) -> dict[str, Any]:
        jwk = jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key(), as_dict=True)
        jwk.update({"kid": self.kid, "alg": "RS256", "use": "sig"})
        return {"keys": [jwk]}

    def claims(
        self,
        oid: str,
        *,
        roles: tuple[str, ...] = (),
        scp: str | None = None,
        aud: str = AUDIENCE,
        ttl: int = 600,
        now: datetime | None = None,
        **extra: Any,
    ) -> dict[str, Any]:
        issued = int((now or datetime.now(UTC)).timestamp())
        claims: dict[str, Any] = {
            "iss": f"{AUTHORITY}/{self.tenant}/v2.0",
            "aud": aud,
            "tid": self.tenant,
            "oid": oid,
            "sub": oid,
            "azp": f"client-{oid}",
            "iat": issued,
            "nbf": issued,
            "exp": issued + ttl,
            "ver": "2.0",
            "uti": f"uti-{oid}-{time.perf_counter_ns()}",
        }
        if roles:
            claims["roles"] = list(roles)
        if scp is not None:
            claims["scp"] = scp
        else:
            claims["idtyp"] = "app"
        claims.update(extra)
        return claims

    def sign(self, claims: dict[str, Any], *, kid: str | None = None) -> str:
        return jwt.encode(claims, self.key, algorithm="RS256", headers={"kid": kid or self.kid})

    def token(self, oid: str, *roles: str, **kw: Any) -> str:
        return self.sign(self.claims(oid, roles=roles, **kw))


@dataclass
class FakeClock:
    current: datetime = field(default_factory=lambda: datetime.now(UTC).replace(microsecond=0))

    def now(self) -> datetime:
        return self.current

    def advance(self, seconds: float) -> None:
        self.current += timedelta(seconds=seconds)


@dataclass
class FakeTicker:
    value: float = 1_000.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


@pytest.fixture
def entra() -> FakeEntra:
    return FakeEntra()


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def ticker() -> FakeTicker:
    return FakeTicker()


@pytest.fixture
def static_pip(tmp_path: Path) -> Path:
    path = tmp_path / "attributes.yaml"
    path.write_text(yaml.safe_dump(STATIC_ATTRIBUTES), encoding="utf-8")
    return path


def make_settings(tmp_path: Path, **overrides: Any) -> Settings:
    db = os.environ.get("AUTHZ_TEST_DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path / 'authz.db'}")
    values: dict[str, Any] = {
        "environment": "test",
        "public_url": PUBLIC_URL,
        "database_url": db,
        "entra_tenant_ids": [TENANT],
        "entra_audiences": [AUDIENCE],
        "dev_ephemeral_audit_key": True,
        "audit_log_path": tmp_path / "audit.jsonl",
        "policy_file": ROOT / "policies" / "runtime-authorization.yaml",
        "policy_tests_file": ROOT / "policies" / "tests" / "runtime-authorization.tests.yaml",
        "action_catalog_file": ROOT / "policies" / "actions.yaml",
        "service_access_policy_file": ROOT / "policies" / "service-access.yaml",
    }
    values.update(overrides)
    return Settings(**values)


@pytest.fixture
def settings(tmp_path: Path, static_pip: Path) -> Settings:
    return make_settings(tmp_path, pip_static_file=static_pip)


@pytest.fixture
async def container(
    settings: Settings, entra: FakeEntra, clock: FakeClock, ticker: FakeTicker
) -> AsyncIterator[Container]:
    built = await build_container(
        settings,
        entra_resolvers={TENANT: StaticJwks(entra.jwks())},
        clock=clock,
        monotonic=ticker,
    )
    yield built
    await built.aclose()


def principal(
    pid: str = AGENT,
    *roles: str,
    kind: PrincipalKind = PrincipalKind.AGENT,
    scopes: frozenset[str] = frozenset(),
    chain: tuple[str, ...] = (),
) -> Principal:
    return Principal(
        id=pid,
        kind=kind,
        issuer=f"{AUTHORITY}/{TENANT}/v2.0",
        tenant=TENANT,
        roles=frozenset(roles) or frozenset({Role.AGENT}),
        scopes=scopes,
        delegation_chain=chain,
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def client(
    settings: Settings, entra: FakeEntra, clock: FakeClock, ticker: FakeTicker
) -> Iterator[TestClient]:
    """App whose container is built inside the app's own event loop by its lifespan."""

    async def factory() -> Container:
        return await build_container(
            settings,
            entra_resolvers={TENANT: StaticJwks(entra.jwks())},
            clock=clock,
            monotonic=ticker,
        )

    with TestClient(create_app(factory, public_url=PUBLIC_URL)) as test_client:
        yield test_client
