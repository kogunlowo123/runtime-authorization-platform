"""Fault injection: the platform fails closed and reports unreadiness when dependencies break."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest
from agentic_core.domain.classification import Decision
from fastapi.testclient import TestClient

from runtime_authorization_platform.api.app import create_app, maintenance_forever
from runtime_authorization_platform.application.decisions import DecisionInput
from runtime_authorization_platform.application.intents import DeclareIntent
from runtime_authorization_platform.domain.errors import DependencyUnavailableError
from runtime_authorization_platform.infrastructure.database import make_engine
from runtime_authorization_platform.runtime.container import Container, build_container
from runtime_authorization_platform.security.jwks import StaticJwks
from runtime_authorization_platform.security.roles import Role
from tests.conftest import (
    AGENT,
    GATEWAY,
    PUBLIC_URL,
    TENANT,
    FakeClock,
    FakeEntra,
    FakeTicker,
    bearer,
    make_settings,
    principal,
)

pytestmark = pytest.mark.chaos

REQUEST = DecisionInput.model_validate(
    {"action": "tickets:comment", "resource": {"type": "ticket", "id": "T-1"}}
)


def scoped() -> Any:
    return principal(AGENT, scopes=frozenset({"tickets:*", "documents:*"}))


def test_database_outage_flips_readiness(client: TestClient) -> None:
    container = client.app.state.container  # type: ignore[attr-defined]
    assert client.get("/readyz").status_code == 200
    healthy = container.engine
    container.engine = make_engine("sqlite+aiosqlite:////nonexistent/dir/db.sqlite")
    try:
        ready = client.get("/readyz")
        assert ready.status_code == 503
        assert ready.json()["checks"]["database"] is False
        assert client.get("/healthz").status_code == 200  # liveness unaffected
    finally:
        container.engine = healthy


def test_database_error_during_decision_is_503(client: TestClient, entra: FakeEntra) -> None:
    container = client.app.state.container  # type: ignore[attr-defined]
    log = container.decision_log
    healthy = log._engine
    log._engine = make_engine("sqlite+aiosqlite:////nonexistent/dir/db.sqlite")
    try:
        response = client.post(
            "/v1/decisions",
            json={
                "subject_token": entra.token(AGENT, Role.AGENT, "tickets:*"),
                "action": "tickets:comment",
                "resource": {"type": "ticket", "id": "T-1"},
            },
            headers=bearer(entra.token(GATEWAY, Role.DECIDE)),
        )
        assert response.status_code == 503
        assert response.json()["error"] == "temporarily_unavailable"
    finally:
        log._engine = healthy


async def test_audit_failure_blocks_decisions(container: Container) -> None:
    """If evidence cannot be written, no decision is returned."""

    async def broken_append(_: object) -> None:
        raise OSError("disk full")

    container.auditor._audit._sink.append = broken_append  # type: ignore[attr-defined]
    with pytest.raises(DependencyUnavailableError, match="audit"):
        await container.decisions.decide(REQUEST, caller=scoped(), subject=scoped())
    with pytest.raises(DependencyUnavailableError):
        await container.intents.declare(
            DeclareIntent(
                action="email:send",
                resource_type="mailbox",
                resource_id="*",
                justification="Send the weekly status report to the team.",
                purpose="reporting",
            ),
            scoped(),
        )


async def opa_container(tmp_path: Path, mode: str, handler: Any, entra: FakeEntra) -> Container:
    settings = make_settings(tmp_path, engine_mode=mode, opa_url="http://opa.test:8181")
    return await build_container(
        settings,
        entra_resolvers={TENANT: StaticJwks(entra.jwks())},
        http=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )


def opa_down(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("refused", request=request)


async def test_opa_outage_fails_closed(tmp_path: Path, entra: FakeEntra) -> None:
    container = await opa_container(tmp_path, "opa", opa_down, entra)
    result = await container.decisions.decide(REQUEST, caller=scoped(), subject=scoped())
    assert result.decision is Decision.DENY
    assert result.reason.startswith("policy engine unavailable")
    assert (await container.ready())["opa"] is False
    await container.aclose()


async def test_opa_outage_in_shadow_mode_is_advisory(tmp_path: Path, entra: FakeEntra) -> None:
    container = await opa_container(tmp_path, "shadow", opa_down, entra)
    result = await container.decisions.decide(REQUEST, caller=scoped(), subject=scoped())
    assert result.decision is Decision.ALLOW
    errors = container.metrics.registry.get_sample_value(
        "authz_opa_shadow_comparisons_total", {"outcome": "error"}
    )
    assert errors == 1.0
    await container.aclose()


async def test_opa_mode_filter_checks_candidates_individually(
    tmp_path: Path, entra: FakeEntra
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = request.read().decode()
        return httpx.Response(200, json={"result": '"doc-finance"' in body})

    container = await opa_container(tmp_path, "opa", handler, entra)
    from runtime_authorization_platform.application.decisions import CandidateInput, FilterInput

    agent = principal(AGENT)
    result = await container.decisions.filter(
        FilterInput(
            action="documents:read",
            resource_type="document",
            candidates=(CandidateInput(id="doc-finance"), CandidateInput(id="doc-legal")),
        ),
        caller=agent,
        subject=agent,
    )
    assert result.residual is None
    assert result.allowed_ids == ("doc-finance",)
    await container.aclose()


async def test_pip_outage_fails_closed_then_serves_stale(tmp_path: Path, entra: FakeEntra) -> None:
    healthy = [True]

    def handler(request: httpx.Request) -> httpx.Response:
        if not healthy[0]:
            return httpx.Response(503)
        return httpx.Response(200, json={"attributes": {"owner": AGENT, "classification": 1}})

    ticker = FakeTicker()
    settings = make_settings(
        tmp_path,
        pips={"ticket": {"url": "https://pip.corp.test/tickets/{id}", "ttl_s": 10, "stale_s": 30}},
    )
    container = await build_container(
        settings,
        entra_resolvers={TENANT: StaticJwks(entra.jwks())},
        http=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        monotonic=ticker,
    )
    agent = principal(AGENT)
    read = DecisionInput.model_validate(
        {"action": "tickets:read", "resource": {"type": "ticket", "id": "T-1"}}
    )
    assert (
        await container.decisions.decide(read, caller=agent, subject=agent)
    ).decision is Decision.ALLOW
    healthy[0] = False
    ticker.advance(15)
    stale = await container.decisions.decide(read, caller=agent, subject=agent)
    assert stale.decision is Decision.ALLOW
    assert stale.attribute_sources["resource"].endswith(":stale")
    other = DecisionInput.model_validate(
        {"action": "tickets:read", "resource": {"type": "ticket", "id": "T-2"}}
    )
    failed = await container.decisions.decide(other, caller=agent, subject=agent)
    assert failed.decision is Decision.DENY
    assert failed.reason.startswith("attribute source unavailable")
    await container.aclose()


async def test_principal_pip_outage_fails_closed(tmp_path: Path, entra: FakeEntra) -> None:
    settings = make_settings(
        tmp_path, pips={"principal": {"url": "https://directory.corp.test/{id}"}}
    )
    container = await build_container(
        settings,
        entra_resolvers={TENANT: StaticJwks(entra.jwks())},
        http=httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(500))),
    )
    agent = principal(AGENT)
    result = await container.decisions.decide(REQUEST, caller=agent, subject=agent)
    assert result.decision is Decision.DENY
    from runtime_authorization_platform.application.decisions import FilterInput

    filtered = await container.decisions.filter(
        FilterInput(action="tickets:comment", resource_type="ticket"), caller=agent, subject=agent
    )
    assert filtered.never_allowed
    await container.aclose()


async def test_maintenance_loop_survives_errors(container: Container) -> None:
    calls: list[float] = []

    async def failing() -> dict[str, int]:
        raise RuntimeError("db hiccup")

    container.maintenance = failing  # type: ignore[method-assign]

    async def sleep(seconds: float) -> None:
        calls.append(seconds)
        if len(calls) == 2:
            raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        await maintenance_forever(container, 7.0, sleep=sleep)
    assert calls == [7.0, 7.0]


def test_jwks_outage_rejects_tokens(tmp_path: Path, entra: FakeEntra, clock: FakeClock) -> None:
    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route", request=request)

    async def factory() -> Container:
        return await build_container(
            make_settings(tmp_path),
            clock=clock,
            http=httpx.AsyncClient(transport=httpx.MockTransport(down)),
        )

    with TestClient(create_app(factory, public_url=PUBLIC_URL)) as test_client:
        response = test_client.post(
            "/v1/intents", json={}, headers=bearer(entra.token(AGENT, Role.AGENT))
        )
        assert response.status_code == 401
        assert "signing keys" in response.json()["error_description"]


def test_mcp_disabled_requires_no_public_url(tmp_path: Path) -> None:
    async def factory() -> Container:  # pragma: no cover - never started
        raise AssertionError

    app = create_app(factory, enable_mcp=False)
    assert all(getattr(r, "path", "") != "/mcp" for r in app.routes)
    with pytest.raises(ValueError, match="public_url"):
        create_app(factory)
