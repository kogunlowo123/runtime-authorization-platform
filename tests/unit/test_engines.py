"""Decision engines and the OPA client (OPA wire shapes via httpx.MockTransport)."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from agentic_core.domain.classification import Decision
from agentic_core.policy import PolicyRequest, PolicySet, Resource, Rule, Subject

from runtime_authorization_platform.domain.errors import OpaUnavailableError
from runtime_authorization_platform.integrations.opa import UNDEFINED, OpaClient
from runtime_authorization_platform.policy.engines import (
    CombinedEngine,
    EngineMode,
    EngineResult,
    LocalEngine,
    OpaEngine,
    PolicyHolder,
    ShadowEngine,
    interpret_opa_result,
    most_restrictive,
)

POLICY = PolicySet(
    name="p",
    version="1",
    rules=(
        Rule(id="allow-read", effect=Decision.ALLOW, actions=("*:read",)),
        Rule(id="approve-write", effect=Decision.REQUIRE_APPROVAL, actions=("*:write",)),
    ),
)
REQUEST = PolicyRequest(subject=Subject(id="a"), action="docs:read", resource=Resource(type="doc"))


def opa_client(handler: Any, **kw: Any) -> OpaClient:
    return OpaClient(
        "http://opa.test:8181/",
        http=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        **kw,
    )


@pytest.mark.parametrize(
    ("result", "decision"),
    [
        (UNDEFINED, Decision.DENY),
        (None, Decision.DENY),
        (True, Decision.ALLOW),
        (False, Decision.DENY),
        ({"decision": "require_approval", "matched_rules": ["b", "a"]}, Decision.REQUIRE_APPROVAL),
        ({"decision": "maybe"}, Decision.DENY),
        ({"allow": True}, Decision.ALLOW),
        ({"allow": True, "require_approval": True}, Decision.REQUIRE_APPROVAL),
        ({"allow": False}, Decision.DENY),
        ({"something": 1}, Decision.DENY),
        ([1, 2], Decision.DENY),
    ],
)
def test_interpret_opa_result(result: Any, decision: Decision) -> None:
    interpreted = interpret_opa_result(result, path="rap/authz/result")
    assert interpreted.decision is decision
    assert interpreted.engine == "opa"


def test_interpret_full_document() -> None:
    result = interpret_opa_result(
        {
            "decision": "allow",
            "matched_rules": ["z", "a"],
            "policy_name": "p",
            "policy_version": "1",
            "policy_digest": "sha256:x",
        },
        path="x",
    )
    assert result.matched_rules == ("a", "z")
    assert (result.policy_name, result.policy_version, result.policy_digest) == (
        "p",
        "1",
        "sha256:x",
    )


async def test_opa_client_wire_format() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == "/health":
            return httpx.Response(200, json={})
        if request.method == "PUT":
            return httpx.Response(200, json={})
        return httpx.Response(200, json={"result": {"decision": "allow"}})

    client = opa_client(handler, bearer_token="opa-secret-token-value")
    engine = OpaEngine(client)
    result = await engine.evaluate(REQUEST)
    assert result.decision is Decision.ALLOW
    assert engine.local_policy() is None
    assert seen[0].url.path == "/v1/data/rap/authz/result"
    assert json.loads(seen[0].content)["input"]["action"] == "docs:read"
    assert seen[0].headers["authorization"] == "Bearer opa-secret-token-value"
    await client.put_policy("rap", "package rap.authz")
    assert seen[1].headers["content-type"] == "text/plain"
    assert await client.healthy() is True


async def test_opa_undefined_result() -> None:
    client = opa_client(lambda _: httpx.Response(200, json={}))
    assert await client.evaluate({}) is UNDEFINED


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(500, json={}),
        httpx.Response(200, content=b"not json"),
        httpx.Response(200, json=[1]),
    ],
)
async def test_opa_client_errors(response: httpx.Response) -> None:
    client = opa_client(lambda _: response)
    with pytest.raises(OpaUnavailableError):
        await client.evaluate({})


async def test_opa_transport_failures() -> None:
    def broken(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    client = opa_client(broken)
    with pytest.raises(OpaUnavailableError):
        await client.evaluate({})
    with pytest.raises(OpaUnavailableError):
        await client.put_policy("p", "package p")
    assert await client.healthy() is False
    rejected = opa_client(lambda _: httpx.Response(400, json={"code": "invalid_parameter"}))
    with pytest.raises(OpaUnavailableError, match="rejected"):
        await rejected.put_policy("p", "package p")


async def test_local_engine_and_holder() -> None:
    holder = PolicyHolder(POLICY)
    engine = LocalEngine(holder)
    assert (await engine.evaluate(REQUEST)).decision is Decision.ALLOW
    assert engine.local_policy() is POLICY
    holder.replace(PolicySet(name="p", version="2", rules=POLICY.rules[1:]))
    assert (await engine.evaluate(REQUEST)).decision is Decision.DENY
    assert holder.policy.version == "2"


def result(decision: Decision, engine: str, rules: tuple[str, ...] = ()) -> EngineResult:
    return EngineResult(
        decision=decision,
        matched_rules=rules,
        policy_name="p",
        policy_version="1",
        policy_digest="d",
        reason=decision.value,
        engine=engine,
    )


def test_most_restrictive() -> None:
    combined = most_restrictive(
        result(Decision.ALLOW, "local", ("a",)),
        result(Decision.REQUIRE_APPROVAL, "opa", ("b", "a")),
    )
    assert combined.decision is Decision.REQUIRE_APPROVAL
    assert combined.matched_rules == ("b", "a")
    assert combined.engine == "combined"
    assert most_restrictive(
        result(Decision.DENY, "local"), result(Decision.ALLOW, "opa")
    ).decision is (Decision.DENY)


async def test_combined_engine() -> None:
    local = LocalEngine(PolicyHolder(POLICY))
    opa = OpaEngine(opa_client(lambda _: httpx.Response(200, json={"result": False})))
    engine = CombinedEngine(local, opa)
    assert engine.mode is EngineMode.COMBINED
    assert (await engine.evaluate(REQUEST)).decision is Decision.DENY
    assert engine.local_policy() is None


async def test_shadow_engine_records_outcomes() -> None:
    outcomes: list[str] = []
    local = LocalEngine(PolicyHolder(POLICY))
    answers = iter([{"result": True}, {"result": False}])

    def handler(_: httpx.Request) -> httpx.Response:
        try:
            return httpx.Response(200, json=next(answers))
        except StopIteration:
            return httpx.Response(503)

    engine = ShadowEngine(local, OpaEngine(opa_client(handler)), outcomes.append)
    for _ in range(3):
        assert (await engine.evaluate(REQUEST)).decision is Decision.ALLOW
    assert outcomes == ["match", "mismatch", "error"]
    assert engine.local_policy() is POLICY
