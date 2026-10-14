"""Latency budgets for hot paths. Loose enough for shared CI runners."""

from __future__ import annotations

import time

import pytest
from agentic_core.domain.classification import RiskLevel
from agentic_core.policy import PolicyEngine, PolicyRequest, PolicySet, Resource, Subject

from runtime_authorization_platform.application.decisions import DecisionInput
from runtime_authorization_platform.integrations.pip import AttributeCache, StaticAttributeSource
from runtime_authorization_platform.policy.partial import allow_residual, evaluate
from runtime_authorization_platform.runtime.container import Container
from tests.conftest import AGENT, ROOT, principal

pytestmark = pytest.mark.performance

POLICY = PolicySet.from_file(ROOT / "policies" / "runtime-authorization.yaml")
BASE = PolicyRequest(
    subject=Subject(id=AGENT, attributes={"department": "finance", "action_in_scope": False}),
    action="documents:read",
    resource=Resource(type="document"),
    risk=RiskLevel.LOW,
    environment={"intent": {"approved": False}},
)


def test_policy_evaluation_budget() -> None:
    engine = PolicyEngine(POLICY)
    request = BASE.model_copy(
        update={"resource": Resource(type="document", attributes={"department": "finance"})}
    )
    started = time.perf_counter()
    for _ in range(2000):
        engine.evaluate(request)
    per_call_us = (time.perf_counter() - started) * 1_000_000 / 2000
    assert per_call_us < 500


def test_residual_filtering_budget() -> None:
    """Filtering rows with one residual must beat one full decision per row."""
    residual = allow_residual(POLICY, BASE)
    requests = [
        BASE.model_copy(
            update={
                "resource": Resource(
                    type="document", attributes={"department": "finance" if i % 2 else "legal"}
                )
            }
        )
        for i in range(5_000)
    ]
    rows = [r.facts() for r in requests]
    engine = PolicyEngine(POLICY)

    started = time.perf_counter()
    allowed = sum(evaluate(residual, row) for row in rows)
    filtering = time.perf_counter() - started
    started = time.perf_counter()
    decided = sum(engine.evaluate(r).allowed for r in requests)
    deciding = time.perf_counter() - started

    assert allowed == decided == 2_500
    assert filtering < deciding
    assert filtering < 5.0


async def test_cached_attribute_lookup_budget() -> None:
    cache = AttributeCache(StaticAttributeSource("s", {"document": {"d": {"owner": "a"}}}))
    await cache.get("document", "d")
    started = time.perf_counter()
    for _ in range(5000):
        await cache.get("document", "d")
    per_call_us = (time.perf_counter() - started) * 1_000_000 / 5000
    assert per_call_us < 100


async def test_end_to_end_decision_budget(container: Container) -> None:
    """Full decision: controls, PIP (cached), policy, decision log write, signed audit event."""
    agent = principal(AGENT)
    request = DecisionInput.model_validate(
        {"action": "documents:read", "resource": {"type": "document", "id": "doc-finance"}}
    )
    await container.decisions.decide(request, caller=agent, subject=agent)
    started = time.perf_counter()
    for _ in range(100):
        await container.decisions.decide(request, caller=agent, subject=agent)
    per_call_ms = (time.perf_counter() - started) * 1000 / 100
    assert per_call_ms < 50
