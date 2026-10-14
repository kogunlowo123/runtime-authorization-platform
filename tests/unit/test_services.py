"""Application services wired through the composition root (SQLite, static PIP)."""

from __future__ import annotations

from typing import Any

import pytest
import yaml
from agentic_core.domain.classification import DataClassification, Decision

from runtime_authorization_platform.application.decisions import (
    CandidateInput,
    DecisionInput,
    FilterInput,
    ResourceInput,
    parse_classification,
)
from runtime_authorization_platform.application.intents import DeclareIntent
from runtime_authorization_platform.application.policies import SubmitPolicy
from runtime_authorization_platform.domain.errors import (
    ConflictError,
    ForbiddenError,
    IntentRejectedError,
    InvalidPolicyError,
    InvalidStateError,
    NotFoundError,
    PolicyTestFailureError,
)
from runtime_authorization_platform.domain.models import IntentStatus, PrincipalKind
from runtime_authorization_platform.runtime.container import Container
from runtime_authorization_platform.security.roles import Role
from tests.conftest import AGENT, ROOT, FakeClock, FakeTicker, principal

AGENT_P = principal(AGENT)
GATEWAY_P = principal("gw", Role.DECIDE, kind=PrincipalKind.SERVICE)


def declare(**overrides: Any) -> DeclareIntent:
    values: dict[str, Any] = {
        "action": "documents:delete",
        "resource_type": "document",
        "resource_id": "doc-finance",
        "justification": "Removing a duplicate upload of the supplier agreement.",
        "purpose": "records-hygiene",
    }
    values.update(overrides)
    return DeclareIntent(**values)


def ask(action: str, rid: str, rtype: str = "document", **kw: Any) -> DecisionInput:
    return DecisionInput(
        action=action, resource=ResourceInput(type=rtype, id=rid, **kw.pop("res", {})), **kw
    )


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0, DataClassification.PUBLIC),
        (3, DataClassification.RESTRICTED),
        (" Confidential ", DataClassification.CONFIDENTIAL),
        (4, None),
        (True, None),
        ("secret", None),
        (None, None),
    ],
)
def test_parse_classification(value: Any, expected: DataClassification | None) -> None:
    assert parse_classification(value) is expected


async def test_unregistered_and_attribute_paths(container: Container) -> None:
    decisions = container.decisions
    unknown = await decisions.decide(ask("unknown:verb", "x"), caller=GATEWAY_P, subject=AGENT_P)
    assert (unknown.decision, unknown.stage, unknown.policy.name) == (
        Decision.DENY,
        "control",
        "action-catalog",
    )
    missing = await decisions.decide(
        ask("documents:read", "nope"), caller=GATEWAY_P, subject=AGENT_P
    )
    assert "not found" in missing.reason
    # Bad label from the PIP is treated as RESTRICTED: above the agent's confidential clearance.
    bad = await decisions.decide(
        ask("documents:read", "doc-bad-label"), caller=GATEWAY_P, subject=AGENT_P
    )
    assert bad.reason == "resource classification exceeds subject clearance"
    # No PIP for tickets: caller-supplied attributes are used.
    ticket = await decisions.decide(
        ask("tickets:read", "T-1", "ticket", res={"attributes": {"owner": AGENT}}),
        caller=GATEWAY_P,
        subject=AGENT_P,
    )
    assert ticket.decision is Decision.ALLOW
    assert ticket.matched_rules == ("allow-owner-read",)
    assert ticket.attribute_sources == {
        "resource": "request",
        "subject": "token+pip:static:attributes.yaml",
    }


async def test_department_access_from_principal_pip(container: Container) -> None:
    result = await container.decisions.decide(
        ask("documents:read", "doc-finance"), caller=GATEWAY_P, subject=AGENT_P
    )
    assert result.decision is Decision.ALLOW
    assert result.matched_rules == ("allow-department-read",)
    stranger = principal("someone")
    denied = await container.decisions.decide(
        ask("documents:read", "doc-finance"), caller=GATEWAY_P, subject=stranger
    )
    assert denied.decision is Decision.DENY


async def test_intent_rules(container: Container, clock: FakeClock) -> None:
    intents, decisions = container.intents, container.decisions
    scoped = principal(AGENT, scopes=frozenset({"documents:*", "tickets:*"}))
    with pytest.raises(IntentRejectedError, match="not registered"):
        await intents.declare(declare(action="unknown:verb"), scoped)
    with pytest.raises(IntentRejectedError, match="does not take intents"):
        await intents.declare(declare(action="tickets:read", resource_type="ticket"), scoped)
    with pytest.raises(IntentRejectedError, match="max_uses"):
        await intents.declare(declare(max_uses=5), scoped)

    intent = await intents.declare(declare(ttl_seconds=60), scoped)
    assert intent.expires_at == clock.now().replace() + (intent.expires_at - intent.created_at)
    assert (intent.expires_at - intent.created_at).total_seconds() == 60

    wrong_resource = await decisions.decide(
        ask("documents:delete", "doc-legal", intent_id=intent.intent_id),
        caller=GATEWAY_P,
        subject=scoped,
    )
    assert "does not match" in wrong_resource.reason
    not_intents = await decisions.decide(
        ask("tickets:read", "T-1", "ticket", intent_id=intent.intent_id),
        caller=GATEWAY_P,
        subject=scoped,
    )
    assert not_intents.reason == "this action does not take intents"
    stolen = await decisions.decide(
        ask("documents:delete", "doc-finance", intent_id=intent.intent_id),
        caller=GATEWAY_P,
        subject=principal("other-agent", scopes=frozenset({"documents:*"})),
    )
    assert "another principal" in stolen.reason
    unknown = await decisions.decide(
        ask("documents:delete", "doc-finance", intent_id="missing"),
        caller=GATEWAY_P,
        subject=scoped,
    )
    assert unknown.reason == "intent rejected: intent not found"

    clock.advance(61)
    expired = await decisions.decide(
        ask("documents:delete", "doc-finance", intent_id=intent.intent_id),
        caller=GATEWAY_P,
        subject=scoped,
    )
    assert expired.reason == "intent rejected: intent is expired"
    assert (await intents.get(intent.intent_id)).status is IntentStatus.EXPIRED
    with pytest.raises(InvalidStateError):
        await intents.approve(intent.intent_id, approver=principal("approver"))
    assert (await container.maintenance())["intents_expired"] == 1


async def test_intent_approval_and_wildcard(container: Container) -> None:
    intents, decisions = container.intents, container.decisions
    scoped = principal(AGENT, scopes=frozenset({"email:send"}))
    intent = await intents.declare(
        declare(action="email:send", resource_type="mailbox", resource_id="*", max_uses=2), scoped
    )
    pending = await decisions.decide(
        ask("email:send", "finance@corp.test", "mailbox", intent_id=intent.intent_id),
        caller=GATEWAY_P,
        subject=scoped,
    )
    assert pending.decision is Decision.REQUIRE_APPROVAL
    with pytest.raises(ForbiddenError):
        await intents.approve(intent.intent_id, approver=scoped)
    approved = await intents.approve(intent.intent_id, approver=principal("approver"))
    with pytest.raises(InvalidStateError, match="already approved"):
        await intents.approve(intent.intent_id, approver=principal("approver"))
    assert approved.approved
    for expected_uses in (1, 2):
        allowed = await decisions.decide(
            ask("email:send", f"box-{expected_uses}", "mailbox", intent_id=intent.intent_id),
            caller=GATEWAY_P,
            subject=scoped,
        )
        assert allowed.decision is Decision.ALLOW
        assert allowed.intent is not None
        assert allowed.intent.uses == expected_uses
    exhausted = await decisions.decide(
        ask("email:send", "box-3", "mailbox", intent_id=intent.intent_id),
        caller=GATEWAY_P,
        subject=scoped,
    )
    assert exhausted.decision is Decision.DENY
    with pytest.raises(ForbiddenError):
        await intents.revoke(
            intent.intent_id, actor=principal("x"), reason="nope", privileged=False
        )
    with pytest.raises(InvalidStateError):
        await intents.revoke(intent.intent_id, actor=scoped, reason="done", privileged=False)
    with pytest.raises(NotFoundError):
        await intents.get("missing")


async def test_lost_consumption_race_denies(container: Container) -> None:
    scoped = principal(AGENT, scopes=frozenset({"documents:*"}))
    intent = await container.intents.declare(declare(action="documents:write"), scoped)
    request = ask("documents:write", "doc-finance", intent_id=intent.intent_id)

    async def nothing_left(_: Any) -> None:
        return None

    container.intents.consume = nothing_left  # type: ignore[method-assign]
    raced = await container.decisions.decide(request, caller=GATEWAY_P, subject=scoped)
    assert raced.decision is Decision.DENY
    assert raced.reason == "intent has no remaining uses"


async def test_policy_administration(container: Container, ticker: FakeTicker) -> None:
    policies = container.policies
    document = yaml.safe_load((ROOT / "policies" / "runtime-authorization.yaml").read_text())
    cases = yaml.safe_load(
        (ROOT / "policies" / "tests" / "runtime-authorization.tests.yaml").read_text()
    )["cases"]
    with pytest.raises(InvalidPolicyError) as invalid:
        await policies.submit(SubmitPolicy(policy={"name": "x"}, tests=cases), actor="alice")
    assert invalid.value.details
    with pytest.raises(ConflictError):
        await policies.submit(SubmitPolicy(policy=document, tests=cases), actor="alice")
    broken = dict(document, version="2")
    with pytest.raises(PolicyTestFailureError):
        await policies.submit(
            SubmitPolicy(policy=broken, tests=[dict(cases[0], expect="deny")]), actor="alice"
        )
    document["version"] = "2026.10.9"
    created = await policies.submit(SubmitPolicy(policy=document, tests=cases), actor="alice")
    with pytest.raises(ForbiddenError):
        await policies.activate(created.version_id, actor="alice")
    with pytest.raises(NotFoundError):
        await policies.get("missing")

    # Another replica activates; this one converges after the refresh interval.
    await container.policies._repo.activate(created.version_id, actor="bob", at=created.created_at)
    await policies.refresh()
    assert policies.holder.policy.version == "2026.10.0"
    ticker.advance(6)
    await policies.refresh()
    assert policies.holder.policy.version == "2026.10.9"
    assert len(await policies.list(limit=10, offset=0)) == 2


async def test_filter_paths(container: Container) -> None:
    decisions = container.decisions
    agent = principal(AGENT)
    unknown = await decisions.filter(
        FilterInput(
            action="unknown:verb", resource_type="document", candidates=(CandidateInput(id="a"),)
        ),
        caller=agent,
        subject=agent,
    )
    assert unknown.never_allowed
    assert unknown.denied_ids == ("a",)
    no_intents = await decisions.filter(
        FilterInput(action="tickets:read", resource_type="ticket", intent_id="i"),
        caller=agent,
        subject=agent,
    )
    assert no_intents.reason == "this action does not take intents"
    bad_intent = await decisions.filter(
        FilterInput(action="documents:delete", resource_type="document", intent_id="missing"),
        caller=agent,
        subject=agent,
    )
    assert bad_intent.never_allowed

    intent = await container.intents.declare(declare(), agent)
    request = FilterInput(
        action="documents:delete",
        resource_type="document",
        intent_id=intent.intent_id,
        environment={"purpose_of_use": "x"},
        candidates=(CandidateInput(id="doc-finance"), CandidateInput(id="doc-own")),
    )
    scoped = principal(AGENT, scopes=frozenset({"documents:*"}))
    pending = await decisions.filter(request, caller=agent, subject=scoped)
    # Delete is high risk and the intent is not yet approved: nothing is allowed outright.
    assert pending.never_allowed
    assert pending.allowed_ids == ()
    await container.intents.approve(intent.intent_id, approver=principal("approver"))
    narrowed = await decisions.filter(request, caller=agent, subject=scoped)
    assert narrowed.allowed_ids == ("doc-finance",)
    assert narrowed.denied_ids == ("doc-own",)
    assert "doc-finance" in str(narrowed.residual)

    await container.controls.block("documents:read", reason="incident 42", actor="sec")
    blocked = await decisions.filter(
        FilterInput(action="documents:read", resource_type="document"), caller=agent, subject=agent
    )
    assert blocked.reason == "action is blocked: incident 42"


async def test_action_controls(container: Container) -> None:
    controls = container.controls
    with pytest.raises(InvalidStateError, match="matches no registered action"):
        await controls.block("nothing:here", reason="test block", actor="sec")
    block = await controls.block("payments:*", reason="fraud wave", actor="sec")
    with pytest.raises(ConflictError):
        await controls.block("payments:*", reason="again", actor="sec")
    assert (await controls.blocked("payments:execute")) == block
    await controls.unblock(block.block_id, actor="sec")
    assert await controls.blocked("payments:execute") is None
    with pytest.raises(NotFoundError):
        await controls.unblock(block.block_id, actor="sec")


async def test_decision_log_query(container: Container) -> None:
    for rid in ("doc-finance", "doc-legal"):
        await container.decisions.decide(
            ask("documents:read", rid), caller=GATEWAY_P, subject=AGENT_P
        )
    log = container.decision_log
    allowed = await log.query(
        subject_id=AGENT,
        action="documents:read",
        decision=Decision.ALLOW,
        since=None,
        limit=10,
        offset=0,
    )
    assert [r.resource_id for r in allowed] == ["doc-finance"]
    everything = await log.query(
        subject_id=None, action=None, decision=None, since=None, limit=10, offset=0
    )
    assert len(everything) == 2
    assert (
        everything[0].classification is DataClassification.CONFIDENTIAL
        or everything[1].classification
    )
