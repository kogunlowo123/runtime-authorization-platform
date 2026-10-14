"""Partial evaluation must agree with full evaluation for every resource."""

from __future__ import annotations

from typing import Any

import pytest
from agentic_core.domain.classification import DataClassification, Decision, RiskLevel
from agentic_core.policy import (
    Condition,
    Operator,
    PolicyEngine,
    PolicyRequest,
    PolicySet,
    Resource,
    Rule,
    Subject,
)
from hypothesis import given, settings
from hypothesis import strategies as st

from runtime_authorization_platform.policy.partial import (
    FALSE,
    TRUE,
    And,
    Cond,
    Not,
    Or,
    allow_residual,
    conj,
    disj,
    evaluate,
    neg,
    partial_condition,
    referenced_attributes,
    to_dict,
)
from tests.conftest import ROOT

VALUES = st.one_of(
    st.integers(0, 3), st.sampled_from(["a", "b", "finance", "legal"]), st.booleans()
)
RESOURCE_PATHS = [
    "resource.owner",
    "resource.department",
    "resource.classification",
    "resource.flag",
]
KNOWN_PATHS = ["subject.id", "subject.department", "subject.level", "environment.mode", "risk"]


@st.composite
def conditions(draw: st.DrawFn) -> Condition:
    attribute = draw(st.sampled_from(RESOURCE_PATHS + KNOWN_PATHS))
    operator = draw(st.sampled_from(list(Operator)))
    if operator is Operator.EQ_ATTR:
        value: Any = draw(st.sampled_from(RESOURCE_PATHS + KNOWN_PATHS))
    elif operator in {Operator.IN, Operator.NOT_IN, Operator.CONTAINS_ANY}:
        value = draw(st.lists(VALUES, max_size=3))
    elif operator is Operator.EXISTS:
        value = draw(st.booleans())
    else:
        value = draw(VALUES)
    return Condition(attribute=attribute, operator=operator, value=value)


@st.composite
def policies(draw: st.DrawFn) -> PolicySet:
    count = draw(st.integers(1, 6))
    rules = [
        Rule(
            id=f"r{i}",
            effect=draw(st.sampled_from(list(Decision))),
            actions=(draw(st.sampled_from(["*", "documents:*", "documents:read", "tickets:*"])),),
            resource_types=(draw(st.sampled_from(["*", "document", "ticket"])),),
            conditions=tuple(draw(st.lists(conditions(), max_size=3))),
        )
        for i in range(count)
    ]
    return PolicySet(name="generated", version="1", rules=tuple(rules))


@st.composite
def attribute_maps(draw: st.DrawFn, names: list[str]) -> dict[str, Any]:
    keys = draw(st.lists(st.sampled_from(names), unique=True))
    return {k: draw(VALUES) for k in keys}


@given(
    policy=policies(),
    subject_attrs=attribute_maps(["department", "level"]),
    resource_attrs=st.lists(
        attribute_maps(["owner", "department", "flag"]), min_size=1, max_size=4
    ),
    classifications=st.lists(st.integers(0, 3), min_size=4, max_size=4),
    action=st.sampled_from(["documents:read", "documents:write", "tickets:close"]),
    resource_type=st.sampled_from(["document", "ticket"]),
    environment=attribute_maps(["mode"]),
    risk=st.sampled_from(list(RiskLevel)),
)
@settings(max_examples=300, deadline=None)
def test_residual_matches_full_evaluation(
    *,
    policy: PolicySet,
    subject_attrs: dict[str, Any],
    resource_attrs: list[dict[str, Any]],
    classifications: list[int],
    action: str,
    resource_type: str,
    environment: dict[str, Any],
    risk: RiskLevel,
) -> None:
    subject = Subject(id="a", attributes=subject_attrs)
    base = PolicyRequest(
        subject=subject,
        action=action,
        resource=Resource(type=resource_type),
        risk=risk,
        environment=environment,
    )
    residual = allow_residual(policy, base)
    engine = PolicyEngine(policy)
    for attributes, classification in zip(resource_attrs, classifications, strict=False):
        resource = Resource(
            type=resource_type,
            id="r",
            classification=DataClassification(classification),
            attributes=attributes,
        )
        request = base.model_copy(update={"resource": resource})
        full = engine.evaluate(request).decision is Decision.ALLOW
        assert evaluate(residual, request.facts()) is full


def test_shipped_policy_residual_for_unscoped_agent() -> None:
    policy = PolicySet.from_file(ROOT / "policies" / "runtime-authorization.yaml")
    request = PolicyRequest(
        subject=Subject(
            id="agent-1",
            attributes={"department": "finance", "action_in_scope": False, "delegated": False},
        ),
        action="documents:read",
        resource=Resource(type="document"),
        risk=RiskLevel.LOW,
        environment={"intent": {"approved": False}},
    )
    residual = allow_residual(policy, request)
    rendered = to_dict(residual)
    assert rendered["op"] == "and"
    refs = referenced_attributes(residual)
    assert refs == {
        "resource.quarantined",
        "resource.classification",
        "resource.owner",
        "resource.department",
    }
    owned = request.model_copy(
        update={"resource": Resource(type="document", attributes={"owner": "agent-1"})}
    )
    assert evaluate(residual, owned.facts()) is True
    other = request.model_copy(
        update={"resource": Resource(type="document", attributes={"department": "legal"})}
    )
    assert evaluate(residual, other.facts()) is False


def test_scoped_critical_delegated_is_never_allowed() -> None:
    policy = PolicySet.from_file(ROOT / "policies" / "runtime-authorization.yaml")
    request = PolicyRequest(
        subject=Subject(id="a", attributes={"action_in_scope": True, "delegated": True}),
        action="payments:execute",
        resource=Resource(type="payment"),
        risk=RiskLevel.CRITICAL,
        environment={"intent": {"approved": True}},
    )
    assert allow_residual(policy, request) == FALSE


def test_simplification() -> None:
    a = Cond(Condition(attribute="resource.a", operator=Operator.EQ, value=1))
    b = Cond(Condition(attribute="resource.b", operator=Operator.EQ, value=2))
    assert conj([]) == TRUE
    assert conj([TRUE, a]) == a
    assert conj([a, FALSE]) == FALSE
    assert conj([And((a, b)), a]) == And((a, b, a))
    assert disj([]) == FALSE
    assert disj([FALSE, a]) == a
    assert disj([a, TRUE]) == TRUE
    assert disj([Or((a, b)), b]) == Or((a, b, b))
    assert neg(TRUE) == FALSE
    assert neg(neg(a)) == a
    assert neg(a) == Not(a)
    assert to_dict(Not(Or((a, b))))["arg"]["op"] == "or"
    assert to_dict(FALSE) == {"op": "false"}
    assert referenced_attributes(Not(a)) == {"resource.a"}


@pytest.mark.parametrize(
    ("condition", "known", "expected"),
    [
        (
            Condition(attribute="subject.id", operator=Operator.EQ_ATTR, value="resource.owner"),
            {"subject": {"id": "x"}},
            Cond(Condition(attribute="resource.owner", operator=Operator.EQ, value="x")),
        ),
        (
            Condition(attribute="subject.id", operator=Operator.EQ_ATTR, value="resource.owner"),
            {"subject": {}},
            FALSE,
        ),
        (
            Condition(attribute="resource.owner", operator=Operator.EQ_ATTR, value="subject.id"),
            {"subject": {"id": "x"}},
            Cond(Condition(attribute="resource.owner", operator=Operator.EQ, value="x")),
        ),
        (
            Condition(attribute="resource.owner", operator=Operator.EQ_ATTR, value="subject.id"),
            {"subject": {}},
            FALSE,
        ),
        (
            Condition(
                attribute="resource.owner", operator=Operator.EQ_ATTR, value="resource.author"
            ),
            {},
            Cond(
                Condition(
                    attribute="resource.owner", operator=Operator.EQ_ATTR, value="resource.author"
                )
            ),
        ),
        (
            Condition(attribute="subject.a", operator=Operator.EQ_ATTR, value="subject.b"),
            {"subject": {"a": 1, "b": 1}},
            TRUE,
        ),
        (
            Condition(attribute="resource.type", operator=Operator.EQ, value="document"),
            {"resource": {"type": "document"}},
            TRUE,
        ),
    ],
)
def test_partial_condition_substitution(
    condition: Condition, known: dict[str, Any], expected: object
) -> None:
    assert partial_condition(condition, known) == expected
