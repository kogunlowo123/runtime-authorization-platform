"""Rego export structure. Decision parity with a live OPA is in tests/integration."""

from __future__ import annotations

import fnmatch
import re

import pytest
from agentic_core.domain.classification import Decision
from agentic_core.policy import Condition, Operator, PolicySet, Rule
from hypothesis import given
from hypothesis import strategies as st

from runtime_authorization_platform.policy.rego import condition_body, export, glob_to_regex
from tests.conftest import ROOT


@pytest.mark.parametrize(
    ("pattern", "value", "matches"),
    [
        ("*", "anything:at/all", True),
        ("documents:*", "documents:read", True),
        ("documents:*", "tickets:read", False),
        ("*:read", "fhir:patient:read", True),
        ("doc?:read", "docs:read", True),
        ("doc?:read", "documents:read", False),
        ("[abc]x", "bx", True),
        ("[!abc]x", "bx", False),
        ("[!abc]x", "dx", True),
        ("a.b", "aXb", False),
        ("[unclosed", "[unclosed", True),
    ],
)
def test_glob_translation(pattern: str, value: str, matches: bool) -> None:
    assert (re.fullmatch(glob_to_regex(pattern), value) is not None) is matches
    assert fnmatch.fnmatchcase(value, pattern) is matches


@given(
    pattern=st.text(alphabet="ab:*?.", max_size=6),
    value=st.text(alphabet="ab:.", max_size=6),
)
def test_glob_translation_agrees_with_fnmatch(pattern: str, value: str) -> None:
    assert (re.fullmatch(glob_to_regex(pattern), value) is not None) == fnmatch.fnmatchcase(
        value, pattern
    )


def test_export_shipped_policy() -> None:
    policy = PolicySet.from_file(ROOT / "policies" / "runtime-authorization.yaml")
    module = export(policy, package="rap.authz")
    assert module.startswith("# Generated from policy set runtime-authorization")
    assert "package rap.authz" in module
    assert "import rego.v1" in module
    for rule in policy.rules:
        assert f'"{rule.id}"' in module
    assert f'"policy_digest": "{policy.digest}"' in module
    assert 'default decision := "deny"' in module


def test_export_declares_empty_rule_sets() -> None:
    policy = PolicySet(
        name="only-allow",
        version="1",
        rules=(Rule(id="a", effect=Decision.ALLOW, actions=("*",), description="multi\nline"),),
    )
    module = export(policy)
    assert "deny_rules contains rule_id if" in module
    assert "approval_rules contains rule_id if" in module
    assert "# multi line" in module


def test_invalid_package() -> None:
    policy = PolicySet(
        name="p", version="1", rules=(Rule(id="a", effect=Decision.ALLOW, actions=("*",)),)
    )
    with pytest.raises(ValueError, match="invalid Rego package"):
        export(policy, package="Bad-Package")


@pytest.mark.parametrize(
    ("operator", "value", "fragment"),
    [
        (Operator.EQ, 3, "v0 == 3"),
        (Operator.NE, "x", 'v0 != "x"'),
        (Operator.IN, ["a"], '_member(v0, ["a"])'),
        (Operator.NOT_IN, ["a"], 'not _member(v0, ["a"])'),
        (Operator.CONTAINS, "a", '_contains(v0, "a")'),
        (Operator.CONTAINS_ANY, ["a"], 'some v0_item in ["a"]'),
        (Operator.GT, 1, "is_number(v0)"),
        (Operator.GTE, "m", "is_string(v0)"),
        (Operator.LT, True, "is_boolean(v0)"),
        (Operator.LTE, [1], "v0 <= [1]"),
        (Operator.EQ_ATTR, "resource.owner", 'v0_other := input["resource"]["owner"]'),
        (Operator.EXISTS, True, '_has(["subject", "x"])'),
        (Operator.EXISTS, False, 'not _has(["subject", "x"])'),
        (Operator.EXISTS, None, '_has(["subject", "x"])'),
    ],
)
def test_condition_translation(operator: Operator, value: object, fragment: str) -> None:
    body = condition_body(Condition(attribute="subject.x", operator=operator, value=value), "v0")
    assert any(fragment in line for line in body), body
