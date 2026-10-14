"""Partial evaluation of agentic-core policy sets for list filtering.

Given everything except the resource (subject, action, risk, environment and
the resource *type*), each rule reduces to TRUE, FALSE, or a residual
condition over ``resource.*`` attributes. The policy's combining algorithm
(deny overrides, then require_approval, then allow, default deny) turns the
per-rule residuals into one expression that is true exactly for resources the
full evaluation would ALLOW:

    allowed = NOT any(deny) AND NOT any(require_approval) AND any(allow)

Residual conditions are the policy's own ``Condition`` objects, evaluated by
the same code path as a full decision, so filtering and deciding cannot
disagree. ``tests/unit/test_partial.py`` checks that equivalence with
property-based tests.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from agentic_core.domain.classification import Decision
from agentic_core.policy import Condition, Operator, PolicyRequest, PolicySet, Rule

MISSING: Any = object()


def lookup(facts: dict[str, Any], path: str) -> Any:
    """Resolve a dotted path with the same semantics as the agentic-core engine."""
    current: Any = facts
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return MISSING
    return current


def is_resource_path(path: str) -> bool:
    """Paths unknown at partial-evaluation time (the resource type is known)."""
    return path.split(".", 1)[0] == "resource" and path != "resource.type"


# ------------------------------------------------------------------ expressions


@dataclass(frozen=True)
class Const:
    value: bool


@dataclass(frozen=True)
class Cond:
    condition: Condition


@dataclass(frozen=True)
class And:
    args: tuple[Expr, ...]


@dataclass(frozen=True)
class Or:
    args: tuple[Expr, ...]


@dataclass(frozen=True)
class Not:
    arg: Expr


Expr = Const | Cond | And | Or | Not

TRUE = Const(True)
FALSE = Const(False)


def conj(args: Iterable[Expr]) -> Expr:
    flat: list[Expr] = []
    for arg in args:
        if arg == FALSE:
            return FALSE
        if arg == TRUE:
            continue
        flat.extend(arg.args if isinstance(arg, And) else (arg,))
    if not flat:
        return TRUE
    return flat[0] if len(flat) == 1 else And(tuple(flat))


def disj(args: Iterable[Expr]) -> Expr:
    flat: list[Expr] = []
    for arg in args:
        if arg == TRUE:
            return TRUE
        if arg == FALSE:
            continue
        flat.extend(arg.args if isinstance(arg, Or) else (arg,))
    if not flat:
        return FALSE
    return flat[0] if len(flat) == 1 else Or(tuple(flat))


def neg(arg: Expr) -> Expr:
    if isinstance(arg, Const):
        return Const(not arg.value)
    if isinstance(arg, Not):
        return arg.arg
    return Not(arg)


def evaluate(expr: Expr, facts: dict[str, Any]) -> bool:
    match expr:
        case Const(value):
            return value
        case Cond(condition):
            return condition.evaluate(facts)
        case And(args):
            return all(evaluate(a, facts) for a in args)
        case Or(args):
            return any(evaluate(a, facts) for a in args)
        case Not(arg):
            return not evaluate(arg, facts)
    raise TypeError(f"unknown expression {expr!r}")  # pragma: no cover - exhaustive


def to_dict(expr: Expr) -> dict[str, Any]:
    """JSON form returned by ``POST /v1/filter`` for callers that push filters down."""
    match expr:
        case Const(value):
            return {"op": "true" if value else "false"}
        case Cond(condition):
            return {
                "op": "cond",
                "attribute": condition.attribute,
                "operator": condition.operator.value,
                "value": condition.value,
            }
        case And(args):
            return {"op": "and", "args": [to_dict(a) for a in args]}
        case Or(args):
            return {"op": "or", "args": [to_dict(a) for a in args]}
        case Not(arg):
            return {"op": "not", "arg": to_dict(arg)}
    raise TypeError(f"unknown expression {expr!r}")  # pragma: no cover - exhaustive


def referenced_attributes(expr: Expr) -> set[str]:
    match expr:
        case Const():
            return set()
        case Cond(condition):
            refs = {condition.attribute}
            if condition.operator is Operator.EQ_ATTR:
                refs.add(str(condition.value))
            return refs
        case And(args) | Or(args):
            return set().union(*(referenced_attributes(a) for a in args))
        case Not(arg):
            return referenced_attributes(arg)
    raise TypeError(f"unknown expression {expr!r}")  # pragma: no cover - exhaustive


# ------------------------------------------------------------- partial evaluation


def partial_condition(  # noqa: PLR0911 - one return per substitution case
    condition: Condition, known: dict[str, Any]
) -> Expr:
    attribute_unknown = is_resource_path(condition.attribute)
    if condition.operator is Operator.EQ_ATTR:
        other = str(condition.value)
        other_unknown = is_resource_path(other)
        if attribute_unknown and other_unknown:
            return Cond(condition)
        if attribute_unknown:
            expected = lookup(known, other)
            if expected is MISSING:
                return FALSE
            return Cond(
                Condition(attribute=condition.attribute, operator=Operator.EQ, value=expected)
            )
        if other_unknown:
            actual = lookup(known, condition.attribute)
            if actual is MISSING:
                return FALSE
            return Cond(Condition(attribute=other, operator=Operator.EQ, value=actual))
    elif attribute_unknown:
        return Cond(condition)
    return TRUE if condition.evaluate(known) else FALSE


def partial_rule(rule: Rule, *, action: str, resource_type: str, known: dict[str, Any]) -> Expr:
    if not any(fnmatch.fnmatchcase(action, pattern) for pattern in rule.actions):
        return FALSE
    if not any(fnmatch.fnmatchcase(resource_type, pattern) for pattern in rule.resource_types):
        return FALSE
    return conj(partial_condition(c, known) for c in rule.conditions)


def known_facts(request: PolicyRequest) -> dict[str, Any]:
    """Facts of a request with every resource attribute except the type removed."""
    facts = request.facts()
    facts["resource"] = {"type": request.resource.type}
    return facts


def allow_residual(policy: PolicySet, request: PolicyRequest) -> Expr:
    """Expression over ``resource.*`` that holds exactly when the decision is ALLOW.

    ``request.resource`` supplies only the type; its id and attributes are ignored.
    """
    known = known_facts(request)
    by_effect: dict[Decision, list[Expr]] = {d: [] for d in Decision}
    for rule in policy.rules:
        residual = partial_rule(
            rule, action=request.action, resource_type=request.resource.type, known=known
        )
        by_effect[rule.effect].append(residual)
    return conj(
        (
            neg(disj(by_effect[Decision.DENY])),
            neg(disj(by_effect[Decision.REQUIRE_APPROVAL])),
            disj(by_effect[Decision.ALLOW]),
        )
    )
