"""Export agentic-core policy sets as Rego for Open Policy Agent.

The generated module evaluates the same ``input`` document the platform
sends to OPA (``PolicyRequest.facts()``) and produces the same combining
result: deny overrides, then require_approval, then allow, default deny.

Semantics are kept aligned with the Python engine:

* globs (``fnmatch``) are translated to anchored RE2 expressions;
* a missing attribute makes every operator except ``exists`` false;
* ordering comparisons are type-guarded, because Rego orders values of
  different types where Python raises ``TypeError`` (treated as false).

``tests/integration/test_opa_parity.py`` checks decision parity against a
real OPA server.
"""

from __future__ import annotations

import json
import re
from typing import Any

from agentic_core.domain.classification import Decision
from agentic_core.policy import Condition, Operator, PolicySet, Rule

_RULE_SETS = {
    Decision.DENY: "deny_rules",
    Decision.REQUIRE_APPROVAL: "approval_rules",
    Decision.ALLOW: "allow_rules",
}
_PACKAGE = re.compile(r"^[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*)*$")

_HELPERS = """\
_glob_any(patterns, value) if {
\tsome pattern in patterns
\tregex.match(pattern, value)
}

_has(path) if object.get(input, path, 0) == object.get(input, path, 1)

_member(value, collection) if {
\tis_string(collection)
\tcontains(collection, value)
}

_member(value, collection) if {
\tnot is_string(collection)
\tvalue in collection
}

_contains(container, item) if {
\tis_string(container)
\tcontains(container, item)
}

_contains(container, item) if {
\tnot is_string(container)
\titem in container
}
"""


def glob_to_regex(pattern: str) -> str:
    """Translate an ``fnmatch`` glob to an anchored RE2 expression."""
    out: list[str] = ["^"]
    i = 0
    while i < len(pattern):
        char = pattern[i]
        if char == "*":
            out.append(".*")
        elif char == "?":
            out.append(".")
        elif char == "[":
            end = pattern.find("]", i + 2 if pattern[i + 1 : i + 2] in {"!", "]"} else i + 1)
            if end == -1:
                out.append(re.escape(char))
            else:
                body = pattern[i + 1 : end]
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append("[" + body.replace("\\", "\\\\") + "]")
                i = end
        else:
            out.append(re.escape(char))
        i += 1
    out.append("$")
    return "".join(out)


def _literal(value: Any) -> str:
    return json.dumps(value, sort_keys=True)


def _ref(path: str) -> str:
    return "input" + "".join(f"[{_literal(part)}]" for part in path.split("."))


def _path(path: str) -> str:
    return _literal(path.split("."))


def _comparison_guard(value: Any) -> str | None:
    if isinstance(value, bool):
        return "is_boolean"
    if isinstance(value, int | float):
        return "is_number"
    if isinstance(value, str):
        return "is_string"
    return None


def condition_body(condition: Condition, var: str) -> list[str]:
    """Rego expressions that hold exactly when ``condition.evaluate`` is true."""
    op, value = condition.operator, condition.value
    if op is Operator.EXISTS:
        wanted = bool(value if value is not None else True)
        test = f"_has({_path(condition.attribute)})"
        return [test if wanted else f"not {test}"]
    lines = [f"{var} := {_ref(condition.attribute)}"]
    match op:
        case Operator.EQ:
            lines.append(f"{var} == {_literal(value)}")
        case Operator.NE:
            lines.append(f"{var} != {_literal(value)}")
        case Operator.IN:
            lines.append(f"_member({var}, {_literal(value)})")
        case Operator.NOT_IN:
            lines.append(f"not _member({var}, {_literal(value)})")
        case Operator.CONTAINS:
            lines.append(f"_contains({var}, {_literal(value)})")
        case Operator.CONTAINS_ANY:
            lines.append(f"some {var}_item in {_literal(value)}")
            lines.append(f"_contains({var}, {var}_item)")
        case Operator.GT | Operator.GTE | Operator.LT | Operator.LTE:
            symbol = {
                Operator.GT: ">",
                Operator.GTE: ">=",
                Operator.LT: "<",
                Operator.LTE: "<=",
            }[op]
            guard = _comparison_guard(value)
            if guard:
                lines.append(f"{guard}({var})")
            lines.append(f"{var} {symbol} {_literal(value)}")
        case Operator.EQ_ATTR:
            lines.append(f"{var}_other := {_ref(str(value))}")
            lines.append(f"{var} == {var}_other")
    return lines


def rule_block(rule: Rule) -> str:
    actions = _literal([glob_to_regex(a) for a in rule.actions])
    types = _literal([glob_to_regex(t) for t in rule.resource_types])
    body = [f"_glob_any({actions}, input.action)", f"_glob_any({types}, input.resource.type)"]
    for index, condition in enumerate(rule.conditions):
        body.extend(condition_body(condition, f"v{index}"))
    description = " ".join(rule.description.split())
    comment = f"# {description}\n" if description else ""
    inner = "\n".join(f"\t{line}" for line in body)
    return f"{comment}{_RULE_SETS[rule.effect]} contains {_literal(rule.id)} if {{\n{inner}\n}}\n"


def export(policy: PolicySet, *, package: str = "rap.authz") -> str:
    """Rego v1 module whose ``result`` mirrors ``PolicyEngine.evaluate``."""
    if not _PACKAGE.fullmatch(package):
        raise ValueError(f"invalid Rego package {package!r}")
    header = (
        f"# Generated from policy set {policy.name} {policy.version} ({policy.digest}).\n"
        "# Regenerate with: authz-policy-test rego <policy.yaml>\n"
        f"package {package}\n\nimport rego.v1\n\n"
    )
    rules = "\n".join(rule_block(rule) for rule in policy.rules)
    combining = f"""\
default decision := "deny"

decision := "require_approval" if {{
\tcount(deny_rules) == 0
\tcount(approval_rules) > 0
}}

decision := "allow" if {{
\tcount(deny_rules) == 0
\tcount(approval_rules) == 0
\tcount(allow_rules) > 0
}}

default matched_rules := set()

matched_rules := deny_rules if count(deny_rules) > 0

matched_rules := approval_rules if {{
\tcount(deny_rules) == 0
\tcount(approval_rules) > 0
}}

matched_rules := allow_rules if {{
\tcount(deny_rules) == 0
\tcount(approval_rules) == 0
\tcount(allow_rules) > 0
}}

result := {{
\t"decision": decision,
\t"matched_rules": matched_rules,
\t"policy_name": {_literal(policy.name)},
\t"policy_version": {_literal(policy.version)},
\t"policy_digest": {_literal(policy.digest)},
}}
"""
    empty_sets = "".join(
        f"{name} contains rule_id if {{\n\tsome rule_id in set()\n}}\n\n"
        for effect, name in _RULE_SETS.items()
        if not any(r.effect is effect for r in policy.rules)
    )
    return header + empty_sets + rules + "\n" + combining + "\n" + _HELPERS
