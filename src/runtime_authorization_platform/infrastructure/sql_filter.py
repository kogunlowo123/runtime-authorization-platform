"""Push a partial-evaluation residual down into SQL as a WHERE clause.

Data services that list resources (documents, tickets, records) call
``POST /v1/filter`` once per query, receive the residual expression, and
compile it here against their own columns, so authorization filtering
happens in the database instead of row by row.

SQL NULL stands for "attribute missing". Every comparison is wrapped with
``IS NOT NULL`` so it evaluates to a definite TRUE/FALSE, which keeps NOT
correct under three-valued logic and matches the policy engine, where any
comparison against a missing attribute is false.
"""

from __future__ import annotations

import operator
from collections.abc import Callable, Mapping
from typing import Any

from agentic_core.policy import Condition, Operator
from sqlalchemy import ColumnElement, and_, false, not_, or_, true

from runtime_authorization_platform.policy.partial import And, Cond, Const, Expr, Not, Or


class UnsupportedFilterError(ValueError):
    """The residual cannot be expressed over the given columns; filter in memory instead."""


def _column(columns: Mapping[str, ColumnElement[Any]], path: str) -> ColumnElement[Any]:
    column = columns.get(path)
    if column is None:
        raise UnsupportedFilterError(f"no column mapped for {path}")
    return column


_BINARY: dict[Operator, Callable[[Any, Any], Any]] = {
    Operator.EQ: operator.eq,
    Operator.NE: operator.ne,
    Operator.GT: operator.gt,
    Operator.GTE: operator.ge,
    Operator.LT: operator.lt,
    Operator.LTE: operator.le,
}


def _comparison(op: Operator, column: ColumnElement[Any], value: Any) -> Any:
    binary = _BINARY.get(op)
    if binary is not None:
        return binary(column, value)
    match op:
        case Operator.IN | Operator.NOT_IN if isinstance(value, list | tuple):
            members = list(value)
            return column.in_(members) if op is Operator.IN else column.not_in(members)
        case Operator.CONTAINS if isinstance(value, str):
            return column.contains(value, autoescape=True)
        case Operator.CONTAINS_ANY if isinstance(value, list | tuple) and all(
            isinstance(v, str) for v in value
        ):
            return or_(false(), *(column.contains(v, autoescape=True) for v in value))
    raise UnsupportedFilterError(f"operator {op.value} with {type(value).__name__}")


def _condition(condition: Condition, columns: Mapping[str, ColumnElement[Any]]) -> Any:
    column = _column(columns, condition.attribute)
    present = column.is_not(None)
    op, value = condition.operator, condition.value
    if op is Operator.EXISTS:
        wanted = bool(value if value is not None else True)
        return present if wanted else column.is_(None)
    if op is Operator.EQ_ATTR:
        other = _column(columns, str(value))
        return and_(present, other.is_not(None), column == other)
    if value is None:
        raise UnsupportedFilterError("comparisons with null are not expressible in SQL")
    return and_(present, _comparison(op, column, value))


def to_sqlalchemy(expr: Expr, columns: Mapping[str, ColumnElement[Any]]) -> Any:
    """Compile a residual to a SQLAlchemy boolean clause.

    ``columns`` maps policy attribute paths (``resource.owner``,
    ``resource.classification``...) to columns of the caller's table.
    """
    match expr:
        case Const(value):
            return true() if value else false()
        case Cond(condition):
            return _condition(condition, columns)
        case And(args):
            return and_(true(), *(to_sqlalchemy(a, columns) for a in args))
        case Or(args):
            return or_(false(), *(to_sqlalchemy(a, columns) for a in args))
        case Not(arg):
            return not_(to_sqlalchemy(arg, columns))
    raise TypeError(f"unknown expression {expr!r}")  # pragma: no cover - exhaustive
