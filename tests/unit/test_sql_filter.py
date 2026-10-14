"""Residual push-down to SQL must select exactly the rows full evaluation allows."""

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
    Subject,
)
from sqlalchemy import Column, Integer, MetaData, String, Table, insert, select
from sqlalchemy.ext.asyncio import create_async_engine

from runtime_authorization_platform.infrastructure.sql_filter import (
    UnsupportedFilterError,
    to_sqlalchemy,
)
from runtime_authorization_platform.policy.partial import (
    FALSE,
    TRUE,
    And,
    Cond,
    Not,
    Or,
    allow_residual,
)
from tests.conftest import ROOT

metadata = MetaData()
documents = Table(
    "documents",
    metadata,
    Column("id", String, primary_key=True),
    Column("owner", String),
    Column("department", String),
    Column("classification", Integer, nullable=False),
    Column("quarantined", Integer),
    Column("title", String),
)
COLUMNS = {
    "resource.id": documents.c.id,
    "resource.owner": documents.c.owner,
    "resource.department": documents.c.department,
    "resource.classification": documents.c.classification,
    "resource.quarantined": documents.c.quarantined,
    "resource.title": documents.c.title,
}
ROWS: list[dict[str, Any]] = [
    {
        "id": "d1",
        "owner": "agent-1",
        "department": "legal",
        "classification": 1,
        "quarantined": None,
        "title": "a_b",
    },
    {
        "id": "d2",
        "owner": None,
        "department": "finance",
        "classification": 2,
        "quarantined": None,
        "title": "x%y",
    },
    {
        "id": "d3",
        "owner": None,
        "department": "finance",
        "classification": 3,
        "quarantined": None,
        "title": None,
    },
    {
        "id": "d4",
        "owner": "agent-1",
        "department": "finance",
        "classification": 1,
        "quarantined": 1,
        "title": "t",
    },
    {
        "id": "d5",
        "owner": "other",
        "department": None,
        "classification": 0,
        "quarantined": None,
        "title": "t",
    },
]


def as_resource(row: dict[str, Any]) -> Resource:
    attributes = {
        k: (bool(v) if k == "quarantined" else v)
        for k, v in row.items()
        if k not in {"id", "classification"} and v is not None
    }
    return Resource(
        type="document",
        id=row["id"],
        classification=DataClassification(row["classification"]),
        attributes=attributes,
    )


async def selected(clause: Any) -> set[str]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(metadata.create_all)
        await conn.execute(insert(documents), ROWS)
        rows = (await conn.execute(select(documents.c.id).where(clause))).all()
    await engine.dispose()
    return {r[0] for r in rows}


@pytest.mark.parametrize(
    ("subject", "environment"),
    [
        ({"department": "finance", "action_in_scope": False, "delegated": False}, {}),
        ({"department": "legal", "action_in_scope": False, "delegated": False}, {}),
        ({"action_in_scope": True, "delegated": False}, {}),
        ({"action_in_scope": True, "delegated": False}, {"purpose_of_use": "audit"}),
    ],
)
async def test_pushdown_matches_policy(
    subject: dict[str, Any], environment: dict[str, Any]
) -> None:
    policy = PolicySet.from_file(ROOT / "policies" / "runtime-authorization.yaml")
    base = PolicyRequest(
        subject=Subject(id="agent-1", attributes=subject),
        action="documents:read",
        resource=Resource(type="document"),
        risk=RiskLevel.LOW,
        environment={**environment, "intent": {"approved": False}},
    )
    residual = allow_residual(policy, base)
    engine = PolicyEngine(policy)
    expected = {
        row["id"]
        for row in ROWS
        if engine.evaluate(base.model_copy(update={"resource": as_resource(row)})).decision
        is Decision.ALLOW
    }
    assert await selected(to_sqlalchemy(residual, COLUMNS)) == expected


def cond(attribute: str, operator: Operator, value: Any) -> Cond:
    return Cond(Condition(attribute=attribute, operator=operator, value=value))


@pytest.mark.parametrize(
    ("expr", "ids"),
    [
        (TRUE, {"d1", "d2", "d3", "d4", "d5"}),
        (FALSE, set()),
        (cond("resource.owner", Operator.NE, "agent-1"), {"d5"}),
        (Not(cond("resource.owner", Operator.EQ, "agent-1")), {"d2", "d3", "d5"}),
        (cond("resource.classification", Operator.GT, 1), {"d2", "d3"}),
        (cond("resource.classification", Operator.LT, 1), {"d5"}),
        (cond("resource.department", Operator.IN, ["legal", "hr"]), {"d1"}),
        (cond("resource.department", Operator.NOT_IN, ["legal"]), {"d2", "d3", "d4"}),
        (cond("resource.title", Operator.CONTAINS, "%"), {"d2"}),
        (cond("resource.title", Operator.CONTAINS, "_"), {"d1"}),
        (cond("resource.title", Operator.CONTAINS_ANY, ["%", "_"]), {"d1", "d2"}),
        (cond("resource.owner", Operator.EXISTS, True), {"d1", "d4", "d5"}),
        (cond("resource.owner", Operator.EXISTS, False), {"d2", "d3"}),
        (cond("resource.owner", Operator.EQ_ATTR, "resource.department"), set()),
        (
            Or(
                (
                    cond("resource.id", Operator.EQ, "d1"),
                    And((TRUE, cond("resource.id", Operator.EQ, "d2"))),
                )
            ),
            {"d1", "d2"},
        ),
    ],
)
async def test_operators(expr: Any, ids: set[str]) -> None:
    assert await selected(to_sqlalchemy(expr, COLUMNS)) == ids


@pytest.mark.parametrize(
    "expr",
    [
        cond("resource.unmapped", Operator.EQ, 1),
        cond("resource.owner", Operator.EQ, None),
        cond("resource.owner", Operator.CONTAINS, 5),
        cond("resource.owner", Operator.IN, "abc"),
        cond("resource.owner", Operator.EQ_ATTR, "resource.unmapped"),
    ],
)
def test_unsupported(expr: Any) -> None:
    with pytest.raises(UnsupportedFilterError):
        to_sqlalchemy(expr, COLUMNS)
