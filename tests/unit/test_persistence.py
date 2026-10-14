"""Repositories against SQLite (PostgreSQL in tests/integration)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from agentic_core.domain.classification import DataClassification, Decision, RiskLevel
from sqlalchemy.ext.asyncio import AsyncEngine

from runtime_authorization_platform.domain.errors import ConflictError, NotFoundError
from runtime_authorization_platform.domain.models import (
    ActionBlock,
    DecisionRecord,
    Intent,
    IntentStatus,
    PolicyStatus,
    PolicyVersion,
)
from runtime_authorization_platform.infrastructure.database import (
    SqlActionBlockRepository,
    SqlDecisionLog,
    SqlIntentRepository,
    SqlPolicyRepository,
    SystemClock,
    create_schema,
    make_engine,
    utc,
)

NOW = datetime(2026, 10, 14, 12, 0, tzinfo=UTC)


def make_intent(intent_id: str = "i1", **kw: object) -> Intent:
    values: dict[str, object] = {
        "intent_id": intent_id,
        "principal_id": "agent",
        "action": "documents:delete",
        "resource_type": "document",
        "resource_id": "d1",
        "justification": "Remove the duplicate supplier agreement.",
        "purpose": "hygiene",
        "risk": RiskLevel.HIGH,
        "status": IntentStatus.ACTIVE,
        "max_uses": 2,
        "created_at": NOW,
        "expires_at": NOW + timedelta(minutes=15),
    }
    values.update(kw)
    return Intent.model_validate(values)


def make_version(version_id: str, digest: str, **kw: object) -> PolicyVersion:
    values: dict[str, object] = {
        "version_id": version_id,
        "name": "p",
        "version": "1",
        "digest": digest,
        "status": PolicyStatus.DRAFT,
        "document": {"name": "p", "version": "1", "rules": []},
        "tests": [{"name": "t"}],
        "test_summary": {"ok": True},
        "author": "alice",
        "created_at": NOW,
    }
    values.update(kw)
    return PolicyVersion.model_validate(values)


def make_record(
    decision_id: str, *, at: datetime, decision: Decision = Decision.ALLOW
) -> DecisionRecord:
    return DecisionRecord(
        decision_id=decision_id,
        timestamp=at,
        caller_id="gw",
        subject_id="agent",
        action="documents:read",
        resource_type="document",
        resource_id="d1",
        decision=decision,
        reason="r",
        stage="policy",
        matched_rules=("allow-scoped-actions",),
        policy_name="p",
        policy_version="1",
        policy_digest="sha256:x",
        engine="local",
        intent_id=None,
        dry_run=False,
        latency_ms=1.5,
        correlation_id="c",
        attribute_sources={"resource": "request"},
        classification=DataClassification.INTERNAL,
    )


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncEngine:
    built = make_engine(f"sqlite+aiosqlite:///{tmp_path / 'p.db'}")
    await create_schema(built)
    await create_schema(built)  # idempotent
    return built


async def test_intents(engine: AsyncEngine) -> None:
    repo = SqlIntentRepository(engine)
    intent = make_intent()
    await repo.add(intent)
    assert await repo.get("i1") == intent
    assert await repo.get("nope") is None
    first = await repo.consume("i1", now=NOW)
    assert first is not None
    assert first.uses == 1
    assert first.status is IntentStatus.ACTIVE
    second = await repo.consume("i1", now=NOW)
    assert second is not None
    assert second.status is IntentStatus.CONSUMED
    assert await repo.consume("i1", now=NOW) is None
    await repo.update(second.model_copy(update={"approved_by": "bob", "approved_at": NOW}))
    assert (await repo.get("i1")).approved_by == "bob"  # type: ignore[union-attr]
    with pytest.raises(NotFoundError):
        await repo.update(make_intent("missing"))

    await repo.add(make_intent("i2"))
    assert await repo.consume("i2", now=NOW + timedelta(hours=1)) is None
    assert await repo.expire(NOW + timedelta(hours=1)) == 1
    assert (await repo.get("i2")).status is IntentStatus.EXPIRED  # type: ignore[union-attr]


async def test_policies(engine: AsyncEngine) -> None:
    repo = SqlPolicyRepository(engine)
    await repo.add(make_version("v1", "sha256:1"))
    await repo.add(make_version("v2", "sha256:2", created_at=NOW + timedelta(seconds=1)))
    with pytest.raises(ConflictError):
        await repo.add(make_version("v3", "sha256:1"))
    assert await repo.active() is None
    active = await repo.activate("v1", actor="bob", at=NOW)
    assert active.status is PolicyStatus.ACTIVE
    assert active.activated_by == "bob"
    await repo.activate("v2", actor="bob", at=NOW)
    assert (await repo.get("v1")).status is PolicyStatus.SUPERSEDED  # type: ignore[union-attr]
    assert (await repo.active()).version_id == "v2"  # type: ignore[union-attr]
    assert (await repo.by_digest("sha256:1")).version_id == "v1"  # type: ignore[union-attr]
    assert await repo.by_digest("sha256:none") is None
    assert [v.version_id for v in await repo.list(limit=10, offset=0)] == ["v2", "v1"]
    with pytest.raises(NotFoundError):
        await repo.activate("missing", actor="bob", at=NOW)


async def test_decision_log(engine: AsyncEngine) -> None:
    log = SqlDecisionLog(engine)
    await log.append(make_record("a", at=NOW - timedelta(days=500)))
    await log.append(make_record("b", at=NOW, decision=Decision.DENY))
    recent = await log.query(
        subject_id="agent",
        action="documents:read",
        decision=None,
        since=NOW - timedelta(days=1),
        limit=5,
        offset=0,
    )
    assert [r.decision_id for r in recent] == ["b"]
    assert recent[0].matched_rules == ("allow-scoped-actions",)
    assert recent[0].timestamp == NOW
    assert await log.purge_before(NOW - timedelta(days=400)) == 1
    assert (
        len(
            await log.query(
                subject_id=None, action=None, decision=Decision.DENY, since=None, limit=5, offset=0
            )
        )
        == 1
    )


async def test_action_blocks(engine: AsyncEngine) -> None:
    repo = SqlActionBlockRepository(engine)
    block = ActionBlock(
        block_id="b1", pattern="payments:*", reason="r", created_by="sec", created_at=NOW
    )
    await repo.add(block)
    assert await repo.list() == [block]
    assert await repo.remove("b1") == block
    assert await repo.remove("b1") is None


def test_helpers() -> None:
    assert utc(datetime(2026, 1, 1)).tzinfo is UTC
    assert SystemClock().now().tzinfo is UTC
