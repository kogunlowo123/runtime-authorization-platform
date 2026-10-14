"""SQLAlchemy Core persistence. PostgreSQL in production; SQLite in tests."""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from agentic_core.domain.classification import DataClassification, Decision, RiskLevel
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    Index,
    Integer,
    MetaData,
    Row,
    String,
    Table,
    Text,
    case,
    delete,
    insert,
    select,
    update,
)
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from runtime_authorization_platform.domain.errors import ConflictError, NotFoundError
from runtime_authorization_platform.domain.models import (
    ActionBlock,
    DecisionRecord,
    Intent,
    IntentStatus,
    PolicyStatus,
    PolicyVersion,
)

metadata = MetaData()

intents = Table(
    "intents",
    metadata,
    Column("intent_id", String(64), primary_key=True),
    Column("principal_id", String(512), nullable=False),
    Column("action", String(200), nullable=False),
    Column("resource_type", String(200), nullable=False),
    Column("resource_id", String(500), nullable=False),
    Column("justification", Text, nullable=False),
    Column("purpose", String(200), nullable=False),
    Column("risk", Integer, nullable=False),
    Column("status", String(16), nullable=False),
    Column("max_uses", Integer, nullable=False),
    Column("uses", Integer, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("approved_by", String(512)),
    Column("approved_at", DateTime(timezone=True)),
    Column("status_reason", Text),
    Column("injection_score", Float, nullable=False),
    Index("ix_intents_principal", "principal_id"),
    Index("ix_intents_status_expiry", "status", "expires_at"),
)

policy_versions = Table(
    "policy_versions",
    metadata,
    Column("version_id", String(64), primary_key=True),
    Column("name", String(200), nullable=False),
    Column("version", String(100), nullable=False),
    Column("digest", String(80), nullable=False, unique=True),
    Column("status", String(16), nullable=False),
    Column("document", Text, nullable=False),
    Column("tests", Text, nullable=False),
    Column("test_summary", Text, nullable=False),
    Column("author", String(512), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("activated_by", String(512)),
    Column("activated_at", DateTime(timezone=True)),
)
# At most one active version, enforced by the database.
Index(
    "ux_policy_single_active",
    policy_versions.c.status,
    unique=True,
    postgresql_where=policy_versions.c.status == "active",
    sqlite_where=policy_versions.c.status == "active",
)

decision_log = Table(
    "decision_log",
    metadata,
    Column("decision_id", String(64), primary_key=True),
    Column("timestamp", DateTime(timezone=True), nullable=False),
    Column("caller_id", String(512), nullable=False),
    Column("subject_id", String(512), nullable=False),
    Column("action", String(200), nullable=False),
    Column("resource_type", String(200), nullable=False),
    Column("resource_id", String(500), nullable=False),
    Column("decision", String(24), nullable=False),
    Column("reason", Text, nullable=False),
    Column("stage", String(16), nullable=False),
    Column("matched_rules", Text, nullable=False),
    Column("policy_name", String(200), nullable=False),
    Column("policy_version", String(100), nullable=False),
    Column("policy_digest", String(80), nullable=False),
    Column("engine", String(16), nullable=False),
    Column("intent_id", String(64)),
    Column("dry_run", Boolean, nullable=False),
    Column("latency_ms", Float, nullable=False),
    Column("correlation_id", String(64)),
    Column("attribute_sources", Text, nullable=False),
    Column("classification", Integer, nullable=False),
    Index("ix_decisions_subject_time", "subject_id", "timestamp"),
    Index("ix_decisions_decision_time", "decision", "timestamp"),
    Index("ix_decisions_time", "timestamp"),
)

action_blocks = Table(
    "action_blocks",
    metadata,
    Column("block_id", String(64), primary_key=True),
    Column("pattern", String(200), nullable=False, unique=True),
    Column("reason", Text, nullable=False),
    Column("created_by", String(512), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
)

schema_version = Table("schema_version", metadata, Column("version", Integer, primary_key=True))

SCHEMA_VERSION = 1


def make_engine(url: str) -> AsyncEngine:
    return create_async_engine(url, pool_pre_ping=True)


async def create_schema(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(metadata.create_all)
        current = (await conn.execute(select(schema_version.c.version))).scalar()
        if current is None:
            await conn.execute(insert(schema_version).values(version=SCHEMA_VERSION))


def utc(value: datetime) -> datetime:
    """Normalize to aware UTC; SQLite returns naive values."""
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _opt_utc(value: datetime | None) -> datetime | None:
    return utc(value) if value is not None else None


# ---------------------------------------------------------------------- intents


def _intent(row: Row[Any]) -> Intent:
    m = row._mapping
    return Intent(
        intent_id=m["intent_id"],
        principal_id=m["principal_id"],
        action=m["action"],
        resource_type=m["resource_type"],
        resource_id=m["resource_id"],
        justification=m["justification"],
        purpose=m["purpose"],
        risk=RiskLevel(m["risk"]),
        status=IntentStatus(m["status"]),
        max_uses=m["max_uses"],
        uses=m["uses"],
        created_at=utc(m["created_at"]),
        expires_at=utc(m["expires_at"]),
        approved_by=m["approved_by"],
        approved_at=_opt_utc(m["approved_at"]),
        status_reason=m["status_reason"],
        injection_score=m["injection_score"],
    )


def _intent_values(intent: Intent) -> dict[str, Any]:
    values = intent.model_dump()
    values["risk"] = int(intent.risk)
    values["status"] = intent.status.value
    for key in ("created_at", "expires_at", "approved_at"):
        if values[key] is not None:
            values[key] = utc(values[key])
    return values


class SqlIntentRepository:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def add(self, intent: Intent) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(insert(intents).values(**_intent_values(intent)))

    async def get(self, intent_id: str) -> Intent | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(select(intents).where(intents.c.intent_id == intent_id))
            ).first()
        return _intent(row) if row else None

    async def update(self, intent: Intent) -> None:
        values = _intent_values(intent)
        values.pop("intent_id")
        async with self._engine.begin() as conn:
            result = await conn.execute(
                update(intents).where(intents.c.intent_id == intent.intent_id).values(**values)
            )
            if result.rowcount == 0:
                raise NotFoundError(f"intent {intent.intent_id} not found")

    async def consume(self, intent_id: str, *, now: datetime) -> Intent | None:
        async with self._engine.begin() as conn:
            result = await conn.execute(
                update(intents)
                .where(
                    intents.c.intent_id == intent_id,
                    intents.c.status == IntentStatus.ACTIVE.value,
                    intents.c.uses < intents.c.max_uses,
                    intents.c.expires_at > utc(now),
                )
                .values(
                    uses=intents.c.uses + 1,
                    status=case(
                        (intents.c.uses + 1 >= intents.c.max_uses, IntentStatus.CONSUMED.value),
                        else_=IntentStatus.ACTIVE.value,
                    ),
                )
            )
            if result.rowcount != 1:
                return None
            row = (
                await conn.execute(select(intents).where(intents.c.intent_id == intent_id))
            ).first()
        return _intent(row) if row else None

    async def expire(self, now: datetime) -> int:
        async with self._engine.begin() as conn:
            result = await conn.execute(
                update(intents)
                .where(
                    intents.c.status == IntentStatus.ACTIVE.value,
                    intents.c.expires_at <= utc(now),
                )
                .values(status=IntentStatus.EXPIRED.value, status_reason="expired")
            )
        return int(result.rowcount or 0)


# ------------------------------------------------------------------- policies


def _policy(row: Row[Any]) -> PolicyVersion:
    m = row._mapping
    return PolicyVersion(
        version_id=m["version_id"],
        name=m["name"],
        version=m["version"],
        digest=m["digest"],
        status=PolicyStatus(m["status"]),
        document=json.loads(m["document"]),
        tests=json.loads(m["tests"]),
        test_summary=json.loads(m["test_summary"]),
        author=m["author"],
        created_at=utc(m["created_at"]),
        activated_by=m["activated_by"],
        activated_at=_opt_utc(m["activated_at"]),
    )


class SqlPolicyRepository:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def add(self, version: PolicyVersion) -> None:
        async with self._engine.begin() as conn:
            exists = (
                await conn.execute(
                    select(policy_versions.c.version_id).where(
                        policy_versions.c.digest == version.digest
                    )
                )
            ).first()
            if exists:
                raise ConflictError(f"policy with digest {version.digest} already exists")
            await conn.execute(
                insert(policy_versions).values(
                    version_id=version.version_id,
                    name=version.name,
                    version=version.version,
                    digest=version.digest,
                    status=version.status.value,
                    document=json.dumps(version.document, sort_keys=True),
                    tests=json.dumps(version.tests, sort_keys=True),
                    test_summary=json.dumps(version.test_summary, sort_keys=True),
                    author=version.author,
                    created_at=utc(version.created_at),
                    activated_by=version.activated_by,
                    activated_at=_opt_utc(version.activated_at),
                )
            )

    async def get(self, version_id: str) -> PolicyVersion | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    select(policy_versions).where(policy_versions.c.version_id == version_id)
                )
            ).first()
        return _policy(row) if row else None

    async def by_digest(self, digest: str) -> PolicyVersion | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    select(policy_versions).where(policy_versions.c.digest == digest)
                )
            ).first()
        return _policy(row) if row else None

    async def active(self) -> PolicyVersion | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    select(policy_versions).where(
                        policy_versions.c.status == PolicyStatus.ACTIVE.value
                    )
                )
            ).first()
        return _policy(row) if row else None

    async def activate(self, version_id: str, *, actor: str, at: datetime) -> PolicyVersion:
        async with self._engine.begin() as conn:
            target = (
                await conn.execute(
                    select(policy_versions.c.version_id).where(
                        policy_versions.c.version_id == version_id
                    )
                )
            ).first()
            if target is None:
                raise NotFoundError(f"policy version {version_id} not found")
            await conn.execute(
                update(policy_versions)
                .where(policy_versions.c.status == PolicyStatus.ACTIVE.value)
                .values(status=PolicyStatus.SUPERSEDED.value)
            )
            await conn.execute(
                update(policy_versions)
                .where(policy_versions.c.version_id == version_id)
                .values(status=PolicyStatus.ACTIVE.value, activated_by=actor, activated_at=utc(at))
            )
            row = (
                await conn.execute(
                    select(policy_versions).where(policy_versions.c.version_id == version_id)
                )
            ).one()
        return _policy(row)

    async def list(self, *, limit: int, offset: int) -> Sequence[PolicyVersion]:
        async with self._engine.connect() as conn:
            rows = (
                await conn.execute(
                    select(policy_versions)
                    .order_by(policy_versions.c.created_at.desc(), policy_versions.c.version_id)
                    .limit(limit)
                    .offset(offset)
                )
            ).all()
        return [_policy(r) for r in rows]


# --------------------------------------------------------------- decision log


def _decision(row: Row[Any]) -> DecisionRecord:
    m = dict(row._mapping)
    m["timestamp"] = utc(m["timestamp"])
    m["decision"] = Decision(m["decision"])
    m["matched_rules"] = tuple(json.loads(m["matched_rules"]))
    m["attribute_sources"] = json.loads(m["attribute_sources"])
    m["classification"] = DataClassification(m["classification"])
    return DecisionRecord.model_validate(m)


class SqlDecisionLog:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def append(self, record: DecisionRecord) -> None:
        values = record.model_dump()
        values.update(
            timestamp=utc(record.timestamp),
            decision=record.decision.value,
            matched_rules=json.dumps(list(record.matched_rules)),
            attribute_sources=json.dumps(record.attribute_sources, sort_keys=True),
            classification=int(record.classification),
        )
        async with self._engine.begin() as conn:
            await conn.execute(insert(decision_log).values(**values))

    async def query(
        self,
        *,
        subject_id: str | None,
        action: str | None,
        decision: Decision | None,
        since: datetime | None,
        limit: int,
        offset: int,
    ) -> Sequence[DecisionRecord]:
        statement = select(decision_log)
        if subject_id is not None:
            statement = statement.where(decision_log.c.subject_id == subject_id)
        if action is not None:
            statement = statement.where(decision_log.c.action == action)
        if decision is not None:
            statement = statement.where(decision_log.c.decision == decision.value)
        if since is not None:
            statement = statement.where(decision_log.c.timestamp >= utc(since))
        statement = (
            statement.order_by(decision_log.c.timestamp.desc(), decision_log.c.decision_id)
            .limit(limit)
            .offset(offset)
        )
        async with self._engine.connect() as conn:
            rows = (await conn.execute(statement)).all()
        return [_decision(r) for r in rows]

    async def purge_before(self, cutoff: datetime) -> int:
        async with self._engine.begin() as conn:
            result = await conn.execute(
                delete(decision_log).where(decision_log.c.timestamp < utc(cutoff))
            )
        return int(result.rowcount or 0)


# -------------------------------------------------------------- action blocks


class SqlActionBlockRepository:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def add(self, block: ActionBlock) -> None:
        async with self._engine.begin() as conn:
            exists = (
                await conn.execute(
                    select(action_blocks.c.block_id).where(action_blocks.c.pattern == block.pattern)
                )
            ).first()
            if exists:
                raise ConflictError(f"action pattern {block.pattern} is already blocked")
            values = block.model_dump()
            values["created_at"] = utc(block.created_at)
            await conn.execute(insert(action_blocks).values(**values))

    async def remove(self, block_id: str) -> ActionBlock | None:
        async with self._engine.begin() as conn:
            row = (
                await conn.execute(
                    select(action_blocks).where(action_blocks.c.block_id == block_id)
                )
            ).first()
            if row is None:
                return None
            await conn.execute(delete(action_blocks).where(action_blocks.c.block_id == block_id))
        return self._block(row)

    async def list(self) -> Sequence[ActionBlock]:
        async with self._engine.connect() as conn:
            rows = (
                await conn.execute(select(action_blocks).order_by(action_blocks.c.created_at))
            ).all()
        return [self._block(r) for r in rows]

    @staticmethod
    def _block(row: Row[Any]) -> ActionBlock:
        m = dict(row._mapping)
        m["created_at"] = utc(m["created_at"])
        return ActionBlock.model_validate(m)


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)
