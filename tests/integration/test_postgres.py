"""Repository and decision behaviour against a real PostgreSQL (CI service container).

Runs when AUTHZ_TEST_DATABASE_URL points at PostgreSQL, e.g.
postgresql+asyncpg://authz:authz@localhost:5432/authz
"""

from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime, timedelta

import pytest
from agentic_core.domain.identifiers import new_id

from runtime_authorization_platform.infrastructure.database import (
    SqlDecisionLog,
    SqlIntentRepository,
    SqlPolicyRepository,
    create_schema,
    make_engine,
)
from tests.unit.test_persistence import make_intent, make_record, make_version

URL = os.environ.get("AUTHZ_TEST_DATABASE_URL", "")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not URL.startswith("postgresql"), reason="PostgreSQL not configured"),
]


async def test_concurrent_intent_consumption_is_atomic() -> None:
    """Twenty decisions racing for a three-use intent consume exactly three uses."""
    engine = make_engine(URL)
    await create_schema(engine)
    await create_schema(engine)
    repo = SqlIntentRepository(engine)
    intent_id = new_id()
    now = datetime.now(UTC)
    await repo.add(
        make_intent(intent_id, max_uses=3, created_at=now, expires_at=now + timedelta(minutes=5))
    )
    results = await asyncio.gather(*(repo.consume(intent_id, now=now) for _ in range(20)))
    assert sum(r is not None for r in results) == 3
    stored = await repo.get(intent_id)
    assert stored is not None
    assert stored.uses == 3
    assert stored.status.value == "consumed"
    await engine.dispose()


async def test_single_active_policy_and_decision_log() -> None:
    engine = make_engine(URL)
    await create_schema(engine)
    policies = SqlPolicyRepository(engine)
    first, second = new_id(), new_id()
    now = datetime.now(UTC)
    await policies.add(make_version(first, f"sha256:{first}", created_at=now))
    await policies.add(make_version(second, f"sha256:{second}", created_at=now))
    await policies.activate(first, actor="bob", at=now)
    await policies.activate(second, actor="bob", at=now)
    active = await policies.active()
    assert active is not None
    assert active.version_id == second

    log = SqlDecisionLog(engine)
    record_id = new_id()
    await log.append(make_record(record_id, at=now))
    found = await log.query(
        subject_id="agent",
        action=None,
        decision=None,
        since=now - timedelta(seconds=1),
        limit=500,
        offset=0,
    )
    assert record_id in {r.decision_id for r in found}
    await engine.dispose()
