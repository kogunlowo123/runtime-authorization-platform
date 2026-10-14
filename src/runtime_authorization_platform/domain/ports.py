"""Ports the application layer depends on. Adapters live in infrastructure and integrations."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any, Protocol

from agentic_core.domain.classification import Decision

from runtime_authorization_platform.domain.models import (
    ActionBlock,
    DecisionRecord,
    Intent,
    PolicyVersion,
)


class Clock(Protocol):
    def now(self) -> datetime: ...


class IntentRepository(Protocol):
    async def add(self, intent: Intent) -> None: ...

    async def get(self, intent_id: str) -> Intent | None: ...

    async def update(self, intent: Intent) -> None: ...

    async def consume(self, intent_id: str, *, now: datetime) -> Intent | None:
        """Atomically take one use; None when no use remains or the intent is not active."""
        ...

    async def expire(self, now: datetime) -> int: ...


class PolicyRepository(Protocol):
    async def add(self, version: PolicyVersion) -> None: ...

    async def get(self, version_id: str) -> PolicyVersion | None: ...

    async def by_digest(self, digest: str) -> PolicyVersion | None: ...

    async def active(self) -> PolicyVersion | None: ...

    async def activate(self, version_id: str, *, actor: str, at: datetime) -> PolicyVersion: ...

    async def list(self, *, limit: int, offset: int) -> Sequence[PolicyVersion]: ...


class DecisionLog(Protocol):
    async def append(self, record: DecisionRecord) -> None: ...

    async def query(
        self,
        *,
        subject_id: str | None,
        action: str | None,
        decision: Decision | None,
        since: datetime | None,
        limit: int,
        offset: int,
    ) -> Sequence[DecisionRecord]: ...

    async def purge_before(self, cutoff: datetime) -> int: ...


class ActionBlockRepository(Protocol):
    async def add(self, block: ActionBlock) -> None: ...

    async def remove(self, block_id: str) -> ActionBlock | None: ...

    async def list(self) -> Sequence[ActionBlock]: ...


class AttributeSource(Protocol):
    """A policy information point (PIP): authoritative attributes for an entity.

    Returns None when the entity does not exist; raises PipUnavailableError when
    the source cannot answer.
    """

    name: str

    async def fetch(self, entity_type: str, entity_id: str) -> dict[str, Any] | None: ...
