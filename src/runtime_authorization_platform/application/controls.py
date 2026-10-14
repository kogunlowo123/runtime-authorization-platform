"""Action-level controls: the registered action catalog and emergency action blocks.

These run before policy and are enforced in code, so a policy edit can never
re-enable an unregistered or blocked action.
"""

from __future__ import annotations

import fnmatch
import time
from collections.abc import Callable, Sequence

from agentic_core.domain.identifiers import new_id
from agentic_core.domain.provenance import canonical_json, content_digest

from runtime_authorization_platform.application.audit import Auditor
from runtime_authorization_platform.domain.errors import InvalidStateError, NotFoundError
from runtime_authorization_platform.domain.models import ActionBlock, ActionCatalog, ActionControl
from runtime_authorization_platform.domain.ports import ActionBlockRepository, Clock


class ActionControls:
    def __init__(
        self,
        *,
        catalog: ActionCatalog,
        blocks: ActionBlockRepository,
        auditor: Auditor,
        clock: Clock,
        refresh_s: float = 2.0,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._catalog = catalog
        self._digest = content_digest(canonical_json(catalog.model_dump(mode="json")))
        self._blocks = blocks
        self._auditor = auditor
        self._clock = clock
        self._refresh_s = refresh_s
        self._monotonic = monotonic
        self._cached: Sequence[ActionBlock] = ()
        self._loaded_at: float | None = None

    @property
    def catalog(self) -> ActionCatalog:
        return self._catalog

    @property
    def catalog_digest(self) -> str:
        return self._digest

    def lookup(self, action: str) -> ActionControl | None:
        return self._catalog.lookup(action)

    async def blocks(self) -> Sequence[ActionBlock]:
        """Active blocks; re-read at most every ``refresh_s`` so all replicas converge fast."""
        now = self._monotonic()
        if self._loaded_at is None or now - self._loaded_at >= self._refresh_s:
            self._cached = await self._blocks.list()
            self._loaded_at = now
        return self._cached

    async def blocked(self, action: str) -> ActionBlock | None:
        return next((b for b in await self.blocks() if b.matches(action)), None)

    async def block(self, pattern: str, *, reason: str, actor: str) -> ActionBlock:
        if not any(
            fnmatch.fnmatchcase(c.pattern, pattern) or c.matches(pattern)
            for c in self._catalog.actions
        ):
            raise InvalidStateError(f"pattern {pattern!r} matches no registered action")
        block = ActionBlock(
            block_id=new_id(),
            pattern=pattern,
            reason=reason,
            created_by=actor,
            created_at=self._clock.now(),
        )
        await self._blocks.add(block)
        self._loaded_at = None
        await self._auditor.record(
            actor=actor,
            action="action.block",
            resource=pattern,
            outcome="success",
            details={"block_id": block.block_id, "reason": reason},
        )
        return block

    async def unblock(self, block_id: str, *, actor: str) -> ActionBlock:
        removed = await self._blocks.remove(block_id)
        if removed is None:
            raise NotFoundError(f"action block {block_id} not found")
        self._loaded_at = None
        await self._auditor.record(
            actor=actor,
            action="action.unblock",
            resource=removed.pattern,
            outcome="success",
            details={"block_id": block_id},
        )
        return removed
