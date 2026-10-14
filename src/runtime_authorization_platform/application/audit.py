"""Fail-closed wrapper around the agentic-core signed audit chain."""

from __future__ import annotations

from typing import Any

from agentic_core.audit import AuditLog
from agentic_core.observability import correlation_id, get_logger

from runtime_authorization_platform.domain.errors import DependencyUnavailableError

log = get_logger("runtime_authorization_platform.audit")


class Auditor:
    """Records every decision and state change. If evidence cannot be written,
    the operation fails instead of completing without a record."""

    def __init__(self, audit: AuditLog) -> None:
        self._audit = audit

    async def record(
        self, *, actor: str, action: str, resource: str, outcome: str, details: dict[str, Any]
    ) -> None:
        try:
            await self._audit.record(
                actor=actor,
                action=action,
                resource=resource,
                outcome=outcome,
                correlation_id=correlation_id(),
                details=details,
            )
        except Exception as exc:
            log.error("audit_write_failed", action=action, error=type(exc).__name__)
            raise DependencyUnavailableError("audit trail unavailable") from exc
