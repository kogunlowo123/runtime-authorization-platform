"""Intent declaration: an agent states what it is about to do, to what, and why, before acting.

The justification is untrusted text written by (or through) a model, so it is
screened with the agentic-core prompt-injection detector and secret scanner
and stored with PII redacted. High-risk intents are approved by a human who is
not the declaring principal (four-eyes).
"""

from __future__ import annotations

import re
from datetime import timedelta
from typing import NoReturn

from agentic_core.domain.identifiers import new_id
from agentic_core.security import PiiDetector, PromptInjectionDetector, SecretScanner
from pydantic import BaseModel, ConfigDict, Field, field_validator

from runtime_authorization_platform.application.audit import Auditor
from runtime_authorization_platform.application.controls import ActionControls
from runtime_authorization_platform.domain.errors import (
    ForbiddenError,
    IntentRejectedError,
    InvalidStateError,
    NotFoundError,
)
from runtime_authorization_platform.domain.models import (
    Intent,
    IntentRequirement,
    IntentStatus,
    Principal,
    validate_action,
)
from runtime_authorization_platform.domain.ports import Clock, IntentRepository
from runtime_authorization_platform.observability.metrics import AuthzMetrics

RESOURCE_TYPE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-/]{0,199}$")


def validate_resource_type(value: str) -> str:
    if not RESOURCE_TYPE.fullmatch(value):
        raise ValueError(f"invalid resource type {value!r}")
    return value


class DeclareIntent(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    action: str = Field(max_length=200, description="Concrete action, e.g. payments:execute")
    resource_type: str = Field(max_length=200)
    resource_id: str = Field(
        min_length=1, max_length=500, description="Target resource id, or * for any of the type"
    )
    justification: str = Field(min_length=20, max_length=2000)
    purpose: str = Field(min_length=3, max_length=200, description="Purpose of use")
    ttl_seconds: int | None = Field(default=None, ge=30, le=86_400)
    max_uses: int | None = Field(default=None, ge=1, le=1000)

    _action = field_validator("action")(validate_action)
    _type = field_validator("resource_type")(validate_resource_type)


class IntentService:
    def __init__(
        self,
        *,
        repository: IntentRepository,
        controls: ActionControls,
        auditor: Auditor,
        clock: Clock,
        metrics: AuthzMetrics,
        injection_threshold: float = 0.5,
        default_ttl: timedelta = timedelta(minutes=15),
        max_ttl: timedelta = timedelta(hours=8),
        detector: PromptInjectionDetector | None = None,
        secrets: SecretScanner | None = None,
        pii: PiiDetector | None = None,
    ) -> None:
        self._repo = repository
        self._controls = controls
        self._auditor = auditor
        self._clock = clock
        self._metrics = metrics
        self._threshold = injection_threshold
        self._default_ttl = default_ttl
        self._max_ttl = max_ttl
        self._detector = detector or PromptInjectionDetector()
        self._secrets = secrets or SecretScanner()
        self._pii = pii or PiiDetector()

    async def _reject(self, principal: Principal, command: DeclareIntent, reason: str) -> NoReturn:
        self._metrics.intents.labels("rejected").inc()
        await self._auditor.record(
            actor=principal.id,
            action="intent.declare",
            resource=f"{command.resource_type}:{command.resource_id}",
            outcome="rejected",
            details={"intent_action": command.action, "reason": reason},
        )
        raise IntentRejectedError(reason)

    async def declare(self, command: DeclareIntent, principal: Principal) -> Intent:
        control = self._controls.lookup(command.action)
        if control is None:
            await self._reject(principal, command, "action is not registered")
        if control.intent is IntentRequirement.NONE:
            await self._reject(principal, command, "this action does not take intents")
        if await self._controls.blocked(command.action):
            await self._reject(principal, command, "action is blocked")
        max_uses = command.max_uses or control.max_intent_uses
        if max_uses > control.max_intent_uses:
            await self._reject(
                principal, command, f"max_uses exceeds the limit of {control.max_intent_uses}"
            )
        text = f"{command.justification}\n{command.purpose}"
        if self._secrets.detect(text):
            await self._reject(principal, command, "justification contains credential material")
        assessment = self._detector.assess(text)
        if assessment.score >= self._threshold:
            await self._reject(
                principal,
                command,
                f"justification failed injection screening ({', '.join(assessment.kinds)})",
            )
        justification, _ = self._pii.redact(command.justification)
        purpose, _ = self._pii.redact(command.purpose)
        ttl = min(
            timedelta(seconds=command.ttl_seconds) if command.ttl_seconds else self._default_ttl,
            self._max_ttl,
        )
        now = self._clock.now()
        intent = Intent(
            intent_id=new_id(),
            principal_id=principal.id,
            action=command.action,
            resource_type=command.resource_type,
            resource_id=command.resource_id,
            justification=justification,
            purpose=purpose,
            risk=control.risk,
            status=IntentStatus.ACTIVE,
            max_uses=max_uses,
            created_at=now,
            expires_at=now + ttl,
            injection_score=assessment.score,
        )
        await self._repo.add(intent)
        self._metrics.intents.labels("declared").inc()
        await self._auditor.record(
            actor=principal.id,
            action="intent.declare",
            resource=f"{intent.resource_type}:{intent.resource_id}",
            outcome="success",
            details={
                "intent_id": intent.intent_id,
                "intent_action": intent.action,
                "risk": int(intent.risk),
                "expires_at": intent.expires_at.isoformat(),
                "injection_score": assessment.score,
            },
        )
        return intent

    async def get(self, intent_id: str) -> Intent:
        intent = await self._repo.get(intent_id)
        if intent is None:
            raise NotFoundError(f"intent {intent_id} not found")
        return self._current(intent)

    def _current(self, intent: Intent) -> Intent:
        status = intent.effective_status(self._clock.now())
        return intent if status is intent.status else intent.model_copy(update={"status": status})

    async def approve(self, intent_id: str, *, approver: Principal) -> Intent:
        intent = await self.get(intent_id)
        if intent.status is not IntentStatus.ACTIVE:
            raise InvalidStateError(f"intent is {intent.status.value}")
        if intent.approved:
            raise InvalidStateError("intent is already approved")
        if approver.id == intent.principal_id:
            raise ForbiddenError("an intent cannot be approved by the principal that declared it")
        updated = intent.model_copy(
            update={"approved_by": approver.id, "approved_at": self._clock.now()}
        )
        await self._repo.update(updated)
        self._metrics.intents.labels("approved").inc()
        await self._auditor.record(
            actor=approver.id,
            action="intent.approve",
            resource=f"{intent.resource_type}:{intent.resource_id}",
            outcome="success",
            details={"intent_id": intent_id, "declared_by": intent.principal_id},
        )
        return updated

    async def revoke(
        self, intent_id: str, *, actor: Principal, reason: str, privileged: bool
    ) -> Intent:
        intent = await self.get(intent_id)
        if not privileged and actor.id != intent.principal_id:
            raise ForbiddenError("only the declaring principal or a security officer may revoke")
        if intent.status is not IntentStatus.ACTIVE:
            raise InvalidStateError(f"intent is {intent.status.value}")
        updated = intent.model_copy(
            update={"status": IntentStatus.REVOKED, "status_reason": reason}
        )
        await self._repo.update(updated)
        self._metrics.intents.labels("revoked").inc()
        await self._auditor.record(
            actor=actor.id,
            action="intent.revoke",
            resource=f"{intent.resource_type}:{intent.resource_id}",
            outcome="success",
            details={"intent_id": intent_id, "reason": reason},
        )
        return updated

    async def for_decision(  # noqa: PLR0911 - one return per rejection reason
        self,
        intent_id: str,
        *,
        subject: Principal,
        action: str,
        resource_type: str,
        resource_id: str | None,
    ) -> tuple[Intent | None, str | None]:
        """Return the usable intent, or a denial reason. ``resource_id`` None skips the id check."""
        intent = await self._repo.get(intent_id)
        if intent is None:
            return None, "intent not found"
        intent = self._current(intent)
        if intent.principal_id != subject.id:
            return None, "intent belongs to another principal"
        if intent.status is not IntentStatus.ACTIVE:
            return None, f"intent is {intent.status.value}"
        if intent.uses >= intent.max_uses:
            return None, "intent has no remaining uses"
        if intent.action != action or intent.resource_type != resource_type:
            return None, "request does not match the declared intent"
        if resource_id is not None and not intent.covers(action, resource_type, resource_id):
            return None, "request does not match the declared intent"
        return intent, None

    async def consume(self, intent: Intent) -> Intent | None:
        consumed = await self._repo.consume(intent.intent_id, now=self._clock.now())
        if consumed is not None:
            self._metrics.intents.labels("used").inc()
        return consumed

    async def expire(self) -> int:
        return await self._repo.expire(self._clock.now())
