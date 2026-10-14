"""Domain model: principals, action controls, intents, policy versions and decisions.

Flow: Intent -> Policy -> Resource -> Authorization -> Decision.
"""

from __future__ import annotations

import fnmatch
import re
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml
from agentic_core.domain.classification import DataClassification, Decision, RiskLevel
from pydantic import BaseModel, ConfigDict, Field, field_validator

_ACTION = re.compile(r"^[a-z0-9][a-z0-9_.\-]*(:[a-z0-9_.\-*]+){1,3}$")
_ACTION_PATTERN = re.compile(r"^[a-z0-9*][a-z0-9_.\-*]*(:[a-z0-9_.\-*]+){0,3}$")


def validate_action(value: str) -> str:
    """Concrete actions look like ``resource:verb[:qualifier]`` without wildcards."""
    if "*" in value or not _ACTION.fullmatch(value):
        raise ValueError(f"invalid action {value!r}; expected resource:verb[:qualifier]")
    return value


class PrincipalKind(StrEnum):
    AGENT = "agent"
    USER = "user"
    SERVICE = "service"


class Principal(BaseModel):
    """An authenticated caller or decision subject."""

    model_config = ConfigDict(frozen=True)

    id: str
    kind: PrincipalKind
    issuer: str
    tenant: str | None = None
    app_id: str | None = None
    roles: frozenset[str] = frozenset()
    scopes: frozenset[str] = frozenset()
    delegation_chain: tuple[str, ...] = ()
    token_id: str | None = None
    expires_at: datetime

    @property
    def delegated(self) -> bool:
        return bool(self.delegation_chain)

    def holds_scope_for(self, action: str) -> bool:
        return any(fnmatch.fnmatchcase(action, scope) for scope in self.scopes)


# ----------------------------------------------------------------- action controls


class IntentRequirement(StrEnum):
    NONE = "none"  # intents are not accepted for this action
    OPTIONAL = "optional"  # an intent may be supplied; policy may require approval of it
    REQUIRED = "required"  # no decision is reached without a valid declared intent


class ActionControl(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    pattern: str = Field(description="Action glob, e.g. payments:execute or tickets:*")
    risk: RiskLevel
    intent: IntentRequirement = IntentRequirement.OPTIONAL
    max_intent_uses: int = Field(default=1, ge=1, le=1000)
    description: str = Field(min_length=3, max_length=500)

    @field_validator("pattern")
    @classmethod
    def _pattern(cls, value: str) -> str:
        if not _ACTION_PATTERN.fullmatch(value):
            raise ValueError(f"invalid action pattern {value!r}")
        return value

    def matches(self, action: str) -> bool:
        return fnmatch.fnmatchcase(action, self.pattern)


class ActionCatalog(BaseModel):
    """Registered actions. Unregistered actions are denied before policy evaluation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    version: str
    actions: tuple[ActionControl, ...] = Field(min_length=1)

    @field_validator("actions")
    @classmethod
    def _unique(cls, actions: tuple[ActionControl, ...]) -> tuple[ActionControl, ...]:
        patterns = [a.pattern for a in actions]
        duplicates = sorted({p for p in patterns if patterns.count(p) > 1})
        if duplicates:
            raise ValueError(f"duplicate action patterns: {duplicates}")
        return actions

    def lookup(self, action: str) -> ActionControl | None:
        """First match wins; list specific patterns before wildcards."""
        return next((a for a in self.actions if a.matches(action)), None)

    @classmethod
    def from_file(cls, path: Path) -> ActionCatalog:
        return cls.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))


class ActionBlock(BaseModel):
    """Emergency stop for an action pattern, set by a security officer."""

    model_config = ConfigDict(frozen=True)

    block_id: str
    pattern: str
    reason: str
    created_by: str
    created_at: datetime

    def matches(self, action: str) -> bool:
        return fnmatch.fnmatchcase(action, self.pattern)


# -------------------------------------------------------------------------- intents


class IntentStatus(StrEnum):
    ACTIVE = "active"
    CONSUMED = "consumed"
    REVOKED = "revoked"
    EXPIRED = "expired"


class Intent(BaseModel):
    """An agent's declaration of what it is about to do and why, made before acting."""

    model_config = ConfigDict(frozen=True)

    intent_id: str
    principal_id: str
    action: str
    resource_type: str
    resource_id: str
    justification: str
    purpose: str
    risk: RiskLevel
    status: IntentStatus
    max_uses: int
    uses: int = 0
    created_at: datetime
    expires_at: datetime
    approved_by: str | None = None
    approved_at: datetime | None = None
    status_reason: str | None = None
    injection_score: float = 0.0

    @property
    def approved(self) -> bool:
        return self.approved_by is not None

    def effective_status(self, now: datetime) -> IntentStatus:
        if self.status is IntentStatus.ACTIVE and now >= self.expires_at:
            return IntentStatus.EXPIRED
        return self.status

    def covers(self, action: str, resource_type: str, resource_id: str) -> bool:
        return (
            self.action == action
            and self.resource_type == resource_type
            and self.resource_id in {"*", resource_id}
        )

    def facts(self) -> dict[str, Any]:
        return {
            "declared": True,
            "approved": self.approved,
            "id": self.intent_id,
            "purpose": self.purpose,
            "uses": self.uses,
            "max_uses": self.max_uses,
        }


NO_INTENT_FACTS: dict[str, Any] = {"declared": False, "approved": False}


# ------------------------------------------------------------------ policy versions


class PolicyStatus(StrEnum):
    DRAFT = "draft"
    ACTIVE = "active"
    SUPERSEDED = "superseded"


class PolicyVersion(BaseModel):
    model_config = ConfigDict(frozen=True)

    version_id: str
    name: str
    version: str
    digest: str
    status: PolicyStatus
    document: dict[str, Any]
    tests: list[dict[str, Any]]
    test_summary: dict[str, Any]
    author: str
    created_at: datetime
    activated_by: str | None = None
    activated_at: datetime | None = None


# ------------------------------------------------------------------------ decisions


class DecisionRecord(BaseModel):
    """One decision-log entry. Every decision is persisted and audited."""

    model_config = ConfigDict(frozen=True)

    decision_id: str
    timestamp: datetime
    caller_id: str
    subject_id: str
    action: str
    resource_type: str
    resource_id: str
    decision: Decision
    reason: str
    stage: str = Field(description="control (pre-policy action controls) or policy")
    matched_rules: tuple[str, ...]
    policy_name: str
    policy_version: str
    policy_digest: str
    engine: str
    intent_id: str | None
    dry_run: bool
    latency_ms: float
    correlation_id: str | None
    attribute_sources: dict[str, str]
    classification: DataClassification
