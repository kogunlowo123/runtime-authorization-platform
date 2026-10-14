"""Request and response bodies for the HTTP API that are not application commands."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from agentic_core.domain.classification import RiskLevel
from pydantic import BaseModel, ConfigDict, Field

from runtime_authorization_platform.application.decisions import DecisionInput, FilterInput
from runtime_authorization_platform.domain.models import (
    ActionBlock,
    ActionControl,
    DecisionRecord,
    Intent,
    IntentStatus,
    PolicyStatus,
    PolicyVersion,
)

SUBJECT_HELP = (
    "The acting agent's or user's bearer token as presented to the enforcement point. "
    "When omitted, the caller is the subject and the request is evaluated as a dry run."
)


class DecisionRequest(DecisionInput):
    subject_token: str | None = Field(
        default=None, min_length=20, max_length=16_384, description=SUBJECT_HELP
    )

    def command(self) -> DecisionInput:
        return DecisionInput.model_validate(self.model_dump(exclude={"subject_token"}))


class FilterRequest(FilterInput):
    subject_token: str | None = Field(
        default=None, min_length=20, max_length=16_384, description=SUBJECT_HELP
    )

    def command(self) -> FilterInput:
        return FilterInput.model_validate(self.model_dump(exclude={"subject_token"}))


class IntentView(BaseModel):
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
    uses: int
    max_uses: int
    created_at: datetime
    expires_at: datetime
    approved: bool
    approved_by: str | None
    approved_at: datetime | None
    status_reason: str | None

    @classmethod
    def of(cls, intent: Intent) -> IntentView:
        return cls(**intent.model_dump(exclude={"injection_score"}), approved=intent.approved)


class RevokeIntent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=5, max_length=500)


class PolicyVersionSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    version_id: str
    name: str
    version: str
    digest: str
    status: PolicyStatus
    author: str
    created_at: datetime
    activated_by: str | None
    activated_at: datetime | None
    test_summary: dict[str, Any]

    @classmethod
    def of(cls, version: PolicyVersion) -> PolicyVersionSummary:
        return cls.model_validate(version.model_dump(exclude={"document", "tests"}))


class PolicyVersionView(PolicyVersionSummary):
    document: dict[str, Any]
    tests: list[dict[str, Any]]

    @classmethod
    def full(cls, version: PolicyVersion) -> PolicyVersionView:
        return cls.model_validate(version.model_dump())


class PolicyVersionList(BaseModel):
    items: list[PolicyVersionSummary]
    limit: int
    offset: int


class ActionCatalogView(BaseModel):
    version: str
    digest: str
    actions: list[ActionControl]
    blocks: list[ActionBlock]


class BlockAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pattern: str = Field(min_length=1, max_length=200, description="Action glob to stop")
    reason: str = Field(min_length=5, max_length=500)


class DecisionLogPage(BaseModel):
    items: list[DecisionRecord]
    limit: int
    offset: int


class OAuthError(BaseModel):
    error: str
    error_description: str
