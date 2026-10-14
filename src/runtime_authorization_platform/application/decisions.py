"""Decision point: Intent -> Policy -> Resource -> Authorization -> Decision.

Order of evaluation for one request:

1. action controls (code-enforced): the action must be registered and not
   blocked;
2. attributes: resource attributes from the policy information point for the
   resource type when one is configured (caller-supplied attributes are then
   ignored), subject attributes from the token plus the ``principal`` PIP;
3. intent: a referenced intent must belong to the subject, be active, have
   uses left and match the action and resource; actions whose catalog entry
   says ``intent: required`` are denied without one;
4. classification ceiling: a resource above the subject's clearance is denied
   regardless of policy;
5. policy: the configured engine (local agentic-core, OPA, combined, shadow);
6. intent consumption on ALLOW (atomic; a lost race turns into DENY).

Every outcome, including denials at steps 1-4 and dependency failures (which
fail closed), is written to the decision log and the signed audit chain.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from agentic_core.domain.classification import DataClassification, Decision, RiskLevel
from agentic_core.domain.identifiers import new_id
from agentic_core.observability import correlation_id
from agentic_core.policy import Condition, Operator, PolicyRequest, Resource, Subject
from pydantic import BaseModel, ConfigDict, Field, field_validator

from runtime_authorization_platform.application.audit import Auditor
from runtime_authorization_platform.application.controls import ActionControls
from runtime_authorization_platform.application.intents import (
    IntentService,
    validate_resource_type,
)
from runtime_authorization_platform.application.policies import PolicyAdministration
from runtime_authorization_platform.domain.errors import DependencyUnavailableError
from runtime_authorization_platform.domain.models import (
    NO_INTENT_FACTS,
    ActionControl,
    DecisionRecord,
    Intent,
    IntentRequirement,
    Principal,
    validate_action,
)
from runtime_authorization_platform.domain.ports import Clock, DecisionLog
from runtime_authorization_platform.integrations.pip import AttributeResolver, CacheOutcome
from runtime_authorization_platform.observability.metrics import AuthzMetrics
from runtime_authorization_platform.policy.engines import DecisionEngine
from runtime_authorization_platform.policy.partial import (
    FALSE,
    TRUE,
    Cond,
    Expr,
    allow_residual,
    conj,
    evaluate,
    to_dict,
)

RESERVED_ENVIRONMENT = frozenset({"intent", "time"})
RESERVED_RESOURCE_ATTRIBUTES = frozenset({"type", "id", "classification"})
RESERVED_SUBJECT_ATTRIBUTES = frozenset({"id", "kind", "roles"})
PRINCIPAL_ENTITY = "principal"
MAX_ENVIRONMENT_KEYS = 50


def parse_classification(value: Any) -> DataClassification | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and 0 <= value <= 3:
        return DataClassification(value)
    if isinstance(value, str) and value.strip().upper() in DataClassification.__members__:
        return DataClassification[value.strip().upper()]
    return None


def _check_environment(value: dict[str, Any]) -> dict[str, Any]:
    reserved = RESERVED_ENVIRONMENT.intersection(value)
    if reserved:
        raise ValueError(f"environment keys {sorted(reserved)} are set by the platform")
    if len(value) > MAX_ENVIRONMENT_KEYS:
        raise ValueError(f"at most {MAX_ENVIRONMENT_KEYS} environment keys")
    return value


class ResourceInput(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    type: str = Field(max_length=200)
    id: str = Field(min_length=1, max_length=500)
    classification: DataClassification | None = Field(
        default=None, description="Used only when no attribute source is configured for the type"
    )
    attributes: dict[str, Any] = Field(
        default_factory=dict,
        description="Used only when no attribute source is configured for the type",
    )

    _type = field_validator("type")(validate_resource_type)


class DecisionInput(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    action: str = Field(max_length=200)
    resource: ResourceInput
    environment: dict[str, Any] = Field(default_factory=dict)
    intent_id: str | None = Field(default=None, min_length=1, max_length=64)
    dry_run: bool = Field(default=False, description="Evaluate without consuming intent uses")

    _action = field_validator("action")(validate_action)
    _env = field_validator("environment")(_check_environment)


class PolicyRef(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    version: str
    digest: str


class IntentUse(BaseModel):
    model_config = ConfigDict(frozen=True)

    intent_id: str
    approved: bool
    uses: int
    max_uses: int


class DecisionResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    decision_id: str
    decision: Decision
    reason: str
    stage: str
    matched_rules: tuple[str, ...]
    policy: PolicyRef
    engine: str
    subject: str
    action: str
    resource: str
    intent: IntentUse | None
    obligations: tuple[str, ...]
    attribute_sources: dict[str, str]
    dry_run: bool
    evaluated_at: datetime


class CandidateInput(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(min_length=1, max_length=500)
    classification: DataClassification | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)


class FilterInput(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    action: str = Field(max_length=200)
    resource_type: str = Field(max_length=200)
    environment: dict[str, Any] = Field(default_factory=dict)
    intent_id: str | None = Field(default=None, min_length=1, max_length=64)
    candidates: tuple[CandidateInput, ...] | None = Field(default=None, max_length=1000)

    _action = field_validator("action")(validate_action)
    _type = field_validator("resource_type")(validate_resource_type)
    _env = field_validator("environment")(_check_environment)


class FilterResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    subject: str
    action: str
    resource_type: str
    residual: dict[str, Any] | None = Field(
        description="Condition over resource.* attributes that holds exactly for allowed "
        "resources; null when an external engine decides and only candidates can be checked"
    )
    always_allowed: bool
    never_allowed: bool
    reason: str
    allowed_ids: tuple[str, ...] | None
    denied_ids: tuple[str, ...] | None
    policy: PolicyRef | None
    engine: str


@dataclass
class _Outcome:
    decision: Decision
    reason: str
    stage: str
    matched_rules: tuple[str, ...] = ()
    policy: PolicyRef | None = None
    engine: str = "controls"
    intent: Intent | None = None
    control: ActionControl | None = None
    classification: DataClassification = DataClassification.INTERNAL
    sources: dict[str, str] = field(default_factory=dict)
    obligations: tuple[str, ...] = ()


class _ResourceMissingError(Exception):
    pass


class DecisionService:
    def __init__(
        self,
        *,
        controls: ActionControls,
        intents: IntentService,
        engine: DecisionEngine,
        policies: PolicyAdministration,
        resolver: AttributeResolver,
        decisions: DecisionLog,
        auditor: Auditor,
        clock: Clock,
        metrics: AuthzMetrics,
        default_clearance: DataClassification = DataClassification.INTERNAL,
        default_subject_risk: RiskLevel = RiskLevel.MODERATE,
        default_classification: DataClassification = DataClassification.INTERNAL,
        filter_concurrency: int = 16,
        perf_counter: Callable[[], float] = time.perf_counter,
    ) -> None:
        self._controls = controls
        self._intents = intents
        self._engine = engine
        self._policies = policies
        self._resolver = resolver
        self._log = decisions
        self._auditor = auditor
        self._clock = clock
        self._metrics = metrics
        self._default_clearance = default_clearance
        self._default_risk = default_subject_risk
        self._default_classification = default_classification
        self._concurrency = filter_concurrency
        self._perf = perf_counter

    @property
    def engine(self) -> DecisionEngine:
        return self._engine

    def _catalog_ref(self) -> PolicyRef:
        return PolicyRef(
            name="action-catalog",
            version=self._controls.catalog.version,
            digest=self._controls.catalog_digest,
        )

    def _local_ref(self) -> PolicyRef:
        policy = self._policies.holder.policy
        return PolicyRef(name=policy.name, version=policy.version, digest=policy.digest)

    # ------------------------------------------------------------- attributes

    async def _resource(self, resource: ResourceInput) -> tuple[Resource, str]:
        lookup = await self._resolver.resolve(resource.type, resource.id)
        if lookup is None:
            attributes = dict(resource.attributes)
            classification = resource.classification or self._default_classification
            source = "request"
        else:
            if lookup.attributes is None:
                raise _ResourceMissingError(
                    f"{resource.type}:{resource.id} not found in {lookup.source}"
                )
            attributes = dict(lookup.attributes)
            raw = attributes.get("classification")
            # Unparseable labels from the source are treated as the most restrictive.
            classification = (
                (parse_classification(raw) or DataClassification.RESTRICTED)
                if raw is not None
                else self._default_classification
            )
            source = f"pip:{lookup.source}" + (
                ":stale" if lookup.outcome is CacheOutcome.STALE else ""
            )
        for key in RESERVED_RESOURCE_ATTRIBUTES:
            attributes.pop(key, None)
        return (
            Resource(
                type=resource.type,
                id=resource.id,
                classification=classification,
                attributes=attributes,
            ),
            source,
        )

    async def _subject(
        self, principal: Principal, action: str
    ) -> tuple[Subject, DataClassification, str]:
        attributes: dict[str, Any] = {}
        source = "token"
        lookup = await self._resolver.resolve(PRINCIPAL_ENTITY, principal.id)
        if lookup is not None and lookup.attributes is not None:
            attributes.update(lookup.attributes)
            source = f"token+pip:{lookup.source}"
        for key in RESERVED_SUBJECT_ATTRIBUTES:
            attributes.pop(key, None)
        clearance = parse_classification(attributes.get("clearance")) or self._default_clearance
        risk = attributes.get("risk")
        attributes.update(
            {
                "clearance": int(clearance),
                "risk": (
                    risk if isinstance(risk, int) and 1 <= risk <= 4 else int(self._default_risk)
                ),
                "tenant": principal.tenant,
                "issuer": principal.issuer,
                "app_id": principal.app_id,
                "scopes": sorted(principal.scopes),
                "delegated": principal.delegated,
                "delegation_depth": len(principal.delegation_chain),
                "delegation_chain": list(principal.delegation_chain),
                "action_in_scope": principal.holds_scope_for(action),
            }
        )
        subject = Subject(
            id=principal.id, kind=principal.kind.value, roles=principal.roles, attributes=attributes
        )
        return subject, clearance, source

    def _environment(self, supplied: dict[str, Any], intent: Intent | None) -> dict[str, Any]:
        now = self._clock.now()
        return {
            **supplied,
            "intent": intent.facts() if intent else dict(NO_INTENT_FACTS),
            "time": {"hour": now.hour, "weekday": now.weekday(), "date": now.date().isoformat()},
        }

    # -------------------------------------------------------------- decisions

    def _deny(self, reason: str, **extra: Any) -> _Outcome:
        return _Outcome(
            decision=Decision.DENY,
            reason=reason,
            stage="control",
            policy=self._catalog_ref(),
            **extra,
        )

    async def _evaluate(  # noqa: PLR0911 - one early return per pipeline stage
        self, request: DecisionInput, subject: Principal
    ) -> _Outcome:
        control = self._controls.lookup(request.action)
        if control is None:
            return self._deny("action is not registered")
        block = await self._controls.blocked(request.action)
        if block is not None:
            return self._deny(f"action is blocked: {block.reason}", control=control)
        sources: dict[str, str] = {}
        try:
            resource, sources["resource"] = await self._resource(request.resource)
            subject_obj, clearance, sources["subject"] = await self._subject(
                subject, request.action
            )
        except _ResourceMissingError as exc:
            return self._deny(f"resource not found: {exc}", control=control, sources=sources)
        except DependencyUnavailableError as exc:
            return self._deny(
                f"attribute source unavailable: {exc.message}", control=control, sources=sources
            )
        context: dict[str, Any] = {
            "control": control,
            "sources": sources,
            "classification": resource.classification,
        }
        intent: Intent | None = None
        if request.intent_id is not None:
            if control.intent is IntentRequirement.NONE:
                return self._deny("this action does not take intents", **context)
            intent, problem = await self._intents.for_decision(
                request.intent_id,
                subject=subject,
                action=request.action,
                resource_type=resource.type,
                resource_id=resource.id,
            )
            if problem is not None:
                return self._deny(f"intent rejected: {problem}", **context)
        elif control.intent is IntentRequirement.REQUIRED:
            return self._deny(
                "a declared intent is required for this action",
                obligations=("declare_intent",),
                **context,
            )
        context["intent"] = intent
        if resource.classification > clearance:
            return self._deny("resource classification exceeds subject clearance", **context)
        policy_request = PolicyRequest(
            subject=subject_obj,
            action=request.action,
            resource=resource,
            risk=control.risk,
            environment=self._environment(request.environment, intent),
        )
        try:
            result = await self._engine.evaluate(policy_request)
        except DependencyUnavailableError as exc:
            return _Outcome(
                decision=Decision.DENY,
                reason=f"policy engine unavailable: {exc.message}",
                stage="policy",
                policy=self._local_ref(),
                engine=self._engine.mode.value,
                **context,
            )
        obligations: tuple[str, ...] = ()
        if result.decision is Decision.REQUIRE_APPROVAL:
            obligations = ("approve_intent",) if intent else ("declare_intent", "approve_intent")
        return _Outcome(
            decision=result.decision,
            reason=result.reason,
            stage="policy",
            matched_rules=result.matched_rules,
            policy=PolicyRef(
                name=result.policy_name, version=result.policy_version, digest=result.policy_digest
            ),
            engine=result.engine,
            obligations=obligations,
            **context,
        )

    async def decide(
        self, request: DecisionInput, *, caller: Principal, subject: Principal
    ) -> DecisionResult:
        started = self._perf()
        await self._policies.refresh()
        outcome = await self._evaluate(request, subject)
        if (
            outcome.decision is Decision.ALLOW
            and outcome.intent is not None
            and not request.dry_run
        ):
            consumed = await self._intents.consume(outcome.intent)
            if consumed is None:
                outcome = self._deny(
                    "intent has no remaining uses",
                    control=outcome.control,
                    sources=outcome.sources,
                    classification=outcome.classification,
                    intent=outcome.intent,
                )
            else:
                outcome.intent = consumed
        latency = self._perf() - started
        now = self._clock.now()
        policy = outcome.policy or self._catalog_ref()
        record = DecisionRecord(
            decision_id=new_id(),
            timestamp=now,
            caller_id=caller.id,
            subject_id=subject.id,
            action=request.action,
            resource_type=request.resource.type,
            resource_id=request.resource.id,
            decision=outcome.decision,
            reason=outcome.reason,
            stage=outcome.stage,
            matched_rules=outcome.matched_rules,
            policy_name=policy.name,
            policy_version=policy.version,
            policy_digest=policy.digest,
            engine=outcome.engine,
            intent_id=request.intent_id,
            dry_run=request.dry_run,
            latency_ms=round(latency * 1000, 3),
            correlation_id=correlation_id(),
            attribute_sources=outcome.sources,
            classification=outcome.classification,
        )
        await self._log.append(record)
        await self._auditor.record(
            actor=subject.id,
            action=f"decision:{request.action}",
            resource=f"{request.resource.type}:{request.resource.id}",
            outcome=outcome.decision.value,
            details={
                "decision_id": record.decision_id,
                "caller": caller.id,
                "stage": outcome.stage,
                "rules": list(outcome.matched_rules),
                "policy_digest": policy.digest,
                "engine": outcome.engine,
                "intent_id": request.intent_id,
                "dry_run": request.dry_run,
                "delegation_chain": list(subject.delegation_chain),
            },
        )
        self._metrics.decisions.labels(outcome.decision.value, outcome.stage, outcome.engine).inc()
        self._metrics.decision_latency.observe(latency)
        intent = outcome.intent
        return DecisionResult(
            decision_id=record.decision_id,
            decision=outcome.decision,
            reason=outcome.reason,
            stage=outcome.stage,
            matched_rules=outcome.matched_rules,
            policy=policy,
            engine=outcome.engine,
            subject=subject.id,
            action=request.action,
            resource=f"{request.resource.type}:{request.resource.id}",
            intent=(
                IntentUse(
                    intent_id=intent.intent_id,
                    approved=intent.approved,
                    uses=intent.uses,
                    max_uses=intent.max_uses,
                )
                if intent
                else None
            ),
            obligations=outcome.obligations,
            attribute_sources=outcome.sources,
            dry_run=request.dry_run,
            evaluated_at=now,
        )

    # -------------------------------------------------------------- filtering

    def _never(self, request: FilterInput, subject: Principal, reason: str) -> FilterResult:
        candidates = request.candidates or ()
        return FilterResult(
            subject=subject.id,
            action=request.action,
            resource_type=request.resource_type,
            residual=to_dict(FALSE),
            always_allowed=False,
            never_allowed=True,
            reason=reason,
            allowed_ids=() if request.candidates is not None else None,
            denied_ids=tuple(c.id for c in candidates) if request.candidates is not None else None,
            policy=self._catalog_ref(),
            engine="controls",
        )

    async def filter(
        self, request: FilterInput, *, caller: Principal, subject: Principal
    ) -> FilterResult:
        await self._policies.refresh()
        result = await self._filter(request, subject)
        mode = "residual" if request.candidates is None else "candidates"
        self._metrics.filters.labels(mode).inc()
        await self._auditor.record(
            actor=subject.id,
            action=f"filter:{request.action}",
            resource=f"{request.resource_type}:*",
            outcome="never" if result.never_allowed else "evaluated",
            details={
                "caller": caller.id,
                "candidates": len(request.candidates or ()),
                "allowed": len(result.allowed_ids or ()),
                "engine": result.engine,
                "policy_digest": result.policy.digest if result.policy else None,
            },
        )
        return result

    async def _filter(  # noqa: PLR0911 - one early return per pipeline stage
        self, request: FilterInput, subject: Principal
    ) -> FilterResult:
        control = self._controls.lookup(request.action)
        if control is None:
            return self._never(request, subject, "action is not registered")
        block = await self._controls.blocked(request.action)
        if block is not None:
            return self._never(request, subject, f"action is blocked: {block.reason}")
        try:
            subject_obj, clearance, _ = await self._subject(subject, request.action)
        except DependencyUnavailableError as exc:
            return self._never(request, subject, f"attribute source unavailable: {exc.message}")
        intent: Intent | None = None
        restriction: Expr = TRUE
        if request.intent_id is not None:
            if control.intent is IntentRequirement.NONE:
                return self._never(request, subject, "this action does not take intents")
            intent, problem = await self._intents.for_decision(
                request.intent_id,
                subject=subject,
                action=request.action,
                resource_type=request.resource_type,
                resource_id=None,
            )
            if problem is not None or intent is None:
                return self._never(request, subject, f"intent rejected: {problem}")
            if intent.resource_id != "*":
                restriction = Cond(
                    Condition(
                        attribute="resource.id", operator=Operator.EQ, value=intent.resource_id
                    )
                )
        elif control.intent is IntentRequirement.REQUIRED:
            return self._never(request, subject, "a declared intent is required for this action")

        base = PolicyRequest(
            subject=subject_obj,
            action=request.action,
            resource=Resource(type=request.resource_type),
            risk=control.risk,
            environment=self._environment(request.environment, intent),
        )
        ceiling = Cond(
            Condition(
                attribute="resource.classification", operator=Operator.LTE, value=int(clearance)
            )
        )
        local = self._engine.local_policy()
        residual = conj((allow_residual(local, base), ceiling, restriction)) if local else None

        allowed: tuple[str, ...] | None = None
        denied: tuple[str, ...] | None = None
        if request.candidates is not None:
            semaphore = asyncio.Semaphore(self._concurrency)

            async def check(candidate: CandidateInput) -> bool:
                async with semaphore:
                    return await self._candidate_allowed(
                        candidate, base, residual, ceiling, restriction
                    )

            verdicts = await asyncio.gather(*(check(c) for c in request.candidates))
            allowed = tuple(c.id for c, ok in zip(request.candidates, verdicts, strict=True) if ok)
            denied = tuple(
                c.id for c, ok in zip(request.candidates, verdicts, strict=True) if not ok
            )
        return FilterResult(
            subject=subject.id,
            action=request.action,
            resource_type=request.resource_type,
            residual=to_dict(residual) if residual is not None else None,
            always_allowed=residual == TRUE,
            never_allowed=residual == FALSE,
            reason=(
                "partial evaluation of the active policy"
                if residual is not None
                else f"{self._engine.mode.value} engine: candidates evaluated individually"
            ),
            allowed_ids=allowed,
            denied_ids=denied,
            policy=self._local_ref() if local else None,
            engine=self._engine.mode.value,
        )

    async def _candidate_allowed(
        self,
        candidate: CandidateInput,
        base: PolicyRequest,
        residual: Expr | None,
        ceiling: Expr,
        restriction: Expr,
    ) -> bool:
        try:
            resource, _ = await self._resource(
                ResourceInput(
                    type=base.resource.type,
                    id=candidate.id,
                    classification=candidate.classification,
                    attributes=candidate.attributes,
                )
            )
        except (_ResourceMissingError, DependencyUnavailableError):
            return False  # unknown or unverifiable resources are filtered out
        request = base.model_copy(update={"resource": resource})
        facts = request.facts()
        if residual is not None:
            return evaluate(residual, facts)
        if not (evaluate(ceiling, facts) and evaluate(restriction, facts)):
            return False
        try:
            result = await self._engine.evaluate(request)
        except DependencyUnavailableError:
            return False
        return result.decision is Decision.ALLOW
