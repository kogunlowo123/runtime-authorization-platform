"""HTTP routes.

Every route except discovery and probes requires a bearer token (Entra ID or
agent identity fabric) and is authorized as ``authz:<operation>`` through
``security.access.ServiceAccess``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Annotated, Any

from agentic_core.domain.classification import Decision
from fastapi import APIRouter, Depends, Header, Query, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from runtime_authorization_platform.api import a2a
from runtime_authorization_platform.api.schemas import (
    ActionCatalogView,
    BlockAction,
    DecisionLogPage,
    DecisionRequest,
    FilterRequest,
    IntentView,
    PolicyVersionList,
    PolicyVersionSummary,
    PolicyVersionView,
    RevokeIntent,
)
from runtime_authorization_platform.application.decisions import DecisionResult, FilterResult
from runtime_authorization_platform.application.intents import DeclareIntent
from runtime_authorization_platform.application.policies import SubmitPolicy, parse_policy
from runtime_authorization_platform.domain.errors import AuthzError
from runtime_authorization_platform.domain.models import ActionBlock, Principal
from runtime_authorization_platform.policy import rego
from runtime_authorization_platform.policy.testing import PolicyTestReport
from runtime_authorization_platform.runtime.container import Container
from runtime_authorization_platform.security.authn import bearer_token
from runtime_authorization_platform.security.roles import Operation

router = APIRouter()


class InvalidSubjectTokenError(AuthzError):
    code = "invalid_subject_token"
    status = 400


@dataclass(frozen=True)
class Caller:
    principal: Principal
    token: str


def container(request: Request) -> Container:
    value: Container = request.app.state.container
    return value


Deps = Annotated[Container, Depends(container)]


async def caller(c: Deps, authorization: Annotated[str | None, Header()] = None) -> Caller:
    token = bearer_token(authorization)
    return Caller(await c.authenticator.authenticate(token), token)


Who = Annotated[Caller, Depends(caller)]


async def _subject(c: Container, token: str) -> Principal:
    try:
        return await c.authenticator.authenticate(token)
    except AuthzError as exc:
        if exc.status == 401:
            raise InvalidSubjectTokenError(f"subject token rejected: {exc.message}") from exc
        raise


# ------------------------------------------------------------------ decisions


@router.post("/v1/decisions", tags=["decisions"])
async def decide(body: DecisionRequest, c: Deps, who: Who) -> DecisionResult:
    """Decide for the subject whose token the enforcement point received.

    Without ``subject_token`` the caller asks about itself and the request is a dry run.
    """
    if body.subject_token:
        await c.access.require(who.principal, who.token, Operation.DECIDE)
        subject = await _subject(c, body.subject_token)
        return await c.decisions.decide(body.command(), caller=who.principal, subject=subject)
    await c.access.require(who.principal, who.token, Operation.DECIDE_SELF)
    dry = body.command().model_copy(update={"dry_run": True})
    return await c.decisions.decide(dry, caller=who.principal, subject=who.principal)


@router.post("/v1/filter", tags=["decisions"])
async def filter_resources(body: FilterRequest, c: Deps, who: Who) -> FilterResult:
    """Partial evaluation for list filtering: a residual condition and/or allowed candidate ids."""
    await c.access.require(who.principal, who.token, Operation.FILTER)
    subject = who.principal
    if body.subject_token:
        await c.access.require(who.principal, who.token, Operation.DECIDE)
        subject = await _subject(c, body.subject_token)
    return await c.decisions.filter(body.command(), caller=who.principal, subject=subject)


@router.get("/v1/decision-logs", tags=["decisions"])
async def decision_logs(
    *,
    c: Deps,
    who: Who,
    subject: Annotated[str | None, Query(max_length=512)] = None,
    action: Annotated[str | None, Query(max_length=200)] = None,
    decision: Decision | None = None,
    since: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
) -> DecisionLogPage:
    await c.access.require(who.principal, who.token, Operation.DECISION_LOG_READ)
    items = await c.decision_log.query(
        subject_id=subject,
        action=action,
        decision=decision,
        since=since,
        limit=limit,
        offset=offset,
    )
    return DecisionLogPage(items=list(items), limit=limit, offset=offset)


# -------------------------------------------------------------------- intents


@router.post("/v1/intents", status_code=201, tags=["intents"])
async def declare_intent(body: DeclareIntent, c: Deps, who: Who) -> IntentView:
    await c.access.require(who.principal, who.token, Operation.INTENT_DECLARE)
    return IntentView.of(await c.intents.declare(body, who.principal))


@router.get("/v1/intents/{intent_id}", tags=["intents"])
async def get_intent(intent_id: str, c: Deps, who: Who) -> IntentView:
    intent = await c.intents.get(intent_id)
    if intent.principal_id != who.principal.id:
        await c.access.require(who.principal, who.token, Operation.INTENT_READ)
    return IntentView.of(intent)


@router.post("/v1/intents/{intent_id}/approve", tags=["intents"])
async def approve_intent(intent_id: str, c: Deps, who: Who) -> IntentView:
    await c.access.require(who.principal, who.token, Operation.INTENT_APPROVE)
    return IntentView.of(await c.intents.approve(intent_id, approver=who.principal))


@router.post("/v1/intents/{intent_id}/revoke", tags=["intents"])
async def revoke_intent(intent_id: str, body: RevokeIntent, c: Deps, who: Who) -> IntentView:
    privileged = await c.access.check(who.principal, who.token, Operation.INTENT_REVOKE)
    intent = await c.intents.revoke(
        intent_id, actor=who.principal, reason=body.reason, privileged=privileged
    )
    return IntentView.of(intent)


# ------------------------------------------------------------------- policies


@router.post("/v1/policies/test", tags=["policies"])
async def test_policy(body: SubmitPolicy, c: Deps, who: Who) -> PolicyTestReport:
    """Run a draft's tests without storing it."""
    await c.access.require(who.principal, who.token, Operation.POLICY_SUBMIT)
    return c.policies.test(body)


@router.post("/v1/policies", status_code=201, tags=["policies"])
async def submit_policy(body: SubmitPolicy, c: Deps, who: Who) -> PolicyVersionView:
    await c.access.require(who.principal, who.token, Operation.POLICY_SUBMIT)
    return PolicyVersionView.full(await c.policies.submit(body, actor=who.principal.id))


@router.get("/v1/policies", tags=["policies"])
async def list_policies(
    c: Deps,
    who: Who,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> PolicyVersionList:
    await c.access.require(who.principal, who.token, Operation.POLICY_READ)
    versions = await c.policies.list(limit=limit, offset=offset)
    return PolicyVersionList(
        items=[PolicyVersionSummary.of(v) for v in versions], limit=limit, offset=offset
    )


@router.get("/v1/policies/active", tags=["policies"])
async def active_policy(c: Deps, who: Who) -> PolicyVersionView:
    await c.access.require(who.principal, who.token, Operation.POLICY_READ)
    return PolicyVersionView.full(await c.policies.active())


@router.get("/v1/policies/{version_id}", tags=["policies"])
async def get_policy(version_id: str, c: Deps, who: Who) -> PolicyVersionView:
    await c.access.require(who.principal, who.token, Operation.POLICY_READ)
    return PolicyVersionView.full(await c.policies.get(version_id))


@router.get(
    "/v1/policies/{version_id}/rego",
    tags=["policies"],
    response_class=PlainTextResponse,
    responses={200: {"content": {"text/plain": {}}}},
)
async def export_rego(
    version_id: str,
    c: Deps,
    who: Who,
    package: Annotated[str, Query(pattern=r"^[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*)*$")] = (
        "rap.authz"
    ),
) -> PlainTextResponse:
    """The version as a Rego module for Open Policy Agent."""
    await c.access.require(who.principal, who.token, Operation.POLICY_READ)
    version = await c.policies.get(version_id)
    return PlainTextResponse(rego.export(parse_policy(version.document), package=package))


@router.post("/v1/policies/{version_id}/activate", tags=["policies"])
async def activate_policy(version_id: str, c: Deps, who: Who) -> PolicyVersionView:
    """Activate (or roll back to) a version. The author of a version cannot activate it."""
    await c.access.require(who.principal, who.token, Operation.POLICY_ACTIVATE)
    return PolicyVersionView.full(await c.policies.activate(version_id, actor=who.principal.id))


# -------------------------------------------------------------------- actions


@router.get("/v1/actions", tags=["actions"])
async def actions(c: Deps, who: Who) -> ActionCatalogView:
    await c.access.require(who.principal, who.token, Operation.ACTION_READ)
    return ActionCatalogView(
        version=c.controls.catalog.version,
        digest=c.controls.catalog_digest,
        actions=list(c.controls.catalog.actions),
        blocks=list(await c.controls.blocks()),
    )


@router.post("/v1/action-blocks", status_code=201, tags=["actions"])
async def block_action(body: BlockAction, c: Deps, who: Who) -> ActionBlock:
    """Emergency stop: every decision for matching actions is denied until unblocked."""
    await c.access.require(who.principal, who.token, Operation.ACTION_BLOCK)
    return await c.controls.block(body.pattern, reason=body.reason, actor=who.principal.id)


@router.delete("/v1/action-blocks/{block_id}", tags=["actions"])
async def unblock_action(block_id: str, c: Deps, who: Who) -> ActionBlock:
    await c.access.require(who.principal, who.token, Operation.ACTION_BLOCK)
    return await c.controls.unblock(block_id, actor=who.principal.id)


# ------------------------------------------------------------------------ A2A


@router.get("/.well-known/agent-card.json", tags=["a2a"])
async def agent_card(c: Deps) -> dict[str, Any]:
    return a2a.agent_card(c.settings)


@router.post("/a2a", tags=["a2a"])
async def a2a_endpoint(request: Request, c: Deps, who: Who) -> JSONResponse:
    """A2A JSON-RPC 2.0 endpoint (``message/send``)."""
    try:
        payload = await request.json()
    except ValueError:
        return JSONResponse(a2a.error_response(None, a2a.PARSE_ERROR, "parse error"))
    return JSONResponse(await a2a.handle(payload, c, who.principal, who.token))


# ----------------------------------------------------------------- operations


@router.get("/healthz", tags=["operations"], include_in_schema=False)
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/readyz", tags=["operations"], include_in_schema=False)
async def readyz(c: Deps, response: Response) -> dict[str, Any]:
    checks = await c.ready()
    if not all(checks.values()):
        response.status_code = 503
        return {"status": "unavailable", "checks": checks}
    return {"status": "ready", "checks": checks}


@router.get("/metrics", tags=["operations"], include_in_schema=False)
async def metrics(c: Deps) -> Response:
    return Response(generate_latest(c.metrics.registry), media_type=CONTENT_TYPE_LATEST)
