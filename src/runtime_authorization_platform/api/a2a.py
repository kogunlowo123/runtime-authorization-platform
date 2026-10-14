"""A2A (Agent2Agent) surface: Agent Card and JSON-RPC ``message/send``.

Another agent sends a message whose first ``data`` part names a skill and its
input, e.g. ``{"skill": "decide", "input": {...}}``. The reply is an A2A
``Message`` from this agent carrying the result as a ``data`` part. Callers
authenticate with a bearer token (Entra ID or agent identity fabric) and each
skill is authorized like the equivalent REST operation.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from agentic_core.domain.identifiers import new_id
from pydantic import BaseModel, ValidationError

from runtime_authorization_platform import __version__
from runtime_authorization_platform.api.schemas import DecisionRequest, FilterRequest, IntentView
from runtime_authorization_platform.application.intents import DeclareIntent
from runtime_authorization_platform.config import Settings
from runtime_authorization_platform.domain.errors import AuthzError
from runtime_authorization_platform.domain.models import Principal
from runtime_authorization_platform.runtime.container import Container
from runtime_authorization_platform.security.roles import Operation

PROTOCOL_VERSION = "0.3.0"

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
SERVER_ERROR = -32000

SKILLS: list[dict[str, Any]] = [
    {
        "id": "decide",
        "name": "Authorization decision",
        "description": (
            "Decide whether an action on a resource is allowed. Include subject_token to "
            "decide for the agent you are enforcing for (consumes intent uses); omit it for "
            "a dry run as yourself."
        ),
        "tags": ["authorization", "abac", "policy"],
        "inputModes": ["application/json"],
        "outputModes": ["application/json"],
    },
    {
        "id": "declare_intent",
        "name": "Declare intent",
        "description": "Declare an intended action, its target and justification before acting.",
        "tags": ["intent", "governance"],
        "inputModes": ["application/json"],
        "outputModes": ["application/json"],
    },
    {
        "id": "filter",
        "name": "Filter resources",
        "description": "Residual policy condition and allowed ids for listing resources.",
        "tags": ["authorization", "partial-evaluation"],
        "inputModes": ["application/json"],
        "outputModes": ["application/json"],
    },
]


def agent_card(settings: Settings) -> dict[str, Any]:
    base = settings.public_url.rstrip("/")
    tenant = settings.entra_tenant_ids[0]
    authority = settings.entra_authority.rstrip("/")
    schemes: dict[str, Any] = {
        "entra": {
            "type": "oauth2",
            "description": "Microsoft Entra ID client credentials",
            "flows": {
                "clientCredentials": {
                    "tokenUrl": f"{authority}/{tenant}/oauth2/v2.0/token",
                    "scopes": {
                        f"{aud}/.default": "Call the platform" for aud in settings.entra_audiences
                    },
                }
            },
        }
    }
    security: list[dict[str, list[str]]] = [{"entra": []}]
    if settings.fabric_url:
        schemes["agentIdentityFabric"] = {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "Agent credential issued by the agent identity fabric",
        }
        security.append({"agentIdentityFabric": []})
    return {
        "protocolVersion": PROTOCOL_VERSION,
        "name": "Runtime Authorization Platform",
        "description": (
            "Policy decision point for AI agents: intent declaration, action-level controls, "
            "ABAC with policy information points, partial evaluation and decision logs."
        ),
        "url": f"{base}/a2a",
        "preferredTransport": "JSONRPC",
        "version": __version__,
        "documentationUrl": "https://github.com/kogunlowo123/runtime-authorization-platform",
        "capabilities": {
            "streaming": False,
            "pushNotifications": False,
            "stateTransitionHistory": False,
        },
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "skills": SKILLS,
        "securitySchemes": schemes,
        "security": security,
    }


def error_response(request_id: Any, code: int, message: str, data: Any = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


Skill = Callable[[Container, Principal, str, dict[str, Any]], Awaitable[BaseModel]]


async def _decide(c: Container, who: Principal, token: str, data: dict[str, Any]) -> BaseModel:
    body = DecisionRequest.model_validate(data)
    if body.subject_token:
        await c.access.require(who, token, Operation.DECIDE)
        subject = await c.authenticator.authenticate(body.subject_token)
        return await c.decisions.decide(body.command(), caller=who, subject=subject)
    await c.access.require(who, token, Operation.DECIDE_SELF)
    dry = body.command().model_copy(update={"dry_run": True})
    return await c.decisions.decide(dry, caller=who, subject=who)


async def _declare(c: Container, who: Principal, token: str, data: dict[str, Any]) -> BaseModel:
    command = DeclareIntent.model_validate(data)
    await c.access.require(who, token, Operation.INTENT_DECLARE)
    return IntentView.of(await c.intents.declare(command, who))


async def _filter(c: Container, who: Principal, token: str, data: dict[str, Any]) -> BaseModel:
    body = FilterRequest.model_validate(data)
    await c.access.require(who, token, Operation.FILTER)
    if body.subject_token:
        await c.access.require(who, token, Operation.DECIDE)
        subject = await c.authenticator.authenticate(body.subject_token)
    else:
        subject = who
    return await c.decisions.filter(body.command(), caller=who, subject=subject)


HANDLERS: dict[str, Skill] = {"decide": _decide, "declare_intent": _declare, "filter": _filter}


def _skill_call(params: Any) -> tuple[dict[str, Any], str, dict[str, Any]] | str:
    message = params.get("message") if isinstance(params, dict) else None
    if not isinstance(message, dict) or not isinstance(message.get("parts"), list):
        return "params.message with parts is required"
    for part in message["parts"]:
        if isinstance(part, dict) and part.get("kind") == "data":
            data = part.get("data")
            if (
                isinstance(data, dict)
                and isinstance(data.get("skill"), str)
                and isinstance(data.get("input"), dict)
            ):
                return message, data["skill"], data["input"]
    return "message needs a data part of the form {skill, input}"


async def handle(  # noqa: PLR0911 - one return per JSON-RPC error class
    payload: Any, container: Container, principal: Principal, token: str
) -> dict[str, Any]:
    if not isinstance(payload, dict) or payload.get("jsonrpc") != "2.0":
        return error_response(None, INVALID_REQUEST, "invalid JSON-RPC 2.0 request")
    request_id = payload.get("id")
    if not isinstance(request_id, str | int) or isinstance(request_id, bool):
        return error_response(None, INVALID_REQUEST, "id must be a string or integer")
    if payload.get("method") != "message/send":
        return error_response(
            request_id, METHOD_NOT_FOUND, f"method {payload.get('method')!r} not found"
        )
    parsed = _skill_call(payload.get("params"))
    if isinstance(parsed, str):
        return error_response(request_id, INVALID_PARAMS, parsed)
    message, skill, data = parsed
    handler = HANDLERS.get(skill)
    if handler is None:
        return error_response(
            request_id, INVALID_PARAMS, f"unknown skill {skill!r}", {"skills": list(HANDLERS)}
        )
    try:
        result = await handler(container, principal, token, data)
    except ValidationError as exc:
        container.metrics.protocol_calls.labels("a2a", skill, "invalid_params").inc()
        details = [{"loc": list(e["loc"]), "msg": e["msg"]} for e in exc.errors()]
        return error_response(request_id, INVALID_PARAMS, "skill input failed validation", details)
    except AuthzError as exc:
        container.metrics.protocol_calls.labels("a2a", skill, exc.code).inc()
        return error_response(
            request_id,
            SERVER_ERROR,
            exc.message,
            {"error": exc.code, "error_description": exc.message},
        )
    container.metrics.protocol_calls.labels("a2a", skill, "ok").inc()
    context_id = message.get("contextId")
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "kind": "message",
            "role": "agent",
            "messageId": new_id(),
            "contextId": context_id if isinstance(context_id, str) else new_id(),
            "parts": [
                {"kind": "data", "data": {"skill": skill, "result": result.model_dump(mode="json")}}
            ],
        },
    }
