"""MCP server (official ``mcp`` SDK, streamable HTTP) exposing the platform to agents.

Tools act as the calling agent: the bearer token on the MCP request is
authenticated, the operation is authorized through the same service-access
policy as the REST API, and every call is audited. Authorization checks made
through MCP are dry runs; enforcement points consume intents through
``POST /v1/decisions``.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import urlparse

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import Field
from starlette.types import ASGIApp, Receive, Scope, Send

from runtime_authorization_platform import __version__
from runtime_authorization_platform.api.schemas import IntentView
from runtime_authorization_platform.application.decisions import (
    DecisionInput,
    DecisionResult,
    FilterInput,
    FilterResult,
)
from runtime_authorization_platform.application.intents import DeclareIntent
from runtime_authorization_platform.domain.errors import AuthzError, ForbiddenError
from runtime_authorization_platform.domain.models import Principal
from runtime_authorization_platform.runtime.container import Container
from runtime_authorization_platform.security.authn import bearer_token
from runtime_authorization_platform.security.roles import Operation

ContainerGetter = Callable[[], Container]


async def _authenticated(container: Container, ctx: Context) -> tuple[Principal, str]:
    headers = {k.lower(): v for k, v in (ctx.headers or {}).items()}
    token = bearer_token(headers.get("authorization"))
    return await container.authenticator.authenticate(token), token


async def _run[T](
    get: ContainerGetter,
    ctx: Context,
    tool: str,
    operation: Operation,
    call: Callable[[Container, Principal], Awaitable[T]],
) -> T:
    container = get()
    try:
        principal, token = await _authenticated(container, ctx)
        await container.access.require(principal, token, operation)
        result = await call(container, principal)
    except AuthzError as exc:
        container.metrics.protocol_calls.labels("mcp", tool, exc.code).inc()
        raise ToolError(f"{exc.code}: {exc.message}") from exc
    container.metrics.protocol_calls.labels("mcp", tool, "ok").inc()
    await container.auditor.record(
        actor=principal.id,
        action=f"mcp.tool.{tool}",
        resource="runtime-authorization",
        outcome="success",
        details={"operation": operation.value},
    )
    return result


def build_mcp_server(get: ContainerGetter) -> MCPServer:
    server = MCPServer(
        name="runtime-authorization-platform",
        version=__version__,
        instructions=(
            "Declare an intent before high-risk actions, then check authorization. "
            "Decisions are deny-by-default; require_approval means a human must approve "
            "the declared intent first."
        ),
    )

    @server.tool(
        name="declare_intent",
        description="Declare the action you are about to take, on which resource, and why.",
    )
    async def declare_intent(request: DeclareIntent, ctx: Context) -> IntentView:
        async def call(c: Container, who: Principal) -> IntentView:
            return IntentView.of(await c.intents.declare(request, who))

        return await _run(get, ctx, "declare_intent", Operation.INTENT_DECLARE, call)

    @server.tool(
        name="check_authorization",
        description="Dry-run decision for an action on a resource, as the calling agent.",
    )
    async def check_authorization(request: DecisionInput, ctx: Context) -> DecisionResult:
        async def call(c: Container, who: Principal) -> DecisionResult:
            dry = request.model_copy(update={"dry_run": True})
            return await c.decisions.decide(dry, caller=who, subject=who)

        return await _run(get, ctx, "check_authorization", Operation.DECIDE_SELF, call)

    @server.tool(
        name="filter_resources",
        description="Which resources of a type may the calling agent act on (partial evaluation).",
    )
    async def filter_resources(request: FilterInput, ctx: Context) -> FilterResult:
        async def call(c: Container, who: Principal) -> FilterResult:
            return await c.decisions.filter(request, caller=who, subject=who)

        return await _run(get, ctx, "filter_resources", Operation.FILTER, call)

    @server.tool(name="get_intent", description="Status of an intent you declared.")
    async def get_intent(
        ctx: Context, intent_id: str = Field(min_length=1, max_length=64)
    ) -> IntentView:
        async def call(c: Container, who: Principal) -> IntentView:
            intent = await c.intents.get(intent_id)
            if intent.principal_id != who.id:
                raise ForbiddenError("intents are visible to the declaring principal")
            return IntentView.of(intent)

        return await _run(get, ctx, "get_intent", Operation.INTENT_DECLARE, call)

    return server


def transport_security(
    public_url: str, extra_hosts: tuple[str, ...] = ()
) -> TransportSecuritySettings:
    """DNS-rebinding protection: accept only the public host (and local probes)."""
    parsed = urlparse(public_url)
    host = parsed.netloc
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[host, f"{parsed.hostname}:*", "127.0.0.1:*", "localhost:*", *extra_hosts],
        allowed_origins=[f"{parsed.scheme}://{host}"],
    )


class BearerRequired:
    """Rejects MCP requests without a valid bearer token before the SDK parses them."""

    def __init__(self, app: ASGIApp, get: ContainerGetter) -> None:
        self._app = app
        self._get = get

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
        try:
            await self._get().authenticator.authenticate(bearer_token(headers.get("authorization")))
        except AuthzError as exc:
            body: dict[str, Any] = {"error": exc.code, "error_description": exc.message}
            payload = json.dumps(body).encode()
            await send(
                {
                    "type": "http.response.start",
                    "status": exc.status,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"www-authenticate", b'Bearer realm="runtime-authorization"'),
                        (b"content-length", str(len(payload)).encode()),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": payload})
            return
        await self._app(scope, receive, send)
