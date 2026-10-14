"""FastAPI application factory."""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from agentic_core.observability import bind_correlation_id, get_logger
from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from starlette.routing import Route

from runtime_authorization_platform import __version__
from runtime_authorization_platform.api.mcp import (
    BearerRequired,
    build_mcp_server,
    transport_security,
)
from runtime_authorization_platform.api.routes import router
from runtime_authorization_platform.domain.errors import AuthzError
from runtime_authorization_platform.runtime.container import Container

ContainerFactory = Callable[[], Awaitable[Container]]

log = get_logger("runtime_authorization_platform.api")


async def maintenance_forever(
    container: Container,
    interval_s: float,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> None:
    """Expire lapsed intents and purge decision-log rows past retention."""
    while True:
        try:
            await container.maintenance()
        except Exception:
            log.exception("maintenance_failed")
        await sleep(interval_s)


def create_app(
    factory: ContainerFactory,
    *,
    public_url: str | None = None,
    enable_mcp: bool = True,
    maintenance_interval_s: float = 300.0,
) -> FastAPI:
    mcp_server = None
    if enable_mcp:
        if public_url is None:
            raise ValueError("public_url is required when MCP is enabled")

        def current() -> Container:
            found: Container = app.state.container
            return found

        mcp_server = build_mcp_server(current)
        mcp_app = mcp_server.streamable_http_app(
            streamable_http_path="/mcp",
            stateless_http=True,
            json_response=True,
            transport_security=transport_security(public_url),
        )

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        container = await factory()
        app.state.container = container
        sweeper = asyncio.create_task(maintenance_forever(container, maintenance_interval_s))
        log.info("startup", version=__version__, engine=container.settings.engine_mode.value)
        try:
            async with contextlib.AsyncExitStack() as stack:
                if mcp_server is not None:
                    await stack.enter_async_context(mcp_server.session_manager.run())
                yield
        finally:
            sweeper.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await sweeper
            await container.aclose()

    app = FastAPI(
        title="Runtime Authorization Platform",
        version=__version__,
        description=(
            "Policy decision point for AI agents: intent declaration, action-level controls, "
            "Entra ID token validation, ABAC with policy information points, policy authoring "
            "with tests, decision logs, partial evaluation for list filtering and OPA/Rego "
            "compatibility."
        ),
        lifespan=lifespan,
    )
    app.include_router(router)
    if mcp_server is not None:
        app.router.routes.append(
            Route(
                "/mcp",
                endpoint=BearerRequired(mcp_app, current),
                methods=["GET", "POST", "DELETE"],
                include_in_schema=False,
            )
        )

    @app.middleware("http")
    async def correlation_and_metrics(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        incoming = request.headers.get("x-correlation-id")
        cid = incoming if incoming and len(incoming) <= 64 and incoming.isprintable() else None
        started = time.perf_counter()
        with bind_correlation_id(cid) as bound:
            response = await call_next(request)
        response.headers["X-Correlation-ID"] = bound
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        route = request.scope.get("route")
        path = getattr(route, "path", "unmatched")
        container: Container | None = getattr(request.app.state, "container", None)
        if container is not None:
            container.metrics.requests.labels(
                request.method, path, str(response.status_code)
            ).observe(time.perf_counter() - started)
        return response

    @app.exception_handler(AuthzError)
    async def authz_error(_: Request, exc: AuthzError) -> JSONResponse:
        headers = (
            {"WWW-Authenticate": 'Bearer realm="runtime-authorization"'}
            if exc.status == 401
            else None
        )
        content: dict[str, object] = {"error": exc.code, "error_description": exc.message}
        if exc.details is not None:
            content["details"] = exc.details
        return JSONResponse(status_code=exc.status, content=content, headers=headers)

    @app.exception_handler(RequestValidationError)
    async def validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "error": "invalid_request",
                "error_description": "request failed validation",
                "details": [
                    {"loc": list(e.get("loc", ())), "msg": str(e.get("msg", ""))}
                    for e in exc.errors()
                ],
            },
        )

    @app.exception_handler(SQLAlchemyError)
    async def database_error(_: Request, exc: SQLAlchemyError) -> JSONResponse:
        log.error("database_error", error=type(exc).__name__)
        return JSONResponse(
            status_code=503,
            content={"error": "temporarily_unavailable", "error_description": "database error"},
            headers={"Retry-After": "1"},
        )

    return app
