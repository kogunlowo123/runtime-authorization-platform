"""Process entry point: ``python -m runtime_authorization_platform``."""

from __future__ import annotations

import os

import uvicorn
from agentic_core.observability import configure_logging, configure_telemetry
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

from runtime_authorization_platform import __version__
from runtime_authorization_platform.api.app import create_app
from runtime_authorization_platform.config import Settings
from runtime_authorization_platform.runtime.container import build_container

SERVICE = "runtime-authorization-platform"


def main() -> None:
    settings = Settings()  # populated from AUTHZ_* environment variables
    configure_logging(service=SERVICE, environment=settings.environment, level=settings.log_level)
    exporter = None
    if settings.otlp_endpoint:
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (  # noqa: PLC0415
            OTLPSpanExporter,
        )

        exporter = OTLPSpanExporter(endpoint=settings.otlp_endpoint)
    configure_telemetry(
        service_name=SERVICE,
        service_version=__version__,
        environment=settings.environment,
        span_exporter=exporter,
    )
    app = create_app(
        lambda: build_container(settings),
        public_url=settings.public_url,
        enable_mcp=settings.mcp_enabled,
        maintenance_interval_s=settings.maintenance_interval_s,
    )
    FastAPIInstrumentor.instrument_app(app, excluded_urls="healthz,readyz,metrics")
    uvicorn.run(
        app,
        host=os.environ.get("AUTHZ_HOST", "127.0.0.1"),
        port=int(os.environ.get("AUTHZ_PORT", "8080")),
        proxy_headers=True,
        forwarded_allow_ips=os.environ.get("AUTHZ_FORWARDED_ALLOW_IPS", "127.0.0.1"),
        log_config=None,
        access_log=False,
    )


if __name__ == "__main__":
    main()
