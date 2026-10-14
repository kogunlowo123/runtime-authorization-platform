"""Composition root: builds every component once per process from Settings."""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import timedelta

import httpx
from agentic_core.audit import AuditLog, JsonlAuditSink
from agentic_core.policy import PolicyEngine, PolicySet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from runtime_authorization_platform.application.audit import Auditor
from runtime_authorization_platform.application.controls import ActionControls
from runtime_authorization_platform.application.decisions import DecisionService
from runtime_authorization_platform.application.intents import IntentService
from runtime_authorization_platform.application.policies import PolicyAdministration
from runtime_authorization_platform.config import Settings
from runtime_authorization_platform.domain.models import ActionCatalog
from runtime_authorization_platform.domain.ports import AttributeSource, Clock
from runtime_authorization_platform.infrastructure.database import (
    SqlActionBlockRepository,
    SqlDecisionLog,
    SqlIntentRepository,
    SqlPolicyRepository,
    SystemClock,
    create_schema,
    make_engine,
)
from runtime_authorization_platform.integrations.fabric import FabricClient, FabricTokenProvider
from runtime_authorization_platform.integrations.opa import OpaClient
from runtime_authorization_platform.integrations.pip import (
    AttributeCache,
    AttributeResolver,
    HttpAttributeSource,
    StaticAttributeSource,
)
from runtime_authorization_platform.observability.metrics import AuthzMetrics
from runtime_authorization_platform.policy.engines import (
    CombinedEngine,
    DecisionEngine,
    EngineMode,
    LocalEngine,
    OpaEngine,
    PolicyHolder,
    ShadowEngine,
)
from runtime_authorization_platform.security.access import ServiceAccess
from runtime_authorization_platform.security.authn import Authenticator
from runtime_authorization_platform.security.entra import EntraIdValidator
from runtime_authorization_platform.security.jwks import KeyResolver


@dataclass
class Container:
    settings: Settings
    decisions: DecisionService
    intents: IntentService
    policies: PolicyAdministration
    controls: ActionControls
    decision_log: SqlDecisionLog
    authenticator: Authenticator
    access: ServiceAccess
    auditor: Auditor
    metrics: AuthzMetrics
    engine: AsyncEngine
    http: httpx.AsyncClient
    opa: OpaClient | None
    clock: Clock

    async def ready(self) -> dict[str, bool]:
        checks: dict[str, bool] = {}
        try:
            async with self.engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            checks["database"] = True
        except Exception:
            checks["database"] = False
        if self.opa is not None and self.settings.engine_mode is not EngineMode.SHADOW:
            checks["opa"] = await self.opa.healthy()
        return checks

    async def maintenance(self) -> dict[str, int]:
        expired = await self.intents.expire()
        cutoff = self.clock.now() - timedelta(days=self.settings.decision_log_retention_days)
        purged = await self.decision_log.purge_before(cutoff)
        self.metrics.maintenance.labels("intents_expired").set(expired)
        self.metrics.maintenance.labels("decisions_purged").set(purged)
        return {"intents_expired": expired, "decisions_purged": purged}

    async def aclose(self) -> None:
        await self.http.aclose()
        await self.engine.dispose()


def _audit_signer(settings: Settings) -> tuple[Ed25519PrivateKey, str]:
    if settings.audit_key_file is None:
        return Ed25519PrivateKey.generate(), "audit-ephemeral"
    key = serialization.load_pem_private_key(settings.audit_key_file.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("audit key must be Ed25519")
    return key, settings.audit_key_file.stem


def _resolver(
    settings: Settings,
    http: httpx.AsyncClient,
    metrics: AuthzMetrics,
    fabric: FabricClient | None,
    monotonic: Callable[[], float] | None,
) -> AttributeResolver:
    caches: dict[str, AttributeCache] = {}
    clock = monotonic or time.monotonic

    def counter(entity_type: str) -> Callable[[str], None]:
        return lambda outcome: metrics.pip_lookups.labels(entity_type, outcome).inc()

    if settings.pip_static_file is not None:
        static = StaticAttributeSource.from_file(settings.pip_static_file)
        for entity_type in static.entity_types():
            caches[entity_type] = AttributeCache(
                static,
                ttl_s=settings.pip_static_ttl_s,
                stale_s=0,
                on_event=counter(entity_type),
                monotonic=clock,
            )
    token_provider = None
    if fabric is not None and settings.fabric_client_id and settings.fabric_workload_token_file:
        token_provider = FabricTokenProvider(
            fabric,
            client_id=settings.fabric_client_id,
            workload_token_file=settings.fabric_workload_token_file,
        )
    for entity_type, spec in settings.pips.items():
        source: AttributeSource = HttpAttributeSource(
            f"http:{entity_type}",
            spec.url,
            http=http,
            token_provider=token_provider if spec.auth == "fabric" else None,
        )
        caches[entity_type] = AttributeCache(
            source,
            ttl_s=spec.ttl_s,
            stale_s=spec.stale_s,
            max_entries=spec.max_entries,
            on_event=counter(entity_type),
            monotonic=clock,
        )
    return AttributeResolver(caches)


async def build_container(
    settings: Settings,
    *,
    entra_resolvers: Mapping[str, KeyResolver] | None = None,
    clock: Clock | None = None,
    http: httpx.AsyncClient | None = None,
    monotonic: Callable[[], float] | None = None,
) -> Container:
    http = http or httpx.AsyncClient(timeout=httpx.Timeout(settings.http_timeout_s))
    clock = clock or SystemClock()
    metrics = AuthzMetrics()

    engine = make_engine(settings.database_url)
    await create_schema(engine)

    signer, key_id = _audit_signer(settings)
    auditor = Auditor(AuditLog(JsonlAuditSink(settings.audit_log_path), signer, key_id=key_id))

    fabric = FabricClient(settings.fabric_url, http=http) if settings.fabric_url else None
    entra = EntraIdValidator(
        tenants=frozenset(settings.entra_tenant_ids),
        audiences=frozenset(settings.entra_audiences),
        http=http,
        authority=settings.entra_authority,
        accept_v1_tokens=settings.entra_accept_v1_tokens,
        allowed_client_ids=frozenset(settings.entra_allowed_client_ids),
        resolvers=entra_resolvers,
        clock=clock.now,
    )
    authenticator = Authenticator(
        entra,
        fabric=fabric,
        fabric_issuer=settings.fabric_issuer,
        introspection_cache_s=settings.fabric_introspection_cache_s,
        clock=clock.now,
    )
    access = ServiceAccess(
        PolicyEngine(PolicySet.from_file(settings.service_access_policy_file)),
        authenticator=authenticator,
        fabric=fabric,
    )

    ticks = monotonic or time.monotonic
    holder = PolicyHolder(PolicySet.from_file(settings.policy_file))
    policies = PolicyAdministration(
        repository=SqlPolicyRepository(engine),
        holder=holder,
        auditor=auditor,
        clock=clock,
        metrics=metrics,
        require_rule_coverage=settings.require_rule_coverage,
        refresh_s=settings.policy_refresh_s,
        monotonic=ticks,
    )
    await policies.bootstrap(settings.policy_file, settings.policy_tests_file)

    opa: OpaClient | None = None
    local = LocalEngine(holder)
    decision_engine: DecisionEngine = local
    if settings.opa_url:
        opa = OpaClient(
            settings.opa_url,
            http=http,
            decision_path=settings.opa_decision_path,
            bearer_token=settings.opa_token.get_secret_value() if settings.opa_token else None,
            timeout_s=settings.opa_timeout_s,
        )
        external = OpaEngine(opa)
        if settings.engine_mode is EngineMode.OPA:
            decision_engine = external
        elif settings.engine_mode is EngineMode.COMBINED:
            decision_engine = CombinedEngine(local, external)
        elif settings.engine_mode is EngineMode.SHADOW:
            decision_engine = ShadowEngine(
                local, external, lambda outcome: metrics.opa_shadow.labels(outcome).inc()
            )

    controls = ActionControls(
        catalog=ActionCatalog.from_file(settings.action_catalog_file),
        blocks=SqlActionBlockRepository(engine),
        auditor=auditor,
        clock=clock,
        refresh_s=settings.action_block_refresh_s,
        monotonic=ticks,
    )
    intents = IntentService(
        repository=SqlIntentRepository(engine),
        controls=controls,
        auditor=auditor,
        clock=clock,
        metrics=metrics,
        injection_threshold=settings.injection_threshold,
        default_ttl=timedelta(seconds=settings.intent_default_ttl_s),
        max_ttl=timedelta(seconds=settings.intent_max_ttl_s),
    )
    decision_log = SqlDecisionLog(engine)
    decisions = DecisionService(
        controls=controls,
        intents=intents,
        engine=decision_engine,
        policies=policies,
        resolver=_resolver(settings, http, metrics, fabric, monotonic),
        decisions=decision_log,
        auditor=auditor,
        clock=clock,
        metrics=metrics,
        default_clearance=settings.default_clearance,
        default_subject_risk=settings.default_subject_risk,
        default_classification=settings.default_resource_classification,
    )
    return Container(
        settings=settings,
        decisions=decisions,
        intents=intents,
        policies=policies,
        controls=controls,
        decision_log=decision_log,
        authenticator=authenticator,
        access=access,
        auditor=auditor,
        metrics=metrics,
        engine=engine,
        http=http,
        opa=opa,
        clock=clock,
    )
