"""Runtime settings, read from AUTHZ_* environment variables."""

from __future__ import annotations

from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from agentic_core.domain.classification import DataClassification, RiskLevel
from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from runtime_authorization_platform.policy.engines import EngineMode


class PipSpec(BaseModel):
    """An HTTP policy information point for one entity type."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    url: str = Field(description="URL template with {id} (and optionally {type})")
    auth: Literal["none", "fabric"] = "none"
    ttl_s: float = Field(default=60.0, gt=0, le=3600)
    stale_s: float = Field(default=300.0, ge=0, le=86_400)
    max_entries: int = Field(default=10_000, ge=10, le=1_000_000)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AUTHZ_", env_nested_delimiter="__")

    environment: str = "production"
    public_url: str = Field(description="Public base URL; used in the A2A Agent Card")
    database_url: str = Field(description="SQLAlchemy async URL, e.g. postgresql+asyncpg://...")

    # Microsoft Entra ID
    entra_tenant_ids: list[str] = Field(description="Allowed directory (tenant) ids")
    entra_audiences: list[str] = Field(description="Accepted aud values (app id URI, client id)")
    entra_authority: str = "https://login.microsoftonline.com"
    entra_accept_v1_tokens: bool = True
    entra_allowed_client_ids: list[str] = Field(default_factory=list)

    # Agent identity fabric (optional)
    fabric_url: str | None = None
    fabric_issuer: str | None = None
    fabric_client_id: str | None = Field(
        default=None, description="This service's agent id at the fabric (for PIP calls)"
    )
    fabric_workload_token_file: Path | None = None
    fabric_introspection_cache_s: float = Field(default=10.0, ge=0, le=60)

    # Policy and controls
    policy_file: Path = Path("policies/runtime-authorization.yaml")
    policy_tests_file: Path = Path("policies/tests/runtime-authorization.tests.yaml")
    action_catalog_file: Path = Path("policies/actions.yaml")
    service_access_policy_file: Path = Path("policies/service-access.yaml")
    require_rule_coverage: bool = True
    policy_refresh_s: float = Field(default=5.0, ge=0.5, le=300)
    action_block_refresh_s: float = Field(default=2.0, ge=0.1, le=60)

    # Decision engine
    engine_mode: EngineMode = EngineMode.LOCAL
    opa_url: str | None = None
    opa_decision_path: str = "rap/authz/result"
    opa_token: SecretStr | None = None
    opa_timeout_s: float = Field(default=2.0, gt=0, le=30)

    # Attributes
    pips: dict[str, PipSpec] = Field(default_factory=dict)
    pip_static_file: Path | None = None
    pip_static_ttl_s: float = Field(default=300.0, gt=0)
    default_clearance: DataClassification = DataClassification.INTERNAL
    default_subject_risk: RiskLevel = RiskLevel.MODERATE
    default_resource_classification: DataClassification = DataClassification.INTERNAL

    # Intents
    intent_default_ttl_s: int = Field(default=900, ge=30, le=86_400)
    intent_max_ttl_s: int = Field(default=28_800, ge=60, le=86_400)
    injection_threshold: float = Field(default=0.5, gt=0, le=1)

    # Audit and retention
    audit_log_path: Path = Path("/var/lib/runtime-authorization/audit/audit.jsonl")
    audit_key_file: Path | None = None
    dev_ephemeral_audit_key: bool = Field(
        default=False, description="In-memory audit key. Refused when environment=production."
    )
    decision_log_retention_days: int = Field(default=400, ge=1, le=3650)
    maintenance_interval_s: float = Field(default=300.0, ge=1)

    mcp_enabled: bool = True
    http_timeout_s: float = Field(default=5.0, gt=0, le=60)
    log_level: str = "INFO"
    otlp_endpoint: str | None = None

    @model_validator(mode="after")
    def _validate(self) -> Settings:
        if not self.entra_tenant_ids or not self.entra_audiences:
            raise ValueError("AUTHZ_ENTRA_TENANT_IDS and AUTHZ_ENTRA_AUDIENCES are required")
        if self.dev_ephemeral_audit_key:
            if self.environment == "production":
                raise ValueError("dev_ephemeral_audit_key cannot be used in production")
        elif self.audit_key_file is None:
            raise ValueError("AUTHZ_AUDIT_KEY_FILE is required")
        if bool(self.fabric_url) != bool(self.fabric_issuer):
            raise ValueError("AUTHZ_FABRIC_URL and AUTHZ_FABRIC_ISSUER are set together")
        if self.engine_mode is not EngineMode.LOCAL and not self.opa_url:
            raise ValueError(f"AUTHZ_OPA_URL is required for engine_mode={self.engine_mode}")
        uses_fabric_auth = any(spec.auth == "fabric" for spec in self.pips.values())
        if uses_fabric_auth and not (
            self.fabric_url and self.fabric_client_id and self.fabric_workload_token_file
        ):
            raise ValueError(
                "PIPs with auth=fabric need AUTHZ_FABRIC_URL, AUTHZ_FABRIC_CLIENT_ID "
                "and AUTHZ_FABRIC_WORKLOAD_TOKEN_FILE"
            )
        for name, spec in self.pips.items():
            if "{id}" not in spec.url:
                raise ValueError(f"PIP {name}: url must contain {{id}}")
            if self.environment == "production" and urlparse(spec.url).scheme != "https":
                raise ValueError(f"PIP {name}: https is required in production")
        if self.intent_default_ttl_s > self.intent_max_ttl_s:
            raise ValueError("intent default TTL exceeds the maximum")
        return self
