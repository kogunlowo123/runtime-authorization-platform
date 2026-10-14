"""Settings validation, domain model rules, container wiring and published contracts."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from agentic_core.domain.classification import RiskLevel
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from runtime_authorization_platform.contracts import main as contracts
from runtime_authorization_platform.domain.models import (
    ActionCatalog,
    ActionControl,
    Intent,
    IntentStatus,
    validate_action,
)
from runtime_authorization_platform.policy.engines import CombinedEngine, OpaEngine, ShadowEngine
from runtime_authorization_platform.runtime.container import build_container
from tests.conftest import ROOT, make_settings


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"entra_tenant_ids": []}, "TENANT_IDS"),
        ({"dev_ephemeral_audit_key": False}, "AUDIT_KEY_FILE"),
        ({"environment": "production"}, "production"),
        ({"fabric_url": "https://identity.corp.test"}, "set together"),
        ({"engine_mode": "opa"}, "OPA_URL"),
        ({"pips": {"document": {"url": "https://pip/doc", "auth": "none"}}}, "{id}"),
        ({"pips": {"document": {"url": "https://pip/{id}", "auth": "fabric"}}}, "auth=fabric"),
        ({"intent_default_ttl_s": 7200, "intent_max_ttl_s": 3600}, "default TTL"),
    ],
)
def test_settings_validation(tmp_path: Path, overrides: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        make_settings(tmp_path, **overrides)


def test_production_requires_https_pips(tmp_path: Path) -> None:
    key = tmp_path / "audit-2026-10.pem"
    with pytest.raises(ValidationError, match="https"):
        make_settings(
            tmp_path,
            environment="production",
            dev_ephemeral_audit_key=False,
            audit_key_file=key,
            pips={"document": {"url": "http://pip/{id}"}},
        )


def test_actions_and_catalog() -> None:
    assert validate_action("documents:read") == "documents:read"
    for bad in ("documents", "Documents:read", "documents:*", "a:b:c:d:e", ""):
        with pytest.raises(ValueError, match="invalid action"):
            validate_action(bad)
    with pytest.raises(ValidationError, match="invalid action pattern"):
        ActionControl(pattern="BAD PATTERN", risk=RiskLevel.LOW, description="desc")
    control = ActionControl(pattern="tickets:*", risk=RiskLevel.LOW, description="tickets")
    with pytest.raises(ValidationError, match="duplicate"):
        ActionCatalog(version="1", actions=(control, control))
    catalog = ActionCatalog.from_file(ROOT / "policies" / "actions.yaml")
    assert catalog.lookup("tickets:read").intent.value == "none"  # type: ignore[union-attr]
    assert catalog.lookup("tickets:close").pattern == "tickets:*"  # type: ignore[union-attr]
    assert catalog.lookup("nothing:here") is None


def test_intent_model() -> None:
    now = datetime.now(UTC)
    intent = Intent(
        intent_id="i",
        principal_id="p",
        action="email:send",
        resource_type="mailbox",
        resource_id="*",
        justification="j" * 20,
        purpose="p",
        risk=RiskLevel.HIGH,
        status=IntentStatus.ACTIVE,
        max_uses=1,
        created_at=now,
        expires_at=now + timedelta(minutes=1),
    )
    assert intent.covers("email:send", "mailbox", "anything")
    assert not intent.covers("email:send", "calendar", "anything")
    assert intent.effective_status(now + timedelta(minutes=2)) is IntentStatus.EXPIRED
    assert intent.facts()["declared"] is True


async def test_container_with_audit_key_and_opa_modes(tmp_path: Path, static_pip: Path) -> None:
    key_file = tmp_path / "audit-2026-10.pem"
    key_file.write_bytes(
        Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    http = httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(200, json={})))
    for mode, kind in (("opa", OpaEngine), ("combined", CombinedEngine), ("shadow", ShadowEngine)):
        settings = make_settings(
            tmp_path,
            dev_ephemeral_audit_key=False,
            audit_key_file=key_file,
            engine_mode=mode,
            opa_url="http://opa.test:8181",
            opa_token="opa-token-value",
            pips={"ticket": {"url": "https://pip.corp.test/tickets/{id}"}},
            pip_static_file=static_pip,
            fabric_url="https://identity.corp.test",
            fabric_issuer="https://identity.corp.test",
            fabric_client_id="spiffe://agents.corp.test/agent/platform/authz",
            fabric_workload_token_file=tmp_path / "token",
        )
        container = await build_container(settings, http=http)
        assert isinstance(container.decisions.engine, kind)
        assert container.opa is not None
        checks = await container.ready()
        assert checks["database"] is True
        assert ("opa" in checks) is (mode != "shadow")
    await http.aclose()


async def test_rejects_non_ed25519_audit_key(tmp_path: Path) -> None:
    from cryptography.hazmat.primitives.asymmetric import ec

    key_file = tmp_path / "audit.pem"
    key_file.write_bytes(
        ec.generate_private_key(ec.SECP256R1()).private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    settings = make_settings(tmp_path, dev_ephemeral_audit_key=False, audit_key_file=key_file)
    with pytest.raises(ValueError, match="Ed25519"):
        await build_container(settings)


def test_committed_contracts_are_current() -> None:
    assert contracts(["--check"], root=ROOT) == 0


def test_export_and_check_round_trip(tmp_path: Path) -> None:
    assert contracts(["--check"], root=tmp_path) == 1
    assert contracts([], root=tmp_path) == 0
    assert contracts(["--check"], root=tmp_path) == 0
    assert (tmp_path / "schemas" / "decision.request.schema.json").is_file()
    assert (tmp_path / "docs" / "api" / "openapi.json").is_file()
