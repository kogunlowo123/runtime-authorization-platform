"""End-to-end flows over HTTP, as agents, gateways, approvers and auditors use the platform."""

from __future__ import annotations

from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient

from runtime_authorization_platform.security.roles import Role
from tests.conftest import (
    AGENT,
    APPROVER,
    AUDITOR,
    AUTHOR,
    GATEWAY,
    POLICY_APPROVER,
    ROOT,
    SECURITY,
    FakeEntra,
    bearer,
)

pytestmark = pytest.mark.e2e


def agent_token(entra: FakeEntra, *scopes: str) -> str:
    return entra.token(AGENT, Role.AGENT, *scopes)


def gateway(entra: FakeEntra) -> dict[str, str]:
    return bearer(entra.token(GATEWAY, Role.DECIDE))


def decide(client: TestClient, entra: FakeEntra, subject_token: str, **body: Any) -> Any:
    response = client.post(
        "/v1/decisions", json={"subject_token": subject_token, **body}, headers=gateway(entra)
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_intent_approval_flow(client: TestClient, entra: FakeEntra) -> None:
    """Intent -> Policy -> Resource -> Authorization -> Decision, with a human in the loop."""
    token = agent_token(entra, "documents:*")
    resource = {"type": "document", "id": "doc-finance"}

    # Deleting requires a declared intent.
    first = decide(client, entra, token, action="documents:delete", resource=resource)
    assert first["decision"] == "deny"
    assert first["stage"] == "control"
    assert first["obligations"] == ["declare_intent"]

    declared = client.post(
        "/v1/intents",
        json={
            "action": "documents:delete",
            "resource_type": "document",
            "resource_id": "doc-finance",
            "justification": "Duplicate vendor contract uploaded twice; removing the copy.",
            "purpose": "records-hygiene",
        },
        headers=bearer(token),
    )
    assert declared.status_code == 201, declared.text
    intent = declared.json()
    assert intent["status"] == "active"
    assert intent["max_uses"] == 1

    # High risk: the policy wants a human-approved intent.
    pending = decide(
        client,
        entra,
        token,
        action="documents:delete",
        resource=resource,
        intent_id=intent["intent_id"],
    )
    assert pending["decision"] == "require_approval"
    assert pending["matched_rules"] == ["approve-high-risk-actions"]
    assert pending["obligations"] == ["approve_intent"]

    # The agent cannot approve its own intent; an approver can.
    own = client.post(f"/v1/intents/{intent['intent_id']}/approve", headers=bearer(token))
    assert own.status_code == 403
    approver = bearer(entra.token(APPROVER, Role.INTENT_APPROVER, scp="user_impersonation"))
    approved = client.post(f"/v1/intents/{intent['intent_id']}/approve", headers=approver)
    assert approved.status_code == 200, approved.text
    assert approved.json()["approved_by"] == APPROVER

    allowed = decide(
        client,
        entra,
        token,
        action="documents:delete",
        resource=resource,
        intent_id=intent["intent_id"],
    )
    assert allowed["decision"] == "allow", allowed
    assert allowed["intent"] == {
        "intent_id": intent["intent_id"],
        "approved": True,
        "uses": 1,
        "max_uses": 1,
    }
    assert allowed["attribute_sources"]["resource"].startswith("pip:static:")

    # Single use: a replay is refused.
    replay = decide(
        client,
        entra,
        token,
        action="documents:delete",
        resource=resource,
        intent_id=intent["intent_id"],
    )
    assert replay["decision"] == "deny"
    assert "consumed" in replay["reason"]

    status = client.get(f"/v1/intents/{intent['intent_id']}", headers=bearer(token))
    assert status.json()["status"] == "consumed"

    # Auditors see every decision with the policy that produced it.
    logs = client.get(
        "/v1/decision-logs",
        params={"subject": AGENT, "action": "documents:delete"},
        headers=bearer(entra.token(AUDITOR, Role.AUDITOR, scp="user_impersonation")),
    )
    assert logs.status_code == 200
    decisions = [item["decision"] for item in logs.json()["items"]]
    assert sorted(decisions) == ["allow", "deny", "deny", "require_approval"]
    assert all(item["caller_id"] == GATEWAY for item in logs.json()["items"])


def test_self_check_is_dry_run(client: TestClient, entra: FakeEntra) -> None:
    token = agent_token(entra, "tickets:*")
    declared = client.post(
        "/v1/intents",
        json={
            "action": "tickets:close",
            "resource_type": "ticket",
            "resource_id": "INC-1",
            "justification": "Customer confirmed the fix in the ticket thread.",
            "purpose": "service-desk",
            "max_uses": 2,
        },
        headers=bearer(token),
    ).json()
    body = {
        "action": "tickets:close",
        "resource": {"type": "ticket", "id": "INC-1"},
        "intent_id": declared["intent_id"],
    }
    for _ in range(3):
        result = client.post("/v1/decisions", json=body, headers=bearer(token)).json()
        assert result["decision"] == "allow"
        assert result["dry_run"] is True
        assert result["intent"]["uses"] == 0


def test_policy_authoring_four_eyes_and_rollback(client: TestClient, entra: FakeEntra) -> None:
    author = bearer(entra.token(AUTHOR, Role.POLICY_AUTHOR, scp="user_impersonation"))
    approver = bearer(entra.token(POLICY_APPROVER, Role.POLICY_APPROVER, scp="user_impersonation"))
    active = client.get("/v1/policies/active", headers=approver).json()
    original_id = active["version_id"]
    assert active["activated_by"] == "bootstrap"

    document = yaml.safe_load((ROOT / "policies" / "runtime-authorization.yaml").read_text())
    tests = yaml.safe_load(
        (ROOT / "policies" / "tests" / "runtime-authorization.tests.yaml").read_text()
    )["cases"]
    # New rule: tickets may never be read on Sundays (weekday 6).
    document["version"] = "2026.10.1"
    document["rules"].insert(
        0,
        {
            "id": "deny-sunday-ticket-reads",
            "effect": "deny",
            "actions": ["tickets:read"],
            "conditions": [{"attribute": "environment.time.weekday", "operator": "eq", "value": 6}],
        },
    )

    # Without a test for the new rule the submission is rejected (rule coverage).
    rejected = client.post(
        "/v1/policies", json={"policy": document, "tests": tests}, headers=author
    )
    assert rejected.status_code == 422
    assert rejected.json()["details"]["uncovered_rules"] == ["deny-sunday-ticket-reads"]

    tests.append(
        {
            "name": "no ticket reads on sunday",
            "subject": {"id": "a", "action_in_scope": True},
            "action": "tickets:read",
            "resource": {"type": "ticket", "id": "t"},
            "environment": {"time": {"weekday": 6}, "intent": {"approved": False}},
            "expect": "deny",
        }
    )
    dry = client.post(
        "/v1/policies/test", json={"policy": document, "tests": tests}, headers=author
    )
    assert dry.json()["ok"] is True

    submitted = client.post(
        "/v1/policies", json={"policy": document, "tests": tests}, headers=author
    )
    assert submitted.status_code == 201, submitted.text
    version_id = submitted.json()["version_id"]
    assert submitted.json()["status"] == "draft"

    # The author holds no activation role; an approver who is also the author is refused.
    assert client.post(f"/v1/policies/{version_id}/activate", headers=author).status_code == 403
    both = bearer(
        entra.token(AUTHOR, Role.POLICY_AUTHOR, Role.POLICY_APPROVER, scp="user_impersonation")
    )
    assert client.post(f"/v1/policies/{version_id}/activate", headers=both).status_code == 403

    activated = client.post(f"/v1/policies/{version_id}/activate", headers=approver)
    assert activated.status_code == 200
    assert activated.json()["status"] == "active"
    assert client.get("/v1/policies/active", headers=approver).json()["version"] == "2026.10.1"

    rego = client.get(f"/v1/policies/{version_id}/rego", headers=approver)
    assert rego.status_code == 200
    assert 'deny_rules contains "deny-sunday-ticket-reads"' in rego.text

    listed = client.get("/v1/policies", headers=approver).json()["items"]
    assert {v["status"] for v in listed} == {"active", "superseded"}

    rolled_back = client.post(f"/v1/policies/{original_id}/activate", headers=approver)
    assert rolled_back.json()["status"] == "active"
    token = agent_token(entra, "documents:read")
    result = decide(
        client,
        entra,
        token,
        action="documents:read",
        resource={"type": "document", "id": "doc-legal"},
    )
    assert result["policy"]["version"] == "2026.10.0"


def test_filter_residual_and_candidates(client: TestClient, entra: FakeEntra) -> None:
    token = agent_token(entra)  # no scopes: only owner and department rules apply
    response = client.post(
        "/v1/filter",
        json={
            "action": "documents:read",
            "resource_type": "document",
            "candidates": [
                {"id": "doc-own"},
                {"id": "doc-finance"},
                {"id": "doc-legal"},
                {"id": "doc-restricted"},
                {"id": "doc-quarantined"},
                {"id": "doc-missing"},
            ],
        },
        headers=bearer(token),
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["allowed_ids"] == ["doc-own", "doc-finance"]
    assert set(body["denied_ids"]) == {
        "doc-legal",
        "doc-restricted",
        "doc-quarantined",
        "doc-missing",
    }
    assert body["residual"]["op"] == "and"
    assert body["never_allowed"] is False

    gateway_view = client.post(
        "/v1/filter",
        json={"action": "payments:execute", "resource_type": "payment", "subject_token": token},
        headers=gateway(entra),
    ).json()
    assert gateway_view["never_allowed"] is True
    assert "intent is required" in gateway_view["reason"]


def test_action_block_kill_switch(client: TestClient, entra: FakeEntra) -> None:
    officer = bearer(entra.token(SECURITY, Role.SECURITY_OFFICER, scp="user_impersonation"))
    token = agent_token(entra, "documents:*")
    resource = {"type": "document", "id": "doc-legal"}
    assert decide(client, entra, token, action="documents:read", resource=resource)["decision"] == (
        "allow"
    )

    blocked = client.post(
        "/v1/action-blocks",
        json={"pattern": "documents:*", "reason": "suspected data exfiltration"},
        headers=officer,
    )
    assert blocked.status_code == 201
    denied = decide(client, entra, token, action="documents:read", resource=resource)
    assert denied["decision"] == "deny"
    assert "suspected data exfiltration" in denied["reason"]

    catalog = client.get("/v1/actions", headers=officer).json()
    assert [b["pattern"] for b in catalog["blocks"]] == ["documents:*"]
    assert len(catalog["actions"]) >= 5

    removed = client.delete(f"/v1/action-blocks/{blocked.json()['block_id']}", headers=officer)
    assert removed.status_code == 200
    assert decide(client, entra, token, action="documents:read", resource=resource)["decision"] == (
        "allow"
    )


def test_revoke_intent(client: TestClient, entra: FakeEntra) -> None:
    token = agent_token(entra)
    intent = client.post(
        "/v1/intents",
        json={
            "action": "email:send",
            "resource_type": "mailbox",
            "resource_id": "*",
            "justification": "Notify suppliers about the revised delivery schedule.",
            "purpose": "supplier-communication",
        },
        headers=bearer(token),
    ).json()
    revoked = client.post(
        f"/v1/intents/{intent['intent_id']}/revoke",
        json={"reason": "task cancelled by the requester"},
        headers=bearer(token),
    )
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"
    again = client.post(
        f"/v1/intents/{intent['intent_id']}/revoke",
        json={"reason": "task cancelled by the requester"},
        headers=bearer(token),
    )
    assert again.status_code == 409


def test_operations_endpoints(client: TestClient) -> None:
    assert client.get("/healthz").json() == {"status": "ok"}
    ready = client.get("/readyz")
    assert ready.status_code == 200
    assert ready.json()["checks"] == {"database": True}
    response = client.get("/healthz", headers={"X-Correlation-ID": "trace-123"})
    assert response.headers["x-correlation-id"] == "trace-123"
    assert response.headers["x-content-type-options"] == "nosniff"
    metrics = client.get("/metrics").text
    assert "authz_http_request_duration_seconds" in metrics
    assert "authz_active_policy_info" in metrics


def test_agent_card(client: TestClient) -> None:
    card = client.get("/.well-known/agent-card.json").json()
    assert card["url"] == "http://testserver/a2a"
    assert {s["id"] for s in card["skills"]} == {"decide", "declare_intent", "filter"}
    assert card["securitySchemes"]["entra"]["type"] == "oauth2"
    assert card["capabilities"]["streaming"] is False


def a2a(client: TestClient, token: str, data: dict[str, Any], **extra: Any) -> Any:
    payload = {
        "jsonrpc": "2.0",
        "id": "req-1",
        "method": "message/send",
        "params": {
            "message": {
                "role": "user",
                "messageId": "m-1",
                "contextId": "ctx-1",
                "parts": [{"kind": "data", "data": data}],
            }
        },
        **extra,
    }
    response = client.post("/a2a", json=payload, headers=bearer(token))
    assert response.status_code == 200, response.text
    return response.json()


def test_a2a_message_send(client: TestClient, entra: FakeEntra) -> None:
    token = agent_token(entra, "documents:read")
    reply = a2a(
        client,
        token,
        {
            "skill": "decide",
            "input": {
                "action": "documents:read",
                "resource": {"type": "document", "id": "doc-legal"},
            },
        },
    )
    message = reply["result"]
    assert message["kind"] == "message"
    assert message["role"] == "agent"
    assert message["contextId"] == "ctx-1"
    result = message["parts"][0]["data"]["result"]
    assert result["decision"] == "allow"
    assert result["dry_run"] is True

    declared = a2a(
        client,
        token,
        {
            "skill": "declare_intent",
            "input": {
                "action": "documents:export",
                "resource_type": "document",
                "resource_id": "doc-finance",
                "justification": "Auditor requested the signed vendor contract as PDF.",
                "purpose": "external-audit",
            },
        },
    )
    assert declared["result"]["parts"][0]["data"]["result"]["status"] == "active"

    filtered = a2a(
        client,
        token,
        {"skill": "filter", "input": {"action": "documents:read", "resource_type": "document"}},
    )
    residual = filtered["result"]["parts"][0]["data"]["result"]
    assert residual["never_allowed"] is False
    assert residual["always_allowed"] is False  # quarantine, purpose and clearance remain

    on_behalf = a2a(
        client,
        entra.token(GATEWAY, Role.DECIDE),
        {
            "skill": "decide",
            "input": {
                "subject_token": token,
                "action": "documents:read",
                "resource": {"type": "document", "id": "doc-legal"},
            },
        },
    )
    assert on_behalf["result"]["parts"][0]["data"]["result"]["subject"] == AGENT


def test_a2a_errors(client: TestClient, entra: FakeEntra) -> None:
    token = agent_token(entra)
    assert a2a(client, token, {"skill": "nope", "input": {}})["error"]["code"] == -32602
    assert a2a(client, token, {"skill": "decide", "input": {"action": "bad"}})["error"]["code"] == (
        -32602
    )
    forbidden = a2a(
        client,
        token,
        {
            "skill": "decide",
            "input": {
                "subject_token": token,
                "action": "documents:read",
                "resource": {"type": "document", "id": "x"},
            },
        },
    )
    assert forbidden["error"]["data"]["error"] == "forbidden"
    wrong_method = client.post(
        "/a2a", json={"jsonrpc": "2.0", "id": 1, "method": "tasks/get"}, headers=bearer(token)
    ).json()
    assert wrong_method["error"]["code"] == -32601
    no_parts = client.post(
        "/a2a",
        json={"jsonrpc": "2.0", "id": 2, "method": "message/send", "params": {}},
        headers=bearer(token),
    ).json()
    assert no_parts["error"]["code"] == -32602
    text_only = a2a(client, token, {"skill": "decide"})
    assert text_only["error"]["code"] == -32602
    bad_version = client.post("/a2a", json={"id": 1}, headers=bearer(token)).json()
    assert bad_version["error"]["code"] == -32600
    bad_id = client.post(
        "/a2a", json={"jsonrpc": "2.0", "id": True, "method": "message/send"}, headers=bearer(token)
    ).json()
    assert bad_id["error"]["code"] == -32600
    garbage = client.post(
        "/a2a",
        content=b"{not json",
        headers={**bearer(token), "Content-Type": "application/json"},
    ).json()
    assert garbage["error"]["code"] == -32700
    assert client.post("/a2a", json={}).status_code == 401


MCP_HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


def mcp(client: TestClient, token: str, method: str, params: dict[str, Any]) -> Any:
    response = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        headers={**MCP_HEADERS, **bearer(token)},
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_mcp_tools(client: TestClient, entra: FakeEntra) -> None:
    token = agent_token(entra, "documents:read")
    init = mcp(
        client,
        token,
        "initialize",
        {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "agent", "version": "1"},
        },
    )
    assert init["result"]["serverInfo"]["name"] == "runtime-authorization-platform"

    tools = {t["name"]: t for t in mcp(client, token, "tools/list", {})["result"]["tools"]}
    assert set(tools) == {"declare_intent", "check_authorization", "filter_resources", "get_intent"}
    assert "outputSchema" in tools["check_authorization"]

    checked = mcp(
        client,
        token,
        "tools/call",
        {
            "name": "check_authorization",
            "arguments": {
                "request": {
                    "action": "documents:read",
                    "resource": {"type": "document", "id": "doc-legal"},
                }
            },
        },
    )["result"]
    assert checked["isError"] is False
    assert checked["structuredContent"]["decision"] == "allow"
    assert checked["structuredContent"]["dry_run"] is True

    declared = mcp(
        client,
        token,
        "tools/call",
        {
            "name": "declare_intent",
            "arguments": {
                "request": {
                    "action": "records:update",
                    "resource_type": "record",
                    "resource_id": "rec-77",
                    "justification": "Correct the cost centre that was keyed incorrectly.",
                    "purpose": "finance-close",
                }
            },
        },
    )["result"]["structuredContent"]
    fetched = mcp(
        client,
        token,
        "tools/call",
        {"name": "get_intent", "arguments": {"intent_id": declared["intent_id"]}},
    )["result"]["structuredContent"]
    assert fetched["status"] == "active"

    other = entra.token("agent-oid-other", Role.AGENT)
    stolen = mcp(
        client,
        other,
        "tools/call",
        {"name": "get_intent", "arguments": {"intent_id": declared["intent_id"]}},
    )["result"]
    assert stolen["isError"] is True
    assert "forbidden" in stolen["content"][0]["text"]

    filtered = mcp(
        client,
        token,
        "tools/call",
        {
            "name": "filter_resources",
            "arguments": {"request": {"action": "documents:read", "resource_type": "document"}},
        },
    )["result"]["structuredContent"]
    assert filtered["never_allowed"] is False
    assert filtered["policy"]["name"] == "runtime-authorization"

    no_role = entra.token("app-oid-unprivileged")
    refused = mcp(
        client,
        no_role,
        "tools/call",
        {
            "name": "check_authorization",
            "arguments": {
                "request": {"action": "documents:read", "resource": {"type": "document", "id": "x"}}
            },
        },
    )["result"]
    assert refused["isError"] is True


def test_mcp_requires_bearer(client: TestClient) -> None:
    response = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        headers=MCP_HEADERS,
    )
    assert response.status_code == 401
    assert response.headers["www-authenticate"].startswith("Bearer")
    bogus = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        headers={**MCP_HEADERS, "Authorization": "Bearer not-a-jwt"},
    )
    assert bogus.status_code == 401
