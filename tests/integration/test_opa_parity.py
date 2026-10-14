"""Decision parity between the local engine and a real OPA running the exported Rego.

Runs when AUTHZ_TEST_OPA_URL points at an OPA server, e.g. http://localhost:8181
(CI starts openpolicyagent/opa; locally: ``opa run --server``).
"""

from __future__ import annotations

import os
from itertools import product
from typing import Any

import httpx
import pytest
from agentic_core.domain.classification import DataClassification, Decision, RiskLevel
from agentic_core.policy import PolicyEngine, PolicyRequest, PolicySet, Resource, Subject

from runtime_authorization_platform.integrations.opa import OpaClient
from runtime_authorization_platform.policy import rego
from runtime_authorization_platform.policy.engines import OpaEngine
from tests.conftest import ROOT

URL = os.environ.get("AUTHZ_TEST_OPA_URL", "")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not URL, reason="OPA not configured"),
]


def requests() -> list[PolicyRequest]:
    subjects = [
        {"action_in_scope": True, "delegated": False, "department": "finance"},
        {"action_in_scope": False, "delegated": False, "department": "finance"},
        {"action_in_scope": True, "delegated": True},
        {"action_in_scope": False},
    ]
    resources: list[dict[str, Any]] = [
        {},
        {"owner": "agent-1"},
        {"department": "finance"},
        {"department": "legal", "quarantined": True},
        {"quarantined": False, "owner": "someone"},
    ]
    environments = [
        {"intent": {"declared": False, "approved": False}},
        {"intent": {"declared": True, "approved": True}, "purpose_of_use": "audit"},
        {"intent": {"declared": True, "approved": False}, "purpose_of_use": "audit"},
    ]
    actions = ["documents:read", "documents:write", "documents:delete", "payments:execute"]
    out = []
    for subject, attrs, env, action, cls, risk in product(
        subjects,
        resources,
        environments,
        actions,
        [1, 2, 3],
        [RiskLevel.LOW, RiskLevel.HIGH, RiskLevel.CRITICAL],
    ):
        out.append(
            PolicyRequest(
                subject=Subject(id="agent-1", attributes=subject),
                action=action,
                resource=Resource(
                    type="document",
                    id="d",
                    classification=DataClassification(cls),
                    attributes=attrs,
                ),
                risk=risk,
                environment=env,
            )
        )
    return out


@pytest.mark.parametrize("policy_file", ["runtime-authorization.yaml", "service-access.yaml"])
async def test_exported_rego_matches_local_engine(policy_file: str) -> None:
    policy = PolicySet.from_file(ROOT / "policies" / policy_file)
    package = "rap." + policy.name.replace("-", "_")
    async with httpx.AsyncClient(timeout=10) as http:
        client = OpaClient(URL, http=http, decision_path=package.replace(".", "/") + "/result")
        await client.put_policy(policy.name, rego.export(policy, package=package))
        assert await client.healthy()
        local = PolicyEngine(policy)
        opa = OpaEngine(client)
        cases = requests()
        if policy_file == "service-access.yaml":
            cases = [
                PolicyRequest(
                    subject=Subject(
                        id="u", roles=frozenset({role}), attributes={"delegated": delegated}
                    ),
                    action=f"authz:{op}",
                    resource=Resource(type="runtime-authorization", id=op),
                )
                for role, delegated, op in product(
                    [
                        "Authz.Decide",
                        "Authz.Agent",
                        "Authz.PolicyApprover",
                        "Authz.Auditor",
                        "none",
                    ],
                    [True, False],
                    [
                        "decide",
                        "decide:self",
                        "policy:activate",
                        "decision-log:read",
                        "action:block",
                    ],
                )
            ]
        mismatches = []
        for request in cases:
            expected = local.evaluate(request)
            actual = await opa.evaluate(request)
            if expected.decision is not actual.decision or set(expected.matched_rules) != set(
                actual.matched_rules
            ):
                mismatches.append(
                    (request.model_dump(mode="json"), expected.decision, actual.decision)
                )
        assert not mismatches, mismatches[:3]
        assert actual.policy_digest == policy.digest
        assert len(cases) > 30


async def test_undefined_package_is_denied() -> None:
    async with httpx.AsyncClient(timeout=10) as http:
        engine = OpaEngine(OpaClient(URL, http=http, decision_path="rap/does/not/exist"))
        result = await engine.evaluate(
            PolicyRequest(
                subject=Subject(id="a"), action="documents:read", resource=Resource(type="d")
            )
        )
    assert result.decision is Decision.DENY
