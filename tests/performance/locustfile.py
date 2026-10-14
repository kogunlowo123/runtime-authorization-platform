"""Load profile for a deployed platform.

Run against a staging deployment, never production. Tokens come from the
staging Entra ID tenant (client credentials for a gateway app holding
Authz.Decide and an agent app holding Authz.Agent):

    AUTHZ_LOAD_GATEWAY_TOKEN=<token> AUTHZ_LOAD_AGENT_TOKEN=<token> \
    locust -f tests/performance/locustfile.py --host https://authz.staging.corp.internal \
           --users 200 --spawn-rate 20 --run-time 10m --headless

Enforcement points ask for decisions far more often than anything else, so
the mix weights decisions over filtering and intent declaration.
"""

from __future__ import annotations

import os

from locust import HttpUser, between, task

GATEWAY_TOKEN = os.environ.get("AUTHZ_LOAD_GATEWAY_TOKEN", "")
AGENT_TOKEN = os.environ.get("AUTHZ_LOAD_AGENT_TOKEN", "")


class EnforcementTraffic(HttpUser):
    wait_time = between(0.02, 0.2)

    @task(20)
    def decide(self) -> None:
        self.client.post(
            "/v1/decisions",
            json={
                "subject_token": AGENT_TOKEN,
                "action": "documents:read",
                "resource": {"type": "document", "id": "load-test-document"},
                "environment": {"purpose_of_use": "load-test"},
            },
            headers={"Authorization": f"Bearer {GATEWAY_TOKEN}"},
            name="/v1/decisions",
        )

    @task(3)
    def filter_documents(self) -> None:
        self.client.post(
            "/v1/filter",
            json={
                "subject_token": AGENT_TOKEN,
                "action": "documents:read",
                "resource_type": "document",
            },
            headers={"Authorization": f"Bearer {GATEWAY_TOKEN}"},
            name="/v1/filter",
        )

    @task(1)
    def declare_intent(self) -> None:
        self.client.post(
            "/v1/intents",
            json={
                "action": "documents:write",
                "resource_type": "document",
                "resource_id": "load-test-document",
                "justification": "Load test: update the load-test document body.",
                "purpose": "load-test",
            },
            headers={"Authorization": f"Bearer {AGENT_TOKEN}"},
            name="/v1/intents",
        )
