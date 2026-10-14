"""Service metrics exposed on /metrics in Prometheus text format."""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram


class AuthzMetrics:
    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        self.registry = registry or CollectorRegistry()
        self.requests = Histogram(
            "authz_http_request_duration_seconds",
            "HTTP request latency",
            ["method", "route", "status"],
            registry=self.registry,
            buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5),
        )
        self.decisions = Counter(
            "authz_decisions_total",
            "Authorization decisions",
            ["decision", "stage", "engine"],
            registry=self.registry,
        )
        self.decision_latency = Histogram(
            "authz_decision_duration_seconds",
            "Time to reach a decision, including attribute lookups",
            registry=self.registry,
            buckets=(0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25),
        )
        self.intents = Counter(
            "authz_intent_events_total",
            "Intent lifecycle events",
            ["event"],
            registry=self.registry,
        )
        self.pip_lookups = Counter(
            "authz_pip_lookups_total",
            "Policy information point lookups by cache outcome",
            ["entity_type", "outcome"],
            registry=self.registry,
        )
        self.opa_shadow = Counter(
            "authz_opa_shadow_comparisons_total",
            "Shadow-mode comparisons between the local engine and OPA",
            ["outcome"],
            registry=self.registry,
        )
        self.policy_activations = Counter(
            "authz_policy_activations_total",
            "Policy versions activated",
            registry=self.registry,
        )
        self.active_policy = Gauge(
            "authz_active_policy_info",
            "Active policy version (value is always 1)",
            ["name", "version", "digest"],
            registry=self.registry,
        )
        self.filters = Counter(
            "authz_filter_requests_total",
            "List-filtering requests by mode",
            ["mode"],
            registry=self.registry,
        )
        self.protocol_calls = Counter(
            "authz_protocol_calls_total",
            "MCP tool calls and A2A requests",
            ["protocol", "operation", "outcome"],
            registry=self.registry,
        )
        self.maintenance = Gauge(
            "authz_maintenance_rows_last",
            "Rows affected by the last maintenance sweep",
            ["task"],
            registry=self.registry,
        )
