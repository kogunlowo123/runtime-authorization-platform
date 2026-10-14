"""Decision engines: the local agentic-core engine, OPA, and their combinations.

``local``     agentic-core PolicyEngine over the active policy version.
``opa``       Open Policy Agent decides; the local policy is not consulted.
``combined``  both decide; the most restrictive outcome wins.
``shadow``    local decides; OPA is evaluated alongside and disagreements are
              counted, for migrations between the two.

Every external failure fails closed (DENY), except in shadow mode where OPA
is advisory.
"""

from __future__ import annotations

from collections.abc import Callable
from enum import StrEnum
from typing import Any, Protocol

from agentic_core.domain.classification import Decision
from agentic_core.observability import get_logger
from agentic_core.policy import PolicyEngine, PolicyRequest, PolicySet
from pydantic import BaseModel, ConfigDict

from runtime_authorization_platform.domain.errors import OpaUnavailableError
from runtime_authorization_platform.integrations.opa import UNDEFINED, OpaClient

log = get_logger("runtime_authorization_platform.engines")

_SEVERITY = {Decision.ALLOW: 0, Decision.REQUIRE_APPROVAL: 1, Decision.DENY: 2}


class EngineMode(StrEnum):
    LOCAL = "local"
    OPA = "opa"
    COMBINED = "combined"
    SHADOW = "shadow"


class EngineResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    decision: Decision
    matched_rules: tuple[str, ...]
    policy_name: str
    policy_version: str
    policy_digest: str
    reason: str
    engine: str


class PolicyHolder:
    """Holds the active policy and its compiled engine; swapped atomically on activation."""

    def __init__(self, policy: PolicySet) -> None:
        self._engine = PolicyEngine(policy)

    @property
    def policy(self) -> PolicySet:
        return self._engine.policy

    @property
    def digest(self) -> str:
        return self.policy.digest

    @property
    def engine(self) -> PolicyEngine:
        return self._engine

    def replace(self, policy: PolicySet) -> None:
        self._engine = PolicyEngine(policy)


class DecisionEngine(Protocol):
    mode: EngineMode

    async def evaluate(self, request: PolicyRequest) -> EngineResult: ...

    def local_policy(self) -> PolicySet | None:
        """The policy usable for partial evaluation, or None when OPA has a say."""
        ...


class LocalEngine:
    mode = EngineMode.LOCAL

    def __init__(self, holder: PolicyHolder) -> None:
        self._holder = holder

    async def evaluate(self, request: PolicyRequest) -> EngineResult:
        decision = self._holder.engine.evaluate(request)
        return EngineResult(
            decision=decision.decision,
            matched_rules=decision.matched_rules,
            policy_name=decision.policy_name,
            policy_version=decision.policy_version,
            policy_digest=decision.policy_digest,
            reason=decision.reason,
            engine="local",
        )

    def local_policy(self) -> PolicySet | None:
        return self._holder.policy


def interpret_opa_result(result: Any, *, path: str) -> EngineResult:
    """Map an OPA decision document to an EngineResult.

    Accepted shapes: ``true``/``false``; ``{"allow": bool, "require_approval": bool}``;
    or the full shape produced by ``policy.rego.export``
    (``{"decision": ..., "matched_rules": [...], "policy_*": ...}``).
    Anything else (including an undefined result) is a deny.
    """
    base: dict[str, Any] = {
        "matched_rules": (),
        "policy_name": f"opa:{path}",
        "policy_version": "",
        "policy_digest": "",
        "engine": "opa",
    }
    if result is UNDEFINED or result is None:
        return EngineResult(decision=Decision.DENY, reason="OPA result undefined", **base)
    if isinstance(result, bool):
        decision = Decision.ALLOW if result else Decision.DENY
        return EngineResult(decision=decision, reason=f"OPA returned {result}", **base)
    if isinstance(result, dict):
        rules = result.get("matched_rules", ())
        if isinstance(rules, list | tuple) and all(isinstance(r, str) for r in rules):
            base["matched_rules"] = tuple(sorted(rules))
        for key in ("policy_name", "policy_version", "policy_digest"):
            if isinstance(result.get(key), str):
                base[key] = result[key]
        raw = result.get("decision")
        if isinstance(raw, str) and raw in {d.value for d in Decision}:
            return EngineResult(decision=Decision(raw), reason=f"OPA decided {raw}", **base)
        if isinstance(result.get("allow"), bool):
            if result["allow"] and result.get("require_approval") is True:
                return EngineResult(
                    decision=Decision.REQUIRE_APPROVAL, reason="OPA requires approval", **base
                )
            decision = Decision.ALLOW if result["allow"] else Decision.DENY
            return EngineResult(decision=decision, reason="OPA allow document", **base)
    return EngineResult(decision=Decision.DENY, reason="OPA result has no decision", **base)


class OpaEngine:
    mode = EngineMode.OPA

    def __init__(self, client: OpaClient) -> None:
        self._client = client

    async def evaluate(self, request: PolicyRequest) -> EngineResult:
        result = await self._client.evaluate(request.facts())
        return interpret_opa_result(result, path=self._client.decision_path)

    def local_policy(self) -> PolicySet | None:
        return None


def most_restrictive(first: EngineResult, second: EngineResult) -> EngineResult:
    winner, other = (
        (first, second)
        if _SEVERITY[first.decision] >= _SEVERITY[second.decision]
        else (second, first)
    )
    return winner.model_copy(
        update={
            "engine": "combined",
            "reason": f"{winner.engine}: {winner.reason}; {other.engine}: {other.reason}",
            "matched_rules": (
                *winner.matched_rules,
                *(r for r in other.matched_rules if r not in winner.matched_rules),
            ),
        }
    )


class CombinedEngine:
    mode = EngineMode.COMBINED

    def __init__(self, local: LocalEngine, opa: OpaEngine) -> None:
        self._local = local
        self._opa = opa

    async def evaluate(self, request: PolicyRequest) -> EngineResult:
        local = await self._local.evaluate(request)
        external = await self._opa.evaluate(request)
        return most_restrictive(local, external)

    def local_policy(self) -> PolicySet | None:
        return None


class ShadowEngine:
    mode = EngineMode.SHADOW

    def __init__(
        self,
        local: LocalEngine,
        opa: OpaEngine,
        on_outcome: Callable[[str], None],
    ) -> None:
        self._local = local
        self._opa = opa
        self._on_outcome = on_outcome

    async def evaluate(self, request: PolicyRequest) -> EngineResult:
        local = await self._local.evaluate(request)
        try:
            external = await self._opa.evaluate(request)
        except OpaUnavailableError as exc:
            log.warning("shadow_opa_unavailable", error=exc.message)
            self._on_outcome("error")
            return local
        if external.decision is local.decision:
            self._on_outcome("match")
        else:
            self._on_outcome("mismatch")
            log.warning(
                "shadow_decision_mismatch",
                action=request.action,
                resource_type=request.resource.type,
                local=local.decision.value,
                opa=external.decision.value,
            )
        return local

    def local_policy(self) -> PolicySet | None:
        return self._local.local_policy()
