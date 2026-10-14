"""Policy unit tests: authored next to every policy and run in CI and on submission.

A suite is a list of cases, each a complete decision request with the expected
decision (and optionally the rules expected to decide it). A suite passes only
when every case passes and, by default, every rule in the policy decided at
least one case, so no rule ships unexercised.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from agentic_core.domain.classification import DataClassification, Decision, RiskLevel
from agentic_core.policy import PolicyEngine, PolicyRequest, PolicySet, Resource, Subject
from pydantic import BaseModel, ConfigDict, Field, computed_field


class PolicyTestCase(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(min_length=3, max_length=200)
    subject: dict[str, Any] = Field(default_factory=dict)
    action: str = Field(min_length=1, max_length=200)
    resource: dict[str, Any] = Field(default_factory=lambda: {"type": "resource"})
    risk: RiskLevel = RiskLevel.LOW
    environment: dict[str, Any] = Field(default_factory=dict)
    expect: Decision
    expect_rules: tuple[str, ...] | None = None

    def request(self) -> PolicyRequest:
        subject = dict(self.subject)
        resource = dict(self.resource)
        classification = resource.pop("classification", DataClassification.INTERNAL)
        return PolicyRequest(
            subject=Subject(
                id=str(subject.pop("id", "test-subject")),
                kind=str(subject.pop("kind", "agent")),
                roles=frozenset(subject.pop("roles", ())),
                attributes=subject,
            ),
            action=self.action,
            resource=Resource(
                type=str(resource.pop("type", "resource")),
                id=str(resource.pop("id", "*")),
                classification=DataClassification(int(classification)),
                attributes=resource,
            ),
            risk=self.risk,
            environment=self.environment,
        )


class PolicyTestSuite(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    policy: str = Field(description="Name of the policy set the suite targets")
    cases: tuple[PolicyTestCase, ...] = Field(min_length=1)

    @classmethod
    def from_file(cls, path: Path) -> PolicyTestSuite:
        return cls.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))


class CaseResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    passed: bool
    expected: Decision
    actual: Decision
    matched_rules: tuple[str, ...]
    message: str


class PolicyTestReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    policy_name: str
    policy_version: str
    policy_digest: str
    total: int
    passed: int
    failed: int
    uncovered_rules: tuple[str, ...]
    coverage_required: bool
    results: tuple[CaseResult, ...]

    @computed_field  # type: ignore[prop-decorator]
    @property
    def ok(self) -> bool:
        return self.failed == 0 and not (self.coverage_required and self.uncovered_rules)

    def summary(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "passed": self.passed,
            "failed": self.failed,
            "uncovered_rules": list(self.uncovered_rules),
            "ok": self.ok,
        }

    def render(self) -> str:
        lines = [f"policy {self.policy_name} {self.policy_version} ({self.policy_digest})"]
        for result in self.results:
            mark = "PASS" if result.passed else "FAIL"
            lines.append(f"  {mark} {result.name}: {result.message}")
        if self.uncovered_rules:
            lines.append(f"  rules never decisive: {', '.join(self.uncovered_rules)}")
        lines.append(f"{self.passed}/{self.total} passed; {'OK' if self.ok else 'FAILED'}")
        return "\n".join(lines)


def run_tests(
    policy: PolicySet, cases: tuple[PolicyTestCase, ...], *, require_rule_coverage: bool = True
) -> PolicyTestReport:
    engine = PolicyEngine(policy)
    results: list[CaseResult] = []
    decisive: set[str] = set()
    for case in cases:
        try:
            decision = engine.evaluate(case.request())
        except (ValueError, TypeError) as exc:
            results.append(
                CaseResult(
                    name=case.name,
                    passed=False,
                    expected=case.expect,
                    actual=Decision.DENY,
                    matched_rules=(),
                    message=f"invalid case: {exc}",
                )
            )
            continue
        decisive.update(decision.matched_rules)
        problems: list[str] = []
        if decision.decision is not case.expect:
            problems.append(f"expected {case.expect.value}, got {decision.decision.value}")
        if case.expect_rules is not None and set(case.expect_rules) != set(decision.matched_rules):
            problems.append(
                f"expected rules {sorted(case.expect_rules)}, got {sorted(decision.matched_rules)}"
            )
        results.append(
            CaseResult(
                name=case.name,
                passed=not problems,
                expected=case.expect,
                actual=decision.decision,
                matched_rules=decision.matched_rules,
                message="; ".join(problems) or f"{decision.decision.value} ({decision.reason})",
            )
        )
    passed = sum(1 for r in results if r.passed)
    return PolicyTestReport(
        policy_name=policy.name,
        policy_version=policy.version,
        policy_digest=policy.digest,
        total=len(results),
        passed=passed,
        failed=len(results) - passed,
        uncovered_rules=tuple(r.id for r in policy.rules if r.id not in decisive),
        coverage_required=require_rule_coverage,
        results=tuple(results),
    )
