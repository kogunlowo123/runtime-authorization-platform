"""Policy authoring: submit with tests, review, activate (four-eyes), roll back.

A policy version is stored only when its own unit tests pass and every rule
decides at least one case. Activation is a separate act by a different
principal. Rolling back is activating an earlier version. Replicas pick up the
active version within ``refresh_s`` seconds.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from agentic_core.domain.identifiers import new_id
from agentic_core.policy import PolicySet
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from runtime_authorization_platform.application.audit import Auditor
from runtime_authorization_platform.domain.errors import (
    ConflictError,
    ForbiddenError,
    InvalidPolicyError,
    NotFoundError,
    PolicyTestFailureError,
)
from runtime_authorization_platform.domain.models import PolicyStatus, PolicyVersion
from runtime_authorization_platform.domain.ports import Clock, PolicyRepository
from runtime_authorization_platform.observability.metrics import AuthzMetrics
from runtime_authorization_platform.policy.engines import PolicyHolder
from runtime_authorization_platform.policy.testing import (
    PolicyTestCase,
    PolicyTestReport,
    PolicyTestSuite,
    run_tests,
)

BOOTSTRAP_ACTOR = "bootstrap"


class SubmitPolicy(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    policy: dict[str, Any] = Field(description="agentic-core policy set: name, version, rules")
    tests: tuple[PolicyTestCase, ...] = Field(min_length=1, max_length=2000)


def parse_policy(document: dict[str, Any]) -> PolicySet:
    try:
        return PolicySet.model_validate(document)
    except ValidationError as exc:
        raise InvalidPolicyError(
            "policy document is invalid",
            details=[
                {"loc": list(e.get("loc", ())), "msg": str(e.get("msg", ""))} for e in exc.errors()
            ],
        ) from exc


class PolicyAdministration:
    def __init__(
        self,
        *,
        repository: PolicyRepository,
        holder: PolicyHolder,
        auditor: Auditor,
        clock: Clock,
        metrics: AuthzMetrics,
        require_rule_coverage: bool = True,
        refresh_s: float = 5.0,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._repo = repository
        self._holder = holder
        self._auditor = auditor
        self._clock = clock
        self._metrics = metrics
        self._coverage = require_rule_coverage
        self._refresh_s = refresh_s
        self._monotonic = monotonic
        self._checked_at: float | None = None

    @property
    def holder(self) -> PolicyHolder:
        return self._holder

    def test(self, command: SubmitPolicy) -> PolicyTestReport:
        return run_tests(
            parse_policy(command.policy), command.tests, require_rule_coverage=self._coverage
        )

    async def submit(self, command: SubmitPolicy, *, actor: str) -> PolicyVersion:
        policy = parse_policy(command.policy)
        report = run_tests(policy, command.tests, require_rule_coverage=self._coverage)
        if not report.ok:
            await self._auditor.record(
                actor=actor,
                action="policy.submit",
                resource=f"policy:{policy.name}",
                outcome="rejected",
                details={"digest": policy.digest, **report.summary()},
            )
            raise PolicyTestFailureError(
                "policy tests failed", details=report.model_dump(mode="json")
            )
        version = PolicyVersion(
            version_id=new_id(),
            name=policy.name,
            version=policy.version,
            digest=policy.digest,
            status=PolicyStatus.DRAFT,
            document=policy.model_dump(mode="json"),
            tests=[case.model_dump(mode="json") for case in command.tests],
            test_summary=report.summary(),
            author=actor,
            created_at=self._clock.now(),
        )
        await self._repo.add(version)
        await self._auditor.record(
            actor=actor,
            action="policy.submit",
            resource=f"policy:{policy.name}",
            outcome="success",
            details={
                "version_id": version.version_id,
                "version": policy.version,
                "digest": policy.digest,
                **report.summary(),
            },
        )
        return version

    async def activate(self, version_id: str, *, actor: str) -> PolicyVersion:
        candidate = await self.get(version_id)
        if actor == candidate.author and actor != BOOTSTRAP_ACTOR:
            raise ForbiddenError("a policy version cannot be activated by its author")
        policy = parse_policy(candidate.document)
        activated = await self._repo.activate(version_id, actor=actor, at=self._clock.now())
        self._install(policy)
        self._metrics.policy_activations.inc()
        await self._auditor.record(
            actor=actor,
            action="policy.activate",
            resource=f"policy:{policy.name}",
            outcome="success",
            details={
                "version_id": version_id,
                "version": policy.version,
                "digest": policy.digest,
                "author": candidate.author,
            },
        )
        return activated

    def _install(self, policy: PolicySet) -> None:
        self._metrics.active_policy.clear()
        self._metrics.active_policy.labels(policy.name, policy.version, policy.digest).set(1)
        self._holder.replace(policy)
        self._checked_at = self._monotonic()

    async def get(self, version_id: str) -> PolicyVersion:
        version = await self._repo.get(version_id)
        if version is None:
            raise NotFoundError(f"policy version {version_id} not found")
        return version

    async def list(self, *, limit: int, offset: int) -> Sequence[PolicyVersion]:
        return await self._repo.list(limit=limit, offset=offset)

    async def active(self) -> PolicyVersion:
        version = await self._repo.active()
        if version is None:
            raise NotFoundError("no active policy version")
        return version

    async def refresh(self, *, force: bool = False) -> None:
        """Converge on the active version another replica may have activated."""
        now = self._monotonic()
        if not force and self._checked_at is not None and now - self._checked_at < self._refresh_s:
            return
        self._checked_at = now
        active = await self._repo.active()
        if active is not None and active.digest != self._holder.digest:
            self._install(parse_policy(active.document))

    async def bootstrap(self, policy_file: Path, tests_file: Path) -> PolicyVersion:
        """First start: install the reviewed policy from the repository. Later starts load the
        active version from the database, which is the source of truth from then on."""
        active = await self._repo.active()
        if active is not None:
            self._install(parse_policy(active.document))
            return active
        suite = PolicyTestSuite.from_file(tests_file)
        policy = PolicySet.from_file(policy_file)
        try:
            submitted = await self.submit(
                SubmitPolicy(policy=policy.model_dump(mode="json"), tests=suite.cases),
                actor=BOOTSTRAP_ACTOR,
            )
        except ConflictError:
            # Another replica bootstrapped the same document first; converge on it.
            existing = await self._repo.by_digest(policy.digest)
            if existing is None:  # pragma: no cover - conflict implies the row exists
                raise
            submitted = existing
        return await self.activate(submitted.version_id, actor=BOOTSTRAP_ACTOR)
