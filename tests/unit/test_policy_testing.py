"""Policy unit-test runner and the authz-policy-test command line."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from agentic_core.domain.classification import Decision
from agentic_core.policy import PolicySet, Rule

from runtime_authorization_platform.policy.cli import main
from runtime_authorization_platform.policy.testing import PolicyTestCase, PolicyTestSuite, run_tests
from tests.conftest import ROOT

POLICY = ROOT / "policies" / "runtime-authorization.yaml"
TESTS = ROOT / "policies" / "tests" / "runtime-authorization.tests.yaml"


def test_shipped_suites_pass_with_full_coverage() -> None:
    for policy_file, tests_file in [
        (POLICY, TESTS),
        (
            ROOT / "policies" / "service-access.yaml",
            ROOT / "policies" / "tests" / "service-access.tests.yaml",
        ),
    ]:
        policy = PolicySet.from_file(policy_file)
        report = run_tests(policy, PolicyTestSuite.from_file(tests_file).cases)
        assert report.ok, report.render()
        assert report.uncovered_rules == ()


def test_failures_and_coverage_are_reported() -> None:
    policy = PolicySet(
        name="p",
        version="1",
        rules=(
            Rule(id="allow-read", effect=Decision.ALLOW, actions=("*:read",)),
            Rule(id="deny-delete", effect=Decision.DENY, actions=("*:delete",)),
        ),
    )
    cases = (
        PolicyTestCase(name="read ok", action="docs:read", expect=Decision.ALLOW),
        PolicyTestCase(
            name="wrong expectation",
            action="docs:write",
            expect=Decision.ALLOW,
            expect_rules=("x",),
        ),
        PolicyTestCase(
            name="bad classification",
            action="docs:read",
            resource={"type": "doc", "classification": 9},
            expect=Decision.ALLOW,
        ),
    )
    report = run_tests(policy, cases)
    assert report.total == 3
    assert report.passed == 1
    assert report.failed == 2
    assert report.uncovered_rules == ("deny-delete",)
    assert report.ok is False
    rendered = report.render()
    assert "FAIL wrong expectation: expected allow, got deny" in rendered
    assert "expected rules ['x'], got []" in rendered
    assert "invalid case" in rendered
    assert report.summary()["uncovered_rules"] == ["deny-delete"]
    relaxed = run_tests(policy, cases[:1], require_rule_coverage=False)
    assert relaxed.ok is True


def test_cli_test_command(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["test", str(POLICY), str(TESTS)]) == 0
    assert "OK" in capsys.readouterr().out
    assert main(["test", str(POLICY)]) == 2


def test_cli_rejects_mismatched_suite(tmp_path: Path) -> None:
    suite = tmp_path / "other.yaml"
    suite.write_text(
        yaml.safe_dump(
            {"policy": "other", "cases": [{"name": "abc", "action": "a:b", "expect": "deny"}]}
        )
    )
    assert main(["test", str(POLICY), str(suite)]) == 1


def test_cli_failing_suite(tmp_path: Path) -> None:
    suite = tmp_path / "fail.yaml"
    suite.write_text(
        yaml.safe_dump(
            {
                "policy": "runtime-authorization",
                "cases": [{"name": "always", "action": "a:b", "expect": "allow"}],
            }
        )
    )
    assert main(["test", str(POLICY), str(suite)]) == 1
    assert main(["test", "--allow-uncovered-rules", str(POLICY), str(suite)]) == 1


def test_cli_catalog(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["catalog", str(ROOT / "policies" / "actions.yaml")]) == 0
    bad = tmp_path / "actions.yaml"
    bad.write_text(yaml.safe_dump({"version": "1", "actions": [{"pattern": "BAD", "risk": 1}]}))
    assert main(["catalog", str(bad)]) == 1
    assert "actions" in capsys.readouterr().err


def test_cli_rego(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["rego", str(POLICY), "--package", "corp.authz"]) == 0
    assert "package corp.authz" in capsys.readouterr().out
