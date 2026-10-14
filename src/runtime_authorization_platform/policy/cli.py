"""Policy authoring command line.

    authz-policy-test test POLICY TESTS [POLICY TESTS ...]   run policy unit tests
    authz-policy-test catalog ACTIONS                        validate the action catalog
    authz-policy-test rego POLICY [--package rap.authz]      print the policy as Rego

Exit status is 1 when any suite fails or any rule never decides a case.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from agentic_core.policy import PolicySet
from pydantic import ValidationError

from runtime_authorization_platform.domain.models import ActionCatalog
from runtime_authorization_platform.policy import rego
from runtime_authorization_platform.policy.testing import PolicyTestSuite, run_tests


def _test(paths: list[str], *, allow_uncovered: bool) -> int:
    if not paths or len(paths) % 2:
        sys.stderr.write("test expects POLICY TESTS pairs\n")
        return 2
    failed = False
    for policy_path, tests_path in zip(paths[::2], paths[1::2], strict=True):
        policy = PolicySet.from_file(Path(policy_path))
        suite = PolicyTestSuite.from_file(Path(tests_path))
        if suite.policy != policy.name:
            sys.stderr.write(f"{tests_path} targets {suite.policy}, not {policy.name}\n")
            failed = True
            continue
        report = run_tests(policy, suite.cases, require_rule_coverage=not allow_uncovered)
        sys.stdout.write(report.render() + "\n")
        failed = failed or not report.ok
    return 1 if failed else 0


def _catalog(path: str) -> int:
    try:
        catalog = ActionCatalog.from_file(Path(path))
    except ValidationError as exc:
        sys.stderr.write(f"{path}: {exc}\n")
        return 1
    sys.stdout.write(f"{path}: {len(catalog.actions)} actions, version {catalog.version}: OK\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="authz-policy-test")
    commands = parser.add_subparsers(dest="command", required=True)
    test = commands.add_parser("test", help="run policy unit tests")
    test.add_argument("paths", nargs="+", help="POLICY TESTS pairs")
    test.add_argument("--allow-uncovered-rules", action="store_true")
    catalog = commands.add_parser("catalog", help="validate an action catalog")
    catalog.add_argument("path")
    export = commands.add_parser("rego", help="export a policy as Rego")
    export.add_argument("path")
    export.add_argument("--package", default="rap.authz")
    args = parser.parse_args(argv)

    if args.command == "test":
        return _test(args.paths, allow_uncovered=args.allow_uncovered_rules)
    if args.command == "catalog":
        return _catalog(args.path)
    sys.stdout.write(rego.export(PolicySet.from_file(Path(args.path)), package=args.package))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
