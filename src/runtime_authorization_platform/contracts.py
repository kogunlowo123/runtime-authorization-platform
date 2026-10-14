"""Export published contracts: JSON Schemas for inputs/outputs and the OpenAPI document.

python -m runtime_authorization_platform.contracts            # rewrite schemas/ and docs/api/
python -m runtime_authorization_platform.contracts --check    # exit 1 if committed files are stale
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel

from runtime_authorization_platform.api.app import create_app
from runtime_authorization_platform.api.schemas import (
    DecisionRequest,
    FilterRequest,
    IntentView,
    PolicyVersionView,
)
from runtime_authorization_platform.application.decisions import DecisionResult, FilterResult
from runtime_authorization_platform.application.intents import DeclareIntent
from runtime_authorization_platform.application.policies import SubmitPolicy
from runtime_authorization_platform.domain.models import ActionCatalog, DecisionRecord
from runtime_authorization_platform.policy.testing import PolicyTestReport, PolicyTestSuite

MODELS: dict[str, type[BaseModel]] = {
    "decision.request": DecisionRequest,
    "decision.response": DecisionResult,
    "filter.request": FilterRequest,
    "filter.response": FilterResult,
    "intent.request": DeclareIntent,
    "intent.response": IntentView,
    "policy-submission.request": SubmitPolicy,
    "policy-version.response": PolicyVersionView,
    "policy-test-report.response": PolicyTestReport,
    "policy-test-suite": PolicyTestSuite,
    "action-catalog": ActionCatalog,
    "decision-log.record": DecisionRecord,
}


async def _no_container() -> Any:  # pragma: no cover - never started
    raise RuntimeError("contract export does not start the application")


def documents() -> dict[str, dict[str, Any]]:
    docs: dict[str, dict[str, Any]] = {
        f"schemas/{name}.schema.json": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": (
                "https://github.com/kogunlowo123/runtime-authorization-platform/"
                f"schemas/{name}.schema.json"
            ),
            **model.model_json_schema(mode="serialization" if "response" in name else "validation"),
        }
        for name, model in MODELS.items()
    }
    app: FastAPI = create_app(_no_container, enable_mcp=False)
    docs["docs/api/openapi.json"] = app.openapi()
    return docs


def render(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def main(argv: list[str] | None = None, root: Path | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    base = root or Path.cwd()
    stale: list[str] = []
    for relative, document in documents().items():
        path = base / relative
        content = render(document)
        if "--check" in args:
            if not path.exists() or path.read_text(encoding="utf-8") != content:
                stale.append(relative)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8", newline="\n")
    if stale:
        sys.stderr.write(
            "stale contracts (run python -m runtime_authorization_platform.contracts): "
            + ", ".join(stale)
            + "\n"
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
