"""Open Policy Agent REST API client (Data API and Policy API)."""

from __future__ import annotations

from typing import Any

import httpx

from runtime_authorization_platform.domain.errors import OpaUnavailableError

UNDEFINED: Any = object()


class OpaClient:
    """Evaluates decisions through ``POST /v1/data/<path>`` with ``{"input": ...}``.

    Any transport error, non-2xx status or non-JSON body raises
    ``OpaUnavailableError``; callers fail closed.
    """

    def __init__(
        self,
        base_url: str,
        *,
        http: httpx.AsyncClient,
        decision_path: str = "rap/authz/result",
        bearer_token: str | None = None,
        timeout_s: float = 2.0,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._http = http
        self._path = decision_path.strip("/")
        self._headers = {"Authorization": f"Bearer {bearer_token}"} if bearer_token else {}
        self._timeout = timeout_s

    @property
    def decision_path(self) -> str:
        return self._path

    async def evaluate(self, input_document: dict[str, Any]) -> Any:
        """Return the decision document, or ``UNDEFINED`` when the rule is undefined."""
        try:
            response = await self._http.post(
                f"{self._base}/v1/data/{self._path}",
                json={"input": input_document},
                headers=self._headers,
                timeout=self._timeout,
            )
        except httpx.HTTPError as exc:
            raise OpaUnavailableError(f"OPA request failed: {type(exc).__name__}") from exc
        if response.status_code >= 400:
            raise OpaUnavailableError(f"OPA returned HTTP {response.status_code}")
        try:
            body = response.json()
        except ValueError as exc:
            raise OpaUnavailableError("OPA returned a non-JSON body") from exc
        if not isinstance(body, dict):
            raise OpaUnavailableError("OPA returned an unexpected document")
        return body.get("result", UNDEFINED)

    async def put_policy(self, policy_id: str, rego: str) -> None:
        """Load or replace a Rego module through the Policy API."""
        try:
            response = await self._http.put(
                f"{self._base}/v1/policies/{policy_id}",
                content=rego.encode(),
                headers={**self._headers, "Content-Type": "text/plain"},
            )
        except httpx.HTTPError as exc:
            raise OpaUnavailableError(f"OPA request failed: {type(exc).__name__}") from exc
        if response.status_code >= 400:
            raise OpaUnavailableError(f"OPA rejected policy: HTTP {response.status_code}")

    async def healthy(self) -> bool:
        try:
            response = await self._http.get(f"{self._base}/health", headers=self._headers)
        except httpx.HTTPError:
            return False
        return response.status_code == 200
