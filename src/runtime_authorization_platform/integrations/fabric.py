"""Typed client for agent-identity-fabric (github.com/kogunlowo123/agent-identity-fabric).

Wire formats follow the fabric's OAuth endpoints: RFC 7523 jwt-bearer at
``/oauth2/token``, RFC 7662 introspection at ``/oauth2/introspect``, and the
policy decision endpoint ``/v1/authorize``.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
from agentic_core.domain.classification import DataClassification, Decision
from pydantic import BaseModel, ConfigDict, ValidationError

from runtime_authorization_platform.domain.errors import (
    AuthzError,
    FabricUnavailableError,
    UnauthorizedError,
)

JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"


class IssuedToken(BaseModel):
    model_config = ConfigDict(frozen=True)

    access_token: str
    # RFC 6750 token type name, not a credential.
    token_type: str = "Bearer"  # noqa: S105
    expires_in: int
    scope: str = ""


class Actor(BaseModel):
    model_config = ConfigDict(frozen=True)

    sub: str
    act: Actor | None = None

    def subjects(self) -> list[str]:
        return [self.sub, *(self.act.subjects() if self.act else [])]


class Introspection(BaseModel):
    model_config = ConfigDict(frozen=True)

    active: bool
    sub: str | None = None
    scope: str | None = None
    exp: int | None = None
    iat: int | None = None
    jti: str | None = None
    iss: str | None = None
    aud: str | None = None
    act: Actor | None = None
    agent_status: str | None = None


class FabricDecision(BaseModel):
    model_config = ConfigDict(frozen=True)

    decision: Decision
    agent: str
    action: str
    resource: str
    matched_rules: tuple[str, ...] = ()
    policy_version: str = ""
    policy_digest: str = ""
    reason: str = ""
    delegation_chain: tuple[str, ...] = ()


class FabricClient:
    def __init__(self, base_url: str, *, http: httpx.AsyncClient) -> None:
        self._base = base_url.rstrip("/")
        self._http = http

    async def _post(self, path: str, **kwargs: Any) -> dict[str, Any]:
        try:
            response = await self._http.post(f"{self._base}{path}", **kwargs)
        except httpx.HTTPError as exc:
            raise FabricUnavailableError(f"identity fabric: {type(exc).__name__}") from exc
        if response.status_code >= 500:
            raise FabricUnavailableError(f"identity fabric returned HTTP {response.status_code}")
        try:
            body = response.json()
        except ValueError as exc:
            raise FabricUnavailableError("identity fabric returned a non-JSON body") from exc
        if not isinstance(body, dict):
            raise FabricUnavailableError("identity fabric returned an unexpected document")
        if response.status_code == 401:
            raise UnauthorizedError(str(body.get("error_description", "fabric rejected token")))
        if response.status_code >= 400:
            raise AuthzError(
                f"identity fabric: {body.get('error', 'error')}: "
                f"{body.get('error_description', '')}".strip()
            )
        return body

    async def token(
        self, client_id: str, assertion: str, *, scope: str | None = None
    ) -> IssuedToken:
        """RFC 7523 jwt-bearer grant: workload token in, agent credential out."""
        data = {"grant_type": JWT_BEARER, "client_id": client_id, "assertion": assertion}
        if scope:
            data["scope"] = scope
        body = await self._post("/oauth2/token", data=data)
        return self._parse(IssuedToken, body)

    async def introspect(self, token: str) -> Introspection:
        body = await self._post("/oauth2/introspect", data={"token": token})
        return self._parse(Introspection, body)

    async def authorize(
        self,
        token: str,
        *,
        action: str,
        resource_type: str,
        resource_id: str = "*",
        classification: DataClassification = DataClassification.INTERNAL,
        attributes: dict[str, Any] | None = None,
        environment: dict[str, Any] | None = None,
    ) -> FabricDecision:
        body = await self._post(
            "/v1/authorize",
            json={
                "action": action,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "resource_classification": int(classification),
                "resource_attributes": attributes or {},
                "environment": environment or {},
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        return self._parse(FabricDecision, body)

    @staticmethod
    def _parse[M: BaseModel](model: type[M], body: dict[str, Any]) -> M:
        try:
            return model.model_validate(body)
        except ValidationError as exc:
            raise FabricUnavailableError(
                f"identity fabric response did not match {model.__name__}"
            ) from exc


class FabricTokenProvider:
    """This service's own agent credential, for calls to PIPs that require one.

    Exchanges the projected workload token (re-read on every refresh, because
    the kubelet rotates it) for a fabric credential, cached until shortly
    before it expires.
    """

    def __init__(
        self,
        client: FabricClient,
        *,
        client_id: str,
        workload_token_file: Path,
        scope: str | None = None,
        refresh_margin: timedelta = timedelta(seconds=60),
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._client = client
        self._client_id = client_id
        self._file = workload_token_file
        self._scope = scope
        self._margin = refresh_margin
        self._clock = clock
        self._token: str | None = None
        self._expires_at = datetime.min.replace(tzinfo=UTC)
        self._lock = asyncio.Lock()

    async def __call__(self) -> str:
        async with self._lock:
            if self._token is None or self._clock() >= self._expires_at - self._margin:
                assertion = (
                    await asyncio.to_thread(self._file.read_text, encoding="utf-8")
                ).strip()
                issued = await self._client.token(self._client_id, assertion, scope=self._scope)
                self._token = issued.access_token
                self._expires_at = self._clock() + timedelta(seconds=issued.expires_in)
            return self._token
