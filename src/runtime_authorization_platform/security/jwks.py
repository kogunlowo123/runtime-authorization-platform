"""JWKS key resolution with caching and rate-limited refresh."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any, Protocol

import httpx
import jwt

from runtime_authorization_platform.domain.errors import UnauthorizedError


class KeyResolver(Protocol):
    async def key_for(self, kid: str) -> Any: ...


def _parse(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
        raise ValueError("not a JWKS document")
    keys: dict[str, Any] = {}
    for entry in document["keys"]:
        if isinstance(entry, dict) and isinstance(entry.get("kid"), str):
            try:
                keys[entry["kid"]] = jwt.PyJWK(entry).key
            except jwt.PyJWTError:
                continue  # unsupported key types are skipped, not fatal
    return keys


class StaticJwks:
    """Resolver backed by a JWKS document supplied in configuration or tests."""

    def __init__(self, jwks: dict[str, Any]) -> None:
        self._keys = _parse(jwks)

    async def key_for(self, kid: str) -> Any:
        key = self._keys.get(kid)
        if key is None:
            raise UnauthorizedError(f"unknown signing key {kid!r}")
        return key


class RemoteJwks:
    """Fetches a JWKS URL, caches it, and refreshes once on an unknown ``kid``.

    Refreshes are rate limited so tokens with random ``kid`` values cannot be
    used to hammer the identity provider. Entra ID rolls keys without notice,
    so an unknown kid triggers a refresh (at most every ``min_refresh_interval_s``).
    """

    def __init__(
        self,
        url: str,
        *,
        client: httpx.AsyncClient,
        ttl_s: float = 3600.0,
        min_refresh_interval_s: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._url = url
        self._client = client
        self._ttl = ttl_s
        self._min_refresh = min_refresh_interval_s
        self._clock = clock
        self._keys: dict[str, Any] = {}
        self._fetched_at: float | None = None

    async def _refresh(self) -> None:
        response = await self._client.get(self._url)
        response.raise_for_status()
        self._keys = _parse(response.json())
        self._fetched_at = self._clock()

    async def key_for(self, kid: str) -> Any:
        now = self._clock()
        stale = self._fetched_at is None or now - self._fetched_at > self._ttl
        may_refresh = self._fetched_at is None or now - self._fetched_at >= self._min_refresh
        if stale or (kid not in self._keys and may_refresh):
            try:
                await self._refresh()
            except (httpx.HTTPError, ValueError) as exc:
                if kid not in self._keys:
                    raise UnauthorizedError("cannot fetch signing keys") from exc
        key = self._keys.get(kid)
        if key is None:
            raise UnauthorizedError(f"unknown signing key {kid!r}")
        return key
