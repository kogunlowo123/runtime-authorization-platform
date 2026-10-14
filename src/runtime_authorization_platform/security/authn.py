"""Caller and subject authentication.

A bearer token is routed by its (unverified) ``iss``: tokens from the agent
identity fabric are validated by fabric introspection, which applies the
fabric's revocation and credential-epoch checks; every other token must be a
valid Entra ID access token. Nothing is trusted before validation succeeds.
"""

from __future__ import annotations

import hashlib
import time
from collections import OrderedDict
from collections.abc import Callable
from datetime import UTC, datetime

import jwt

from runtime_authorization_platform.domain.errors import UnauthorizedError
from runtime_authorization_platform.domain.models import Principal, PrincipalKind
from runtime_authorization_platform.integrations.fabric import FabricClient
from runtime_authorization_platform.security.entra import EntraIdValidator


def bearer_token(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise UnauthorizedError("bearer token required")
    token = authorization[7:].strip()
    if not token:
        raise UnauthorizedError("bearer token required")
    return token


class Authenticator:
    def __init__(
        self,
        entra: EntraIdValidator,
        *,
        fabric: FabricClient | None = None,
        fabric_issuer: str | None = None,
        introspection_cache_s: float = 10.0,
        max_cache_entries: int = 10_000,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._entra = entra
        self._fabric = fabric
        self._fabric_issuer = fabric_issuer.rstrip("/") if fabric_issuer else None
        self._cache_s = introspection_cache_s
        self._max = max_cache_entries
        self._clock = clock
        self._monotonic = monotonic
        self._cache: OrderedDict[str, tuple[Principal, float]] = OrderedDict()

    @property
    def fabric_issuer(self) -> str | None:
        return self._fabric_issuer

    def is_fabric_principal(self, principal: Principal) -> bool:
        return self._fabric_issuer is not None and principal.issuer == self._fabric_issuer

    async def authenticate(self, token: str) -> Principal:
        try:
            issuer = str(jwt.decode(token, options={"verify_signature": False}).get("iss", ""))
        except jwt.PyJWTError as exc:
            raise UnauthorizedError("malformed token") from exc
        if self._fabric_issuer is not None and issuer.rstrip("/") == self._fabric_issuer:
            return await self._fabric_principal(token)
        return await self._entra.validate(token)

    async def _fabric_principal(self, token: str) -> Principal:
        if self._fabric is None:  # pragma: no cover - configuration validator requires both
            raise UnauthorizedError("identity fabric is not configured")
        key = hashlib.sha256(token.encode()).hexdigest()
        cached = self._cache.get(key)
        now_mono = self._monotonic()
        if cached is not None:
            principal, at = cached
            if now_mono - at < self._cache_s and self._clock() < principal.expires_at:
                return principal
            self._cache.pop(key, None)
        result = await self._fabric.introspect(token)
        if not result.active or not result.sub or result.exp is None:
            raise UnauthorizedError("agent credential is not active")
        expires_at = datetime.fromtimestamp(result.exp, UTC)
        if self._clock() >= expires_at:
            raise UnauthorizedError("agent credential expired")
        principal = Principal(
            id=result.sub,
            kind=PrincipalKind.AGENT,
            issuer=self._fabric_issuer or "",
            scopes=frozenset((result.scope or "").split()),
            delegation_chain=tuple(result.act.subjects()) if result.act else (),
            token_id=result.jti,
            expires_at=expires_at,
        )
        if self._cache_s > 0:
            self._cache[key] = (principal, now_mono)
            while len(self._cache) > self._max:
                self._cache.popitem(last=False)
        return principal
