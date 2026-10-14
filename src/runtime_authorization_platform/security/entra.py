"""Microsoft Entra ID access-token validation.

Validates v2.0 (``https://login.microsoftonline.com/<tid>/v2.0``) and,
optionally, v1.0 (``https://sts.windows.net/<tid>/``) access tokens issued
for this API:

* ``alg`` must be RS256 and ``kid`` present (no ``none``, no HMAC confusion);
* the signing key is looked up only in the JWKS (``/discovery/v2.0/keys``) of
  allowed tenants, so a token cannot make the service fetch arbitrary key
  sets, and no claim is read before the signature is verified;
* ``tid`` must be an allowed tenant and ``iss`` must match it;
  ``aud`` must be one of the configured audiences;
* ``exp``, ``nbf`` and ``iat`` against the injected clock with bounded skew;
* ``oid`` is required and becomes the principal id;
* optional allow list of client application ids (``azp``/``appid``).

App-only tokens (``idtyp: app``, or no ``scp``) become SERVICE principals, or
AGENT principals when they hold the ``Authz.Agent`` app role; their app roles
double as scopes. Delegated (user) tokens use ``scp``.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import jwt

from runtime_authorization_platform.domain.errors import UnauthorizedError
from runtime_authorization_platform.domain.models import Principal, PrincipalKind
from runtime_authorization_platform.security.jwks import KeyResolver, RemoteJwks
from runtime_authorization_platform.security.roles import Role


class EntraIdValidator:
    def __init__(
        self,
        *,
        tenants: frozenset[str],
        audiences: frozenset[str],
        http: httpx.AsyncClient,
        authority: str = "https://login.microsoftonline.com",
        accept_v1_tokens: bool = True,
        allowed_client_ids: frozenset[str] = frozenset(),
        resolvers: Mapping[str, KeyResolver] | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        leeway: timedelta = timedelta(seconds=60),
    ) -> None:
        if not tenants or not audiences:
            raise ValueError("at least one tenant and one audience are required")
        self._tenants = frozenset(t.lower() for t in tenants)
        self._audiences = audiences
        self._authority = authority.rstrip("/")
        self._accept_v1 = accept_v1_tokens
        self._clients = allowed_client_ids
        self._clock = clock
        self._leeway = leeway
        self._resolvers: dict[str, KeyResolver] = {
            t.lower(): r for t, r in (resolvers or {}).items()
        }
        for tenant in self._tenants:
            self._resolvers.setdefault(
                tenant,
                RemoteJwks(f"{self._authority}/{tenant}/discovery/v2.0/keys", client=http),
            )

    def issuers_for(self, tenant: str) -> set[str]:
        issuers = {f"{self._authority}/{tenant}/v2.0"}
        if self._accept_v1:
            issuers.add(f"https://sts.windows.net/{tenant}/")
        return issuers

    async def validate(self, token: str) -> Principal:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise UnauthorizedError("malformed token") from exc
        if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
            raise UnauthorizedError("token algorithm or key id not accepted")
        key = await self._key(header["kid"])
        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                key=key,
                algorithms=["RS256"],
                audience=list(self._audiences),
                options={
                    "require": ["exp", "iat", "iss", "aud", "oid", "tid"],
                    "verify_exp": False,  # checked below against the injected clock
                    "verify_nbf": False,
                    "verify_iat": False,
                },
            )
        except jwt.PyJWTError as exc:
            raise UnauthorizedError(f"token rejected: {type(exc).__name__}") from exc
        tenant = str(claims["tid"]).lower()
        if tenant not in self._tenants:
            raise UnauthorizedError("tenant not allowed")
        if claims["iss"] not in self.issuers_for(tenant):
            raise UnauthorizedError("issuer does not match tenant")
        now = self._clock()
        expires_at = self._time(claims, "exp")
        if now >= expires_at + self._leeway:
            raise UnauthorizedError("token expired")
        if "nbf" in claims and now + self._leeway < self._time(claims, "nbf"):
            raise UnauthorizedError("token not yet valid")
        if now + self._leeway < self._time(claims, "iat"):
            raise UnauthorizedError("token issued in the future")
        client_id = claims.get("azp") or claims.get("appid")
        if self._clients and client_id not in self._clients:
            raise UnauthorizedError("client application not allowed")
        return self._principal(claims, tenant, expires_at, client_id)

    async def _key(self, kid: str) -> Any:
        """Find ``kid`` in the JWKS of an allowed tenant.

        Only allowed tenants' key sets are ever fetched, and nothing in the
        token is read before its signature is verified; tenant and issuer are
        checked on the verified claims.
        """
        last: UnauthorizedError | None = None
        for tenant in sorted(self._tenants):
            try:
                return await self._resolvers[tenant].key_for(kid)
            except UnauthorizedError as exc:
                last = exc
        raise last or UnauthorizedError(f"unknown signing key {kid!r}")

    @staticmethod
    def _time(claims: dict[str, Any], name: str) -> datetime:
        value = claims.get(name)
        if not isinstance(value, int | float) or isinstance(value, bool):
            raise UnauthorizedError(f"invalid {name} claim")
        return datetime.fromtimestamp(value, UTC)

    @staticmethod
    def _principal(
        claims: dict[str, Any], tenant: str, expires_at: datetime, client_id: Any
    ) -> Principal:
        raw_roles = claims.get("roles", [])
        roles = frozenset(
            r for r in (raw_roles if isinstance(raw_roles, list) else []) if isinstance(r, str)
        )
        scp = claims.get("scp")
        app_only = claims.get("idtyp") == "app" or not isinstance(scp, str)
        if app_only:
            kind = PrincipalKind.AGENT if Role.AGENT in roles else PrincipalKind.SERVICE
            scopes = roles
        else:
            kind = PrincipalKind.USER
            scopes = frozenset(str(scp).split())
        token_id = claims.get("uti") or claims.get("jti")
        return Principal(
            id=str(claims["oid"]),
            kind=kind,
            issuer=str(claims["iss"]),
            tenant=tenant,
            app_id=str(client_id) if client_id else None,
            roles=roles,
            scopes=scopes,
            token_id=str(token_id) if token_id else None,
            expires_at=expires_at,
        )
