"""Authorization of callers to the platform's own operations.

Fabric-issued agent credentials are authorized by the agent identity fabric
(``/v1/authorize``), which knows the agent's scopes, delegation chain and
status. Entra ID principals are authorized by the local agentic-core
PolicyEngine over ``policies/service-access.yaml``. Both are deny by default;
there is no "allow all" path.
"""

from __future__ import annotations

from agentic_core.domain.classification import Decision
from agentic_core.policy import PolicyEngine, PolicyRequest, Resource, Subject

from runtime_authorization_platform.domain.errors import ForbiddenError
from runtime_authorization_platform.domain.models import Principal
from runtime_authorization_platform.integrations.fabric import FabricClient
from runtime_authorization_platform.security.authn import Authenticator
from runtime_authorization_platform.security.roles import Operation

SERVICE_RESOURCE = "runtime-authorization"


class ServiceAccess:
    def __init__(
        self,
        policy: PolicyEngine,
        *,
        authenticator: Authenticator,
        fabric: FabricClient | None = None,
    ) -> None:
        self._policy = policy
        self._authn = authenticator
        self._fabric = fabric

    @property
    def policy(self) -> PolicyEngine:
        return self._policy

    async def check(self, principal: Principal, token: str, operation: Operation) -> bool:
        if self._fabric is not None and self._authn.is_fabric_principal(principal):
            decision = await self._fabric.authorize(
                token,
                action=operation.action,
                resource_type=SERVICE_RESOURCE,
                resource_id=operation.value,
            )
            return decision.decision is Decision.ALLOW
        result = self._policy.evaluate(
            PolicyRequest(
                subject=Subject(
                    id=principal.id,
                    kind=principal.kind.value,
                    roles=principal.roles,
                    attributes={
                        "tenant": principal.tenant,
                        "delegated": principal.delegated,
                        "app_id": principal.app_id,
                    },
                ),
                action=operation.action,
                resource=Resource(type=SERVICE_RESOURCE, id=operation.value),
            )
        )
        return result.decision is Decision.ALLOW

    async def require(self, principal: Principal, token: str, operation: Operation) -> None:
        if not await self.check(principal, token, operation):
            raise ForbiddenError(f"not permitted to perform {operation.action}")
