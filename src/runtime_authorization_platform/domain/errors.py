"""Domain errors mapped to HTTP status codes (and JSON-RPC errors) by the API layer."""

from __future__ import annotations

from typing import Any


class AuthzError(Exception):
    code = "invalid_request"
    status = 400

    def __init__(self, message: str, *, details: Any = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details


class NotFoundError(AuthzError):
    code = "not_found"
    status = 404


class ConflictError(AuthzError):
    code = "conflict"
    status = 409


class InvalidStateError(AuthzError):
    code = "invalid_state"
    status = 409


class UnauthorizedError(AuthzError):
    code = "unauthorized"
    status = 401


class ForbiddenError(AuthzError):
    code = "forbidden"
    status = 403


class InvalidPolicyError(AuthzError):
    code = "invalid_policy"
    status = 400


class PolicyTestFailureError(AuthzError):
    code = "policy_tests_failed"
    status = 422


class IntentRejectedError(AuthzError):
    code = "intent_rejected"
    status = 422


class DependencyUnavailableError(AuthzError):
    """A dependency needed to reach a safe outcome is unavailable; the caller should retry."""

    code = "temporarily_unavailable"
    status = 503


class PipUnavailableError(DependencyUnavailableError):
    code = "attribute_source_unavailable"


class OpaUnavailableError(DependencyUnavailableError):
    code = "policy_engine_unavailable"


class FabricUnavailableError(DependencyUnavailableError):
    code = "identity_fabric_unavailable"
