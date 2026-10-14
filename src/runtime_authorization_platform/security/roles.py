"""Entra ID app roles and the service operations they gate.

Roles are defined on the platform's Entra app registration and granted to
applications (agents, gateways) or users (approvers, auditors). Which role
may perform which operation is policy, not code: see
``policies/service-access.yaml``.
"""

from __future__ import annotations

from enum import StrEnum


class Role:
    DECIDE = "Authz.Decide"  # policy enforcement points (gateways) requesting decisions
    AGENT = "Authz.Agent"  # agents declaring intents and checking their own access
    POLICY_AUTHOR = "Authz.PolicyAuthor"  # submit and test policy versions
    POLICY_APPROVER = "Authz.PolicyApprover"  # activate policy versions (four-eyes)
    INTENT_APPROVER = "Authz.IntentApprover"  # approve high-risk declared intents
    SECURITY_OFFICER = "Authz.SecurityOfficer"  # block and unblock actions, revoke intents
    AUDITOR = "Authz.Auditor"  # read decision logs, policies and intents


class Operation(StrEnum):
    """Service operations.

    Each is checked as action ``authz:<operation>`` on resource type ``runtime-authorization``.
    """

    DECIDE = "decide"
    DECIDE_SELF = "decide:self"
    FILTER = "filter"
    INTENT_DECLARE = "intent:declare"
    INTENT_READ = "intent:read"
    INTENT_APPROVE = "intent:approve"
    INTENT_REVOKE = "intent:revoke"
    POLICY_SUBMIT = "policy:submit"
    POLICY_ACTIVATE = "policy:activate"
    POLICY_READ = "policy:read"
    DECISION_LOG_READ = "decision-log:read"
    ACTION_READ = "action:read"
    ACTION_BLOCK = "action:block"

    @property
    def action(self) -> str:
        return f"authz:{self.value}"
