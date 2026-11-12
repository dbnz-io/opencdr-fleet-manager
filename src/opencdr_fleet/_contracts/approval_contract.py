"""P4 review bindings. Internal contract, not yet a deployed authorization boundary.

Actor/grant/target facts must come from authenticated owner adapters, never from
client claims. Existing rollout execution will consume these bindings; this
module does not introduce a second worker or authorize a runtime mutation.
"""

import re
from copy import deepcopy

from .case_contract import CaseError
from .case_store import digest
from .detection_query import canonical

VERSION = "1.0.0"
OPERATIONS = frozenset(
    {
        "rule.write",
        "list.write",
        "release.apply",
        "configuration.write",
        "package.apply",
        "response.execute",
    }
)
PERMISSIONS = frozenset({"mutate", "approve", "response", "policy_admin", "emergency"})


class ApprovalError(CaseError):
    pass


def require(condition, code, status=400):
    if not condition:
        raise ApprovalError(code, status)


def integer(value, minimum=0, maximum=9007199254740991):
    require(type(value) is int and minimum <= value <= maximum, "invalid_approval_integer")
    return value


def text(value, maximum=256):
    require(
        isinstance(value, str) and 0 < len(value) <= maximum and value.strip() == value,
        "invalid_approval_text",
    )
    return value


def checksum(value):
    require(
        isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value), "invalid_approval_digest"
    )
    return value


def actor(value):
    text(value)
    require(
        re.fullmatch(
            r"(?:human:[a-f0-9]{64}|aws(?:-us-gov|-cn)?:[0-9]{12}:(?:AROA|AIDA)[A-Z0-9]{12,64})",
            value,
        ),
        "invalid_approval_actor",
    )
    return value


def actors(values):
    require(isinstance(values, list) and 1 <= len(values) <= 100, "invalid_approval_reviewers")
    result = [actor(v) for v in values]
    require(len(set(result)) == len(result), "duplicate_approval_actor")
    return sorted(result)


def policy(value):
    require(
        isinstance(value, dict)
        and set(value)
        == {
            "reviewers",
            "allow_self_if_sole",
            "emergency_actors",
            "max_lifetime_seconds",
            "operations",
        },
        "invalid_review_policy",
    )
    result = deepcopy(value)
    result["reviewers"] = actors(value["reviewers"])
    require(type(value["allow_self_if_sole"]) is bool, "invalid_review_policy")
    emergency = value["emergency_actors"]
    require(isinstance(emergency, list), "invalid_review_policy")
    result["emergency_actors"] = actors(emergency) if emergency else []
    integer(value["max_lifetime_seconds"], 60, 86400)
    operations = value["operations"]
    require(
        isinstance(operations, list) and operations and all(isinstance(x, str) for x in operations),
        "invalid_review_operations",
    )
    require(
        set(operations) <= OPERATIONS and len(set(operations)) == len(operations),
        "invalid_review_operations",
    )
    result["operations"] = sorted(operations)
    return result


def plan(value):
    require(
        isinstance(value, dict)
        and set(value)
        == {"operation", "content_sha256", "dependencies_sha256", "targets", "response_required"},
        "invalid_approval_plan",
    )
    require(
        isinstance(value["operation"], str) and value["operation"] in OPERATIONS,
        "invalid_review_operation",
    )
    checksum(value["content_sha256"])
    checksum(value["dependencies_sha256"])
    require(type(value["response_required"]) is bool, "invalid_approval_plan")
    require(
        value["operation"] != "response.execute" or value["response_required"],
        "response_authority_required",
        403,
    )
    targets = value["targets"]
    require(isinstance(targets, list) and 1 <= len(targets) <= 100, "invalid_approval_targets")
    names = []
    for target in targets:
        require(
            isinstance(target, dict)
            and set(target)
            == {"target_id", "registration_rev", "snapshot_sha256", "expected_revisions"},
            "invalid_approval_target",
        )
        names.append(text(target["target_id"]))
        integer(target["registration_rev"])
        checksum(target["snapshot_sha256"])
        revisions = target["expected_revisions"]
        require(
            isinstance(revisions, dict) and 1 <= len(revisions) <= 100, "invalid_approval_revisions"
        )
        for key, rev in revisions.items():
            text(key)
            integer(rev)
    require(len(set(names)) == len(names), "duplicate_approval_target")
    result = {**deepcopy(value), "targets": sorted(deepcopy(targets), key=lambda x: x["target_id"])}
    require(len(canonical(result).encode()) <= 64000, "approval_plan_too_large", 413)
    return result


def grant(value, expected_actor, permission, now, target_ids=(), *, operation=None):
    require(
        isinstance(value, dict) and value.get("actor") == expected_actor,
        "approval_authority_unavailable",
        403,
    )
    actor(expected_actor)
    integer(value.get("revision"), 1)
    integer(value.get("expires_at"), 1)
    require(
        value.get("enabled") is True and value["expires_at"] > now,
        "approval_authority_expired_or_revoked",
        403,
    )
    permissions = value.get("permissions")
    require(
        isinstance(permissions, (list, set, frozenset)) and permission in permissions,
        "approval_permission_denied",
        403,
    )
    if operation is not None:
        operations = value.get("operations")
        require(
            isinstance(operations, (list, set, frozenset)) and operation in operations,
            "approval_operation_scope_denied",
            403,
        )
    scopes = value.get("target_ids")
    require(
        isinstance(scopes, (list, set, frozenset)) and set(target_ids) <= set(scopes),
        "approval_target_scope_denied",
        403,
    )
    # No user-controlled wildcard expands a reviewed target snapshot.
    return {
        "actor": expected_actor,
        "revision": value["revision"],
        "expires_at": value["expires_at"],
        **(
            {"identity_sha256": checksum(value["identity_sha256"])}
            if "identity_sha256" in value
            else {}
        ),
    }


def binding(owner, proposal, proposer, proposer_grant, review_policy, policy_revision, expires_at):
    return {
        "schema_version": VERSION,
        "owner": text(owner),
        "plan": plan(proposal),
        "proposer": actor(proposer),
        "proposer_grant": deepcopy(proposer_grant),
        "policy_revision": integer(policy_revision, 1),
        "policy_sha256": digest(policy(review_policy)),
        "expires_at": integer(expires_at, 1),
    }
