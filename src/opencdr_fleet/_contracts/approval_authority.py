"""Owner-local approval grants and atomic authority fences.

The owner adapter authenticates its administrator callback. Every grant change
atomically advances the owner epoch, fencing eligibility changes without a
transaction per possible reviewer. Grants do not independently prove execution.
"""

import json
import time
from copy import deepcopy

from .approval_contract import OPERATIONS, PERMISSIONS, actor, integer, require, text
from .approval_store import Reviews
from .case_contract import CaseError, identifier
from .case_store import Cases, digest, wire
from .detection_query import canonical


class ApprovalGrants(Cases):
    def __init__(self, client, table, owner, principal, administrator, *, clock=time.time):
        super().__init__(client, table, None, "", actor(principal), [], None)
        self.owner, self.administrator, self.clock = text(owner), administrator, clock
        self.namespace = digest(owner)
        self.partition = "REVIEW_GRANT#" + self.namespace

    def configure(self, subject, value, *, expected_rev, request_id, reason):
        actor(subject)
        integer(expected_rev)
        identifier(request_id)
        text(reason, 1000)
        self.check_access()
        require(self.administrator(self.actor) is True, "approval_grant_admin_required", 403)
        require(
            isinstance(value, dict)
            and set(value) == {"enabled", "expires_at", "permissions", "target_ids", "operations"},
            "invalid_approval_grant",
        )
        require(type(value["enabled"]) is bool, "invalid_approval_grant")
        integer(value["expires_at"], 1)
        require(
            not value["enabled"] or value["expires_at"] > self.clock(), "approval_grant_expired"
        )
        operations = value["operations"]
        require(
            isinstance(operations, list)
            and all(isinstance(x, str) for x in operations)
            and set(operations) <= OPERATIONS
            and len(set(operations)) == len(operations),
            "invalid_approval_operations",
        )
        permissions, targets = value["permissions"], value["target_ids"]
        require(
            isinstance(permissions, list)
            and all(isinstance(x, str) for x in permissions)
            and set(permissions) <= PERMISSIONS
            and len(set(permissions)) == len(permissions),
            "invalid_approval_permissions",
        )
        require(isinstance(targets, list) and len(targets) <= 100, "invalid_approval_targets")
        for target in targets:
            text(target)
        require(len(set(targets)) == len(targets), "duplicate_approval_target")
        normalized = {
            **deepcopy(value),
            "permissions": sorted(permissions),
            "operations": sorted(operations),
            "target_ids": sorted(targets),
        }
        body = {
            "subject": subject,
            "grant": normalized,
            "expected_rev": expected_rev,
            "reason": reason,
        }
        key = {
            "pk": "REVIEW_GRANT_REQUEST#" + self.namespace + "#" + digest(self.actor),
            "sk": request_id,
        }
        prior = self.get(**key)
        if prior:
            require(prior["request_sha256"] == digest(body), "approval_grant_request_conflict", 409)
            return {"grant": prior["result"], "idempotent": True}
        old = self.get(self.partition, subject)
        require(
            (int(old["revision"]) if old else 0) == expected_rev,
            "approval_grant_revision_conflict",
            409,
        )
        epoch = self.get(self.partition, "EPOCH")
        revision = int(epoch["revision"]) if epoch else 0
        grant = {
            "owner": self.owner,
            "actor": subject,
            "revision": expected_rev + 1,
            "updated_by": self.actor,
            "updated_at": int(self.clock()),
            **normalized,
        }
        epoch_row = {
            "pk": self.partition,
            "sk": "EPOCH",
            "owner": self.owner,
            "revision": revision + 1,
        }
        row = {"pk": self.partition, "sk": subject, **grant}
        self.check_access()
        require(self.administrator(self.actor) is True, "approval_grant_admin_required", 403)
        require(
            not grant["enabled"] or grant["expires_at"] > self.clock(), "approval_grant_expired"
        )
        try:
            self.transact(
                [
                    self.put(epoch_row, "revision = :rev", {":rev": revision})
                    if epoch
                    else self.put(epoch_row),
                    self.put(row, "revision = :rev", {":rev": expected_rev})
                    if old
                    else self.put(row),
                    self.put({**key, "request_sha256": digest(body), "result": grant}),
                    self.put(
                        {
                            "pk": "REVIEW_GRANT_AUDIT#" + self.namespace + "#" + digest(subject),
                            "sk": f"{grant['revision']:016d}",
                            "owner": self.owner,
                            "actor": self.actor,
                            "reason": reason,
                            "at": int(self.clock()),
                            "before": old,
                            "after": grant,
                        }
                    ),
                ]
            )
        except CaseError:
            prior = self.get(**key)
            if prior:
                require(
                    prior["request_sha256"] == digest(body), "approval_grant_request_conflict", 409
                )
                return {"grant": prior["result"], "idempotent": True}
            raise
        return {"grant": grant, "idempotent": False}


class OwnerAuthority:
    """Fresh owner grant snapshot. One instance per request, never a shared cache."""

    def __init__(self, client, table, owner, *, clock=time.time):
        self.reader = Cases(client, table, None, "", "", [], None)
        self.owner, self.clock = text(owner), clock
        self.partition = "REVIEW_GRANT#" + digest(owner)
        self.epoch = None
        self.observed = {}
        self.identity_epoch = None
        self.identity_used = False

    def begin(self):
        self.epoch = self.reader.get(self.partition, "EPOCH")
        require(
            self.epoch is not None and self.epoch.get("owner") == self.owner,
            "approval_authority_not_configured",
            403,
        )
        self.observed = {}
        self.identity_epoch = self.reader.get("IDENTITY_AUTHORITY", "EPOCH")
        self.identity_used = False

    def __call__(self, principal):
        require(self.epoch is not None, "approval_authority_snapshot_required", 403)
        actor(principal)
        row = self.reader.get(self.partition, principal)
        if row is None:
            return None
        require(
            row.get("owner") == self.owner and row.get("actor") == principal,
            "approval_authority_owner_mismatch",
            403,
        )
        # DynamoDB number values must pass the strict approval contract as integers.
        value = json.loads(canonical(row))
        if principal.startswith("human:") and value["enabled"]:
            from .delegation import actor_id

            self.identity_used = True
            require(self.identity_epoch is not None, "approval_identity_epoch_required", 403)
            subject = self.reader.get("IDENTITY_SUBJECT", principal)
            issuer = self.reader.get("IDENTITY_ISSUER", subject["issuer"]) if subject else None
            if not subject or not issuer or not subject.get("enabled") or not issuer.get("enabled"):
                return {**value, "enabled": False}
            require(
                subject.get("actor") == principal
                and issuer.get("issuer") == subject.get("issuer")
                and issuer.get("tenant") == subject.get("tenant")
                and actor_id(subject["issuer"], subject["tenant"], subject["subject"]) == principal,
                "approval_identity_binding_mismatch",
                403,
            )
            value["target_ids"] = sorted(set(value["target_ids"]) & set(subject["agent_ids"]))
            value["identity_sha256"] = digest(
                {
                    "issuer": subject["issuer"],
                    "issuer_rev": int(issuer["rev"]),
                    "actor": principal,
                    "subject_rev": int(subject["rev"]),
                }
            )
        if value["enabled"] and value["expires_at"] > self.clock():
            self.observed[principal] = value
        return value

    def fences(self):
        require(self.epoch is not None, "approval_authority_snapshot_required", 403)
        current = self.reader.get(self.partition, "EPOCH")
        require(current == self.epoch, "approval_authority_changed", 409)
        require(
            all(
                not row["enabled"] or row["expires_at"] > self.clock()
                for row in self.observed.values()
            ),
            "approval_authority_expired_or_revoked",
            403,
        )
        identity_fences = []
        if self.identity_used:
            current_identity = self.reader.get("IDENTITY_AUTHORITY", "EPOCH")
            require(current_identity == self.identity_epoch, "approval_identity_changed", 409)
            identity_fences.append(
                {
                    "ConditionCheck": {
                        "TableName": self.reader.table,
                        "Key": wire({"pk": "IDENTITY_AUTHORITY", "sk": "EPOCH"}),
                        "ConditionExpression": "revision = :rev",
                        "ExpressionAttributeValues": wire(
                            {":rev": self.identity_epoch["revision"]}
                        ),
                    }
                }
            )
        return [
            *identity_fences,
            {
                "ConditionCheck": {
                    "TableName": self.reader.table,
                    "Key": wire({"pk": self.partition, "sk": "EPOCH"}),
                    "ConditionExpression": "revision = :rev AND #owner = :owner",
                    "ExpressionAttributeNames": {"#owner": "owner"},
                    "ExpressionAttributeValues": wire(
                        {":rev": self.epoch["revision"], ":owner": self.owner}
                    ),
                }
            },
        ]


class FencedReviews(Reviews):
    """Internal owner-grant adapter. Execution still needs a freshly authorized job claim."""

    def __init__(self, client, table, owner, principal, authority, *, clock=time.time):
        require(
            isinstance(authority, OwnerAuthority)
            and authority.owner == owner
            and authority.reader.table == table
            and authority.reader.client is client,
            "approval_owner_authority_required",
            403,
        )
        super().__init__(client, table, owner, principal, authority, clock=clock)

    def command(self, request_id, reason):
        self.authority.begin()
        return super().command(request_id, reason)

    def transact(self, operations):
        return super().transact([*operations, *self.authority.fences()])

    def authorize(self, approval_id, expected_plan):
        self.authority.begin()
        result = super().authorize(approval_id, expected_plan)
        result["fences"].extend(self.authority.fences())
        return result

    def detail_visible(self, approval_id):
        self.authority.begin()
        result = super().detail_visible(approval_id)
        self.authority.fences()
        self.check_access()
        return result

    def list_visible(self, query):
        self.authority.begin()
        result = super().list_visible(query)
        self.authority.fences()
        self.check_access()
        return result
