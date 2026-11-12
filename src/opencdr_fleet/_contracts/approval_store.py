"""Retained policy, immutable review plans and atomic decision/audit receipts.

Core and Fleet owner APIs share this store. authorize() is a preflight, not
permission to issue an external mutation: execution must atomically fence its
returned rows and current authority while claiming the operation. Cross-account
workers also enforce their target binding and permanent execution claims.
"""

import base64
import json
import time
from copy import deepcopy

from .approval_contract import (
    ApprovalError,
    actor,
    binding,
    grant,
    integer,
    plan,
    policy,
    require,
    text,
)
from .case_contract import CaseError, identifier
from .case_store import Cases, decode, digest, wire
from .detection_query import canonical


def public(row):
    return {k: deepcopy(v) for k, v in row.items() if k not in {"pk", "sk"}}


class Reviews(Cases):
    def __init__(self, client, table, owner, principal, authority, *, clock=time.time):
        super().__init__(client, table, None, "", actor(principal), [], None)
        self.owner, self.authority, self.clock = text(owner), authority, clock
        self.namespace = digest(owner)

    def get(self, pk, sk):
        row = super().get(pk, sk)
        return json.loads(canonical(row)) if row is not None else None

    def now(self):
        return int(self.clock())

    def authority_for(self, principal, permission, targets=(), *, operation=None):
        return grant(
            self.authority(principal),
            principal,
            permission,
            self.now(),
            targets,
            operation=operation,
        )

    def command(self, request_id, reason):
        identifier(request_id)
        text(reason, 1000)
        self.check_access()

    def policy_row(self):
        row = self.get("REVIEW_POLICY", self.owner)
        require(row is not None, "review_policy_not_configured", 409)
        return row

    def policy_check(self, row):
        return {
            "ConditionCheck": {
                "TableName": self.table,
                "Key": wire({"pk": "REVIEW_POLICY", "sk": self.owner}),
                "ConditionExpression": "rev = :rev AND policy_sha256 = :digest",
                "ExpressionAttributeValues": wire(
                    {":rev": row["rev"], ":digest": row["policy_sha256"]}
                ),
            }
        }

    def retry(self, operation, request_id, body):
        row = self.get("REVIEW_REQUEST#" + self.namespace + "#" + digest(self.actor), request_id)
        if row:
            require(
                row["request_sha256"] == digest({"operation": operation, "body": body}),
                "approval_request_conflict",
                409,
            )
            return {**public(row["result"]), "idempotent": True}
        return None

    def commit(self, operation, request_id, body, result, writes):
        receipt = {
            "pk": "REVIEW_REQUEST#" + self.namespace + "#" + digest(self.actor),
            "sk": request_id,
            "request_sha256": digest({"operation": operation, "body": body}),
            "result": result,
        }
        if "approval_id" in result:
            index = {**result, "pk": "REVIEW_INDEX#" + self.namespace, "sk": result["approval_id"]}
            writes = [
                *writes,
                self.put(
                    index, "attribute_not_exists(pk) OR rev = :rev", {":rev": result["rev"] - 1}
                ),
            ]
        try:
            self.transact([*writes, self.put(receipt)])
        except ApprovalError:
            raise
        except CaseError:
            previous = self.retry(operation, request_id, body)
            if previous:
                return previous
            raise ApprovalError("approval_revision_conflict", 409) from None
        return {**public(result), "idempotent": False}

    def audit(self, approval_id, rev, event, reason, detail):
        from .delegation import audit_identity

        return self.put(
            {
                "pk": "REVIEW_AUDIT#" + self.namespace + "#" + approval_id,
                "sk": f"{rev:016d}",
                "owner": self.owner,
                "actor": self.actor,
                "at": self.now(),
                "event": event,
                "reason": reason,
                "identity": audit_identity(),
                "detail": detail,
            }
        )

    def configure(self, value, *, expected_rev, request_id, reason):
        self.command(request_id, reason)
        self.authority_for(self.actor, "policy_admin")
        integer(expected_rev)
        value = policy(value)
        body = {"policy": value, "expected_rev": expected_rev, "reason": reason}
        previous = self.retry("configure", request_id, body)
        if previous:
            return previous
        old = self.get("REVIEW_POLICY", self.owner)
        require((int(old["rev"]) if old else 0) == expected_rev, "approval_revision_conflict", 409)
        row = {
            "pk": "REVIEW_POLICY",
            "sk": self.owner,
            "owner": self.owner,
            "rev": expected_rev + 1,
            "policy": value,
            "policy_sha256": digest(value),
            "updated_by": self.actor,
            "updated_at": self.now(),
        }
        version = {
            **row,
            "pk": "REVIEW_POLICY_VERSION#" + self.namespace,
            "sk": f"{row['rev']:016d}",
        }
        return self.commit(
            "configure",
            request_id,
            body,
            row,
            [
                self.put(row, "rev = :rev", {":rev": expected_rev}) if old else self.put(row),
                self.put(version),
                self.audit(
                    "policy",
                    row["rev"],
                    "policy_configured",
                    reason,
                    {"policy_sha256": row["policy_sha256"]},
                ),
            ],
        )

    def propose(self, value, *, expires_at, request_id, reason, material=None):
        self.command(request_id, reason)
        value = plan(value)
        targets = [t["target_id"] for t in value["targets"]]
        auth = self.authority_for(self.actor, "mutate", targets, operation=value["operation"])
        if value["response_required"]:
            self.authority_for(self.actor, "response", targets, operation=value["operation"])
        integer(expires_at, 1)
        body = {"plan": value, "expires_at": expires_at, "reason": reason}
        if material is not None:
            require(
                isinstance(material, dict) and set(material) == {"content", "dependencies"},
                "invalid_review_material",
            )
            require(
                digest(material["content"]) == value["content_sha256"]
                and digest(material["dependencies"]) == value["dependencies_sha256"],
                "review_material_checksum_mismatch",
                409,
            )
            require(len(canonical(material).encode()) <= 128000, "review_material_too_large", 413)
            body["material"] = material
        previous = self.retry("propose", request_id, body)
        if previous:
            return previous
        current = self.policy_row()
        require(
            value["operation"] in current["policy"]["operations"], "operation_not_reviewable", 403
        )
        require(
            self.now()
            < expires_at
            <= min(auth["expires_at"], self.now() + int(current["policy"]["max_lifetime_seconds"])),
            "invalid_approval_expiry",
        )
        fixed = binding(
            self.owner, value, self.actor, auth, current["policy"], int(current["rev"]), expires_at
        )
        if material is not None:
            fixed["material"] = material
        identity = digest({"owner": self.owner, "actor": self.actor, "request_id": request_id})[:32]
        row = {
            "pk": "REVIEW#" + self.namespace + "#" + identity,
            "sk": "META",
            "owner": self.owner,
            "approval_id": identity,
            "rev": 1,
            "state": "pending",
            "binding_sha256": digest(fixed),
            "expires_at": expires_at,
            "created_at": self.now(),
            "proposer": self.actor,
        }
        return self.commit(
            "propose",
            request_id,
            body,
            row,
            [
                self.policy_check(current),
                self.put(row),
                self.put(
                    {
                        "pk": row["pk"],
                        "sk": "PLAN",
                        "binding": fixed,
                        "binding_sha256": digest(fixed),
                    }
                ),
                self.audit(identity, 1, "proposed", reason, {"binding_sha256": digest(fixed)}),
            ],
        )

    def review(self, approval_id):
        identifier(approval_id)
        key = "REVIEW#" + self.namespace + "#" + approval_id
        row, document = self.get(key, "META"), self.get(key, "PLAN")
        require(row is not None and document is not None, "approval_not_found", 404)
        require(
            row["owner"] == self.owner and document["binding"]["owner"] == self.owner,
            "approval_owner_mismatch",
            403,
        )
        require(
            digest(document["binding"]) == row["binding_sha256"] == document["binding_sha256"],
            "approval_plan_checksum_mismatch",
            409,
        )
        require(
            row["expires_at"] == document["binding"]["expires_at"]
            and row["proposer"] == document["binding"]["proposer"],
            "approval_plan_checksum_mismatch",
            409,
        )
        return row, document["binding"]

    def current_binding(self, row, fixed):
        current = self.policy_row()
        require(
            current["rev"] == fixed["policy_revision"]
            and current["policy_sha256"] == fixed["policy_sha256"],
            "approval_policy_changed",
            409,
        )
        require(int(row["expires_at"]) > self.now(), "approval_expired", 409)
        targets = [t["target_id"] for t in fixed["plan"]["targets"]]
        proposer = self.authority_for(
            fixed["proposer"], "mutate", targets, operation=fixed["plan"]["operation"]
        )
        require(proposer == fixed["proposer_grant"], "approval_proposer_authority_changed", 403)
        if fixed["plan"]["response_required"]:
            self.authority_for(
                fixed["proposer"], "response", targets, operation=fixed["plan"]["operation"]
            )
        return current, targets

    def eligible_reviewers(self, current, targets, *, operation, response_required=False):
        eligible = []
        for name in current["policy"]["reviewers"]:
            value = self.authority(name)
            if (
                value is None
                or value.get("enabled") is not True
                or value.get("expires_at", 0) <= self.now()
            ):
                continue
            if "approve" not in value.get("permissions", []) or not set(targets) <= set(
                value.get("target_ids", [])
            ):
                continue
            if operation not in value.get("operations", []):
                continue
            if response_required and "response" not in value.get("permissions", []):
                continue
            grant(value, name, "approve", self.now(), targets, operation=operation)
            eligible.append(name)
        return eligible

    def decide(self, approval_id, *, expected_rev, mode, approve, request_id, reason):
        self.command(request_id, reason)
        row, fixed = self.review(approval_id)
        current, targets = self.current_binding(row, fixed)
        reviewer = self.authority_for(
            self.actor, "approve", targets, operation=fixed["plan"]["operation"]
        )
        require(
            type(approve) is bool
            and isinstance(mode, str)
            and mode in {"peer", "self_exception", "emergency"},
            "invalid_approval_decision",
        )
        integer(expected_rev, 1)
        body = {
            "approval_id": approval_id,
            "expected_rev": expected_rev,
            "mode": mode,
            "approve": approve,
            "reason": reason,
        }
        previous = self.retry("decide", request_id, body)
        if previous:
            return previous
        require(
            row["rev"] == expected_rev and row["state"] == "pending",
            "approval_already_decided",
            409,
        )
        if mode == "emergency":
            require(
                self.actor in current["policy"]["emergency_actors"],
                "approval_emergency_not_configured",
                403,
            )
            self.authority_for(
                self.actor, "emergency", targets, operation=fixed["plan"]["operation"]
            )
        else:
            if fixed["plan"]["response_required"]:
                self.authority_for(
                    self.actor, "response", targets, operation=fixed["plan"]["operation"]
                )
            eligible = self.eligible_reviewers(
                current,
                targets,
                operation=fixed["plan"]["operation"],
                response_required=fixed["plan"]["response_required"],
            )
            require(self.actor in eligible, "approval_reviewer_ineligible", 403)
            if self.actor == fixed["proposer"]:
                require(
                    mode == "self_exception"
                    and current["policy"]["allow_self_if_sole"]
                    and eligible == [self.actor],
                    "approval_requires_other_reviewer",
                    403,
                )
            else:
                require(mode == "peer", "invalid_approval_exception", 403)
        if fixed["plan"]["response_required"]:
            self.authority_for(
                self.actor, "response", targets, operation=fixed["plan"]["operation"]
            )
        decision = {
            "reviewer": self.actor,
            "reviewer_grant": reviewer,
            "mode": mode,
            "self_approved": self.actor == fixed["proposer"],
            "approved": approve,
            "decided_at": self.now(),
            "reason": reason,
            "binding_sha256": row["binding_sha256"],
        }
        updated = {
            **row,
            "rev": expected_rev + 1,
            "state": "approved" if approve else "rejected",
            "decision": decision,
        }
        return self.commit(
            "decide",
            request_id,
            body,
            updated,
            [
                self.policy_check(current),
                self.put(updated, "rev = :rev", {":rev": expected_rev}),
                self.put({"pk": row["pk"], "sk": "DECISION", **decision}),
                self.audit(
                    approval_id,
                    expected_rev + 1,
                    "approved" if approve else "rejected",
                    reason,
                    decision,
                ),
            ],
        )

    def withdraw(self, approval_id, *, expected_rev, request_id, reason):
        """Revoke unused approval authority without undoing any execution."""
        self.command(request_id, reason)
        integer(expected_rev, 1)
        row, fixed = self.review(approval_id)
        targets = [t["target_id"] for t in fixed["plan"]["targets"]]
        self.authority_for(
            self.actor,
            "mutate" if self.actor == fixed["proposer"] else "policy_admin",
            targets,
            operation=fixed["plan"]["operation"] if self.actor == fixed["proposer"] else None,
        )
        body = {"approval_id": approval_id, "expected_rev": expected_rev, "reason": reason}
        previous = self.retry("withdraw", request_id, body)
        if previous:
            return previous
        require(
            row["rev"] == expected_rev and row["state"] in {"pending", "approved"},
            "approval_not_withdrawable",
            409,
        )
        updated = {
            **row,
            "rev": expected_rev + 1,
            "state": "withdrawn",
            "withdrawal": {"actor": self.actor, "at": self.now(), "reason": reason},
        }
        return self.commit(
            "withdraw",
            request_id,
            body,
            updated,
            [
                self.put(updated, "rev = :rev", {":rev": expected_rev}),
                self.audit(
                    approval_id, expected_rev + 1, "withdrawn", reason, updated["withdrawal"]
                ),
            ],
        )

    def authorize(self, approval_id, expected_plan):
        """Read-only preflight. Caller must fence authority and claim its existing job atomically."""
        self.check_access()
        row, fixed = self.review(approval_id)
        current, targets = self.current_binding(row, fixed)
        require(row["state"] == "approved", "approval_not_approved", 403)
        require(plan(expected_plan) == fixed["plan"], "approval_plan_changed", 409)
        executor = self.authority_for(
            self.actor, "mutate", targets, operation=fixed["plan"]["operation"]
        )
        decision = row["decision"]
        reviewer = self.authority_for(
            decision["reviewer"], "approve", targets, operation=fixed["plan"]["operation"]
        )
        require(reviewer == decision["reviewer_grant"], "approval_reviewer_authority_changed", 403)
        if fixed["plan"]["response_required"]:
            self.authority_for(
                self.actor, "response", targets, operation=fixed["plan"]["operation"]
            )
            self.authority_for(
                decision["reviewer"], "response", targets, operation=fixed["plan"]["operation"]
            )
        if decision["mode"] == "emergency":
            self.authority_for(
                decision["reviewer"], "emergency", targets, operation=fixed["plan"]["operation"]
            )
        elif decision["mode"] == "self_exception":
            require(
                self.eligible_reviewers(
                    current,
                    targets,
                    operation=fixed["plan"]["operation"],
                    response_required=fixed["plan"]["response_required"],
                )
                == [fixed["proposer"]],
                "approval_self_exception_no_longer_valid",
                403,
            )
        return {
            "approval_id": approval_id,
            "owner": self.owner,
            "binding_sha256": row["binding_sha256"],
            "expires_at": min(
                int(row["expires_at"]), reviewer["expires_at"], executor["expires_at"]
            ),
            "target_ids": targets,
            "preflight_only": True,
            "approval_revision": int(row["rev"]),
            "authority": {
                "executor": executor,
                "reviewer": reviewer,
                "proposer": fixed["proposer_grant"],
            },
            "fences": [
                self.policy_check(current),
                {
                    "ConditionCheck": {
                        "TableName": self.table,
                        "Key": wire({"pk": row["pk"], "sk": "META"}),
                        "ConditionExpression": "rev = :rev AND binding_sha256 = :digest",
                        "ExpressionAttributeValues": wire(
                            {":rev": row["rev"], ":digest": row["binding_sha256"]}
                        ),
                    }
                },
            ],
        }

    def visible(self, fixed):
        value = self.authority(self.actor)
        targets = [t["target_id"] for t in fixed["plan"]["targets"]]
        if value is None or not value.get("enabled") or value.get("expires_at", 0) <= self.now():
            return False
        if not set(targets) <= set(value.get("target_ids", [])):
            return False
        if fixed["plan"]["operation"] not in value.get("operations", []):
            return False
        return bool({"mutate", "approve", "policy_admin"} & set(value.get("permissions", [])))

    def detail_visible(self, approval_id):
        self.check_access()
        row, fixed = self.review(approval_id)
        require(self.visible(fixed), "approval_not_found", 404)
        return {"review": public(row), "binding": fixed}

    def list_visible(self, query):
        require(set(query) <= {"limit", "after"}, "invalid_review_query")
        raw = query.get("limit", "20")
        require(isinstance(raw, str) and raw.isdigit(), "invalid_review_limit")
        limit = integer(int(raw), 1, 50)
        self.check_access()
        # Query one bounded owner partition. Never scan or fan out to targets.
        pk = "REVIEW_INDEX#" + self.namespace
        args = {
            "TableName": self.table,
            "KeyConditionExpression": "pk = :pk",
            "ExpressionAttributeValues": wire({":pk": pk}),
            "Limit": limit,
            "ConsistentRead": True,
        }
        context = digest({"owner": self.owner, "actor": self.actor})
        if query.get("after"):
            try:
                token = query["after"]
                require(isinstance(token, str) and len(token) <= 1024, "invalid_review_cursor")
                cursor = json.loads(base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)))
                require(
                    set(cursor) == {"context", "after"} and cursor["context"] == context,
                    "invalid_review_cursor",
                )
                identifier(cursor["after"])
            except (ValueError, TypeError, KeyError):
                raise ApprovalError("invalid_review_cursor") from None
            args["ExclusiveStartKey"] = wire({"pk": pk, "sk": cursor["after"]})
        page = self.client.query(**args)
        items = []
        for raw in page.get("Items", []):
            indexed = decode(raw)
            row, fixed = self.review(indexed["approval_id"])
            if self.visible(fixed):
                items.append(public(row))
        after = decode(page["LastEvaluatedKey"])["sk"] if page.get("LastEvaluatedKey") else None
        cursor = (
            base64.urlsafe_b64encode(canonical({"context": context, "after": after}).encode())
            .decode()
            .rstrip("=")
            if after
            else None
        )
        return {
            "items": items,
            "next_after": cursor,
            "examined": len(page.get("Items", [])),
            "order": "approval_id",
            "snapshot": False,
        }
