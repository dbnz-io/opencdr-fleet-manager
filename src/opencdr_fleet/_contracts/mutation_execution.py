"""Atomic owner-reviewed mutations; receipts reconcile uncertain responses.

The compiler is an owner adapter, never a client callback. External effects must
use an existing fenced job worker; they cannot enter this DDB-only executor.
"""

import time

from botocore.exceptions import ClientError

from .approval_contract import integer, require, text
from .case_contract import CaseError, identifier
from .case_store import Cases, digest, public
from .delegation import CURRENT
from .detection_query import canonical


class Mutations:
    def __init__(self, reviews, compile_operation, *, clock=time.time):
        self.reviews, self.compile, self.clock = reviews, compile_operation, clock

    def key(self, approval_id):
        identifier(approval_id)
        return "REVIEW_EXECUTION#" + self.reviews.namespace + "#" + approval_id

    def read(self, approval_id):
        self.reviews.detail_visible(approval_id)
        row = self.reviews.get(self.key(approval_id), "META")
        return {"execution": public(row) if row else None}

    def execute(self, approval_id, body):
        require(
            isinstance(body, dict)
            and set(body)
            in (
                {"expected_rev", "request_id", "reason"},
                {"expected_rev", "request_id", "reason", "not_after"},
            ),
            "invalid_review_execution",
        )
        integer(body["expected_rev"], 1)
        identifier(body["request_id"])
        text(body["reason"], 1000)
        if "not_after" in body:
            integer(body["not_after"], 1)
        detail = self.reviews.detail_visible(approval_id)
        row, fixed = detail["review"], detail["binding"]
        request_sha = digest({"actor": self.reviews.actor, "request": body})
        pk = self.key(approval_id)

        def receipt():
            saved = self.reviews.get(pk, "META")
            if saved:
                require(saved["request_sha256"] == request_sha, "approval_already_executed", 409)
                return {"execution": public(saved), "idempotent": True}

        previous = receipt()
        if previous:
            return previous
        require(int(row["rev"]) == body["expected_rev"], "approval_revision_conflict", 409)
        material = fixed.get("material")
        require(isinstance(material, dict), "review_material_required", 409)
        operation = (
            {"kind": "release.apply", "manifest": material["content"]}
            if fixed["plan"]["operation"] == "release.apply"
            else material["content"]
        )
        prepared = self.compile(operation, self.reviews.actor)
        require(prepared["material"] == material, "approval_dependencies_changed", 409)
        authorization = self.reviews.authorize(approval_id, prepared["plan"])

        def lifetime(auth):
            require(
                auth["approval_revision"] == body["expected_rev"], "approval_revision_conflict", 409
            )
            deadline = min(int(auth["expires_at"]), body.get("not_after", int(auth["expires_at"])))
            identity = CURRENT.get()
            if identity:
                deadline = min(deadline, identity.expires_at)
            # The owner adapter uses a non-retrying client with a <=5s network
            # budget. Never dispatch a transaction near its authority deadline.
            require(self.clock() + 5 < deadline, "approval_execution_lifetime_exhausted", 403)
            self.reviews.check_access()
            return deadline

        lifetime(authorization)
        # Staged list versions are immutable and unreachable until META commits.
        # Failed/revoked execution leaves no effective configuration mutation.
        for item in prepared.get("staging", []):
            lifetime(authorization)
            try:
                self.reviews.client.put_item(**item["put"])
            except ClientError as error:
                if error.response["Error"]["Code"] != "ConditionalCheckFailedException":
                    raise
                saved = self.reviews.client.get_item(
                    TableName=item["put"]["TableName"], Key=item["key"], ConsistentRead=True
                ).get("Item")
                require(saved == item["put"]["Item"], "staged_mutation_conflict", 409)
        # Recheck live authority after potentially lengthy immutable staging.
        authorization = self.reviews.authorize(approval_id, prepared["plan"])
        deadline = lifetime(authorization)
        result = {
            "pk": pk,
            "sk": "META",
            "approval_id": approval_id,
            "binding_sha256": row["binding_sha256"],
            "request_sha256": request_sha,
            "request_id": body["request_id"],
            "reason": body["reason"],
            "actor": self.reviews.actor,
            "proposer": fixed["proposer"],
            "reviewer": authorization["authority"]["reviewer"]["actor"],
            "approval_rev": body["expected_rev"],
            "executor_binding": authorization["authority"]["executor"],
            "state": "succeeded",
            "authorized_until": deadline,
            "committed_at": int(self.clock()),
            "stored": True,
            "runtime_activation": "not_verified",
            **prepared["result"],
        }
        actions = [
            *prepared["writes"],
            *prepared["fences"],
            *authorization["fences"],
            self.reviews.put(result),
            self.reviews.put(
                {
                    "pk": pk,
                    "sk": "AUDIT",
                    "event": "executed",
                    "actor": self.reviews.actor,
                    "request_id": body["request_id"],
                    "binding_sha256": row["binding_sha256"],
                    "reason": body["reason"],
                }
            ),
        ]
        from .delegation import transaction_fences

        require(len(actions) + len(transaction_fences()) <= 100, "mutation_transaction_limit", 413)
        require(len(canonical(actions).encode()) <= 3_500_000, "mutation_transaction_bytes", 413)
        try:
            # authorize already supplied the epoch fences; don't append them twice.
            Cases.transact(self.reviews, actions)
        except CaseError:
            previous = receipt()
            if previous:
                return previous
            raise CaseError("reviewed_mutation_conflict", 409) from None
        return {"execution": public(result), "idempotent": False}
