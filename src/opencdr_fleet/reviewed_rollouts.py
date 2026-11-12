"""Approval-fenced extension of the existing rollout table and worker.

Planning freezes at most 100 registrations and prepares at most eight Core
approvals per request. No new scheduler or worker is introduced.
"""

import os
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from ._contracts.approval_authority import FencedReviews, OwnerAuthority
from ._contracts.approval_contract import actor, integer, plan, require
from ._contracts.case_contract import CaseError, identifier
from ._contracts.case_store import Cases
from ._contracts.delegation import CURRENT
from .models import FleetError, agent_id, json_text, now_iso, public_registration
from .rollouts import access, digest
from .store import wire


def enforced():
    return os.getenv("FLEET_REVIEW_ENFORCEMENT", "false") == "true"


def owner():
    return ":".join(
        [
            os.environ["SECURITY_ACCOUNT_ID"],
            os.getenv("AWS_REGION", os.getenv("AWS_DEFAULT_REGION")),
            os.environ["FLEET_STAGE"],
        ]
    )


class ReviewedRollouts:
    def __init__(self, manager):
        self.m, self.store, self.table = manager, manager.store, manager.table

    def reviews(self, principal=None):
        principal = principal or self.m.actor
        actor(principal)
        table = os.environ["CASE_TABLE_NAME"]
        return FencedReviews(
            self.store.client,
            table,
            owner(),
            principal,
            OwnerAuthority(self.store.client, table, owner()),
        )

    def authority(self, names, permission="mutate", principal=None):
        reviews = self.reviews(principal)
        reviews.authority.begin()
        reviews.authority_for(reviews.actor, permission, names, operation="package.apply")
        reviews.check_access()
        return reviews

    def visible(self, meta):
        reviews = self.reviews()
        reviews.authority.begin()
        require(
            reviews.visible(
                {
                    "plan": {
                        "operation": "package.apply",
                        "targets": [{"target_id": name} for name in meta["agent_ids"]],
                    }
                }
            ),
            "rollout_not_found",
            404,
        )
        reviews.authority.fences()
        reviews.check_access()

    def plan(self, request):
        require(
            isinstance(request, dict)
            and set(request)
            in (
                {"targets", "request_id", "reason"},
                {"targets", "request_id", "reason", "allocation"},
            ),
            "reviewed_rollout_requires_exact_targets",
        )
        identifier(request["request_id"])
        require(
            isinstance(request["reason"], str) and 1 <= len(request["reason"].strip()) <= 1000,
            "invalid_rollout_reason",
        )
        targets = request["targets"]
        require(isinstance(targets, list) and 1 <= len(targets) <= 100, "select_1_to_100_targets")
        for target in targets:
            require(
                isinstance(target, dict)
                and set(target) == {"agent_id", "approval_id", "expected_rev"},
                "invalid_reviewed_target",
            )
            agent_id(target["agent_id"])
            identifier(target["approval_id"])
            integer(target["expected_rev"], 1)
        names = [t["agent_id"] for t in targets]
        require(len(set(names)) == len(names), "duplicate_rollout_target")
        names = sorted(names)
        request = {**request, "targets": sorted(targets, key=lambda target: target["agent_id"])}
        reviewer = self.authority(names)
        fingerprint = digest({"actor": reviewer.actor, "request": request})
        rollout_id = (
            access()
            + "-"
            + digest({"actor": reviewer.actor, "request_id": request["request_id"]})[:32]
        )
        key = {"pk": rollout_id, "sk": "META"}
        existing = self.table.get_item(Key=key, ConsistentRead=True).get("Item")
        if existing:
            require(existing.get("request_sha256") == fingerprint, "rollout_request_conflict", 409)
            snapshots = existing["registrations"]
            meta = existing
        else:
            allocation, allocation_fences = None, []
            if "allocation" in request:
                from .desired_allocations import resolve
                from .groups import Groups

                selected = request["allocation"]
                require(
                    isinstance(selected, dict) and set(selected) == {"group_id", "expected_rev"},
                    "invalid_allocation_selection",
                )
                integer(selected["expected_rev"], 1)
                groups = Groups(self.store, reviewer)
                row = groups.read(selected["group_id"])["group"]
                require(
                    row["kind"] == "allocation"
                    and row["enabled"]
                    and row["rev"] == selected["expected_rev"]
                    and sorted(row["agent_ids"]) == names,
                    "allocation_scope_or_revision_changed",
                    409,
                )
                allocation = {
                    "group_id": row["group_id"],
                    "group_rev": row["rev"],
                    "group_sha256": digest(row),
                    "compilation": resolve(self.store, reviewer.actor, row["desired"]),
                }
                allocation_fences = [
                    {
                        "ConditionCheck": {
                            "TableName": groups.table.name,
                            "Key": wire({"pk": groups.partition, "sk": row["group_id"]}),
                            "ConditionExpression": "rev = :rev",
                            "ExpressionAttributeValues": wire({":rev": row["rev"]}),
                        }
                    }
                ]
            snapshots = {}
            for name in names:
                record = self.store.get_agent(name)
                require(
                    record.get("enabled")
                    and record.get("allow_writes")
                    and record.get("auth_mode") == "iam",
                    "agent_writes_disabled",
                    403,
                )
                snapshots[name] = {
                    "rev": int(record["rev"]),
                    "sha256": digest(public_registration(record)),
                }
            meta = {
                **key,
                "schema": "reviewed-rollout/1",
                "state": "planning",
                "actor": reviewer.actor,
                "request_sha256": fingerprint,
                "request": request,
                "registrations": snapshots,
                **({"allocation": allocation} if allocation else {}),
                "agent_ids": names,
                "access": access(),
                "review_digest": "",
                "created_at": now_iso(),
                "created_ms": int(time.time() * 1000),
                "expires_at": int(time.time()) + 7 * 86400,
            }
            try:
                Cases.transact(
                    reviewer,
                    [
                        {
                            "Put": {
                                "TableName": self.table.name,
                                "Item": wire(meta),
                                "ConditionExpression": "attribute_not_exists(pk)",
                            }
                        },
                        *reviewer.authority.fences(),
                        *allocation_fences,
                    ],
                )
            except CaseError:
                saved = self.table.get_item(Key=key, ConsistentRead=True).get("Item")
                require(
                    saved and saved.get("request_sha256") == fingerprint,
                    "rollout_request_conflict",
                    409,
                )
                meta = saved
        require(not meta.get("cancellation"), "rollout_cancelled", 409)
        for target in request["targets"]:
            row = {
                "pk": rollout_id,
                "sk": "TARGET#" + target["agent_id"],
                **target,
                "registration": snapshots[target["agent_id"]],
                "state": "unresolved",
                "expires_at": int(meta["expires_at"]),
            }
            try:
                self.table.put_item(Item=row, ConditionExpression="attribute_not_exists(pk)")
            except ClientError as error:
                if error.response["Error"]["Code"] != "ConditionalCheckFailedException":
                    raise
        reviewer.authority.fences()
        reviewer.check_access()
        return self.status(rollout_id)

    def validate_registration(self, meta, name):
        record = self.store.get_agent(name)
        expected = meta["registrations"][name]
        require(
            record.get("enabled")
            and record.get("allow_writes")
            and record.get("auth_mode") == "iam"
            and int(record["rev"]) == expected["rev"]
            and digest(public_registration(record)) == expected["sha256"],
            "agent_registration_changed_since_review",
            409,
        )
        return record

    def core_review(self, meta, target):
        name = target["agent_id"]
        record = self.validate_registration(meta, name)
        _, client = self.m.prepare_agent(name)
        code, detail = client.request("GET", "/reviews/" + target["approval_id"])
        require(
            code == 200 and isinstance(detail, dict),
            "core_approval_unavailable",
            503 if code >= 500 else 409,
        )
        row, binding = detail.get("review", {}), detail.get("binding", {})
        core_owner = ":".join(record[k] for k in ["account_id", "region", "stage"])
        require(
            row.get("approval_id") == target["approval_id"]
            and row.get("state") == "approved"
            and row.get("rev") == target["expected_rev"]
            and binding.get("owner") == core_owner
            and row.get("binding_sha256") == digest(binding),
            "core_approval_binding_changed",
            409,
        )
        fixed = binding["plan"]
        require(
            fixed["operation"]
            in {"rule.write", "list.write", "configuration.write", "release.apply", "package.apply"}
            and len(fixed["targets"]) == 1
            and fixed["targets"][0]["target_id"] == core_owner,
            "core_approval_owner_mismatch",
            409,
        )
        require(int(row["expires_at"]) > time.time() + 5, "core_approval_expired", 403)
        if meta.get("allocation"):
            from .desired_allocations import check_target

            check_target(meta["allocation"], binding)
        summary = {
            "agent_id": name,
            "registration_rev": int(record["rev"]),
            "registration_sha256": meta["registrations"][name]["sha256"],
            "owner": core_owner,
            "approval_id": target["approval_id"],
            "approval_rev": int(row["rev"]),
            "binding_sha256": row["binding_sha256"],
            "expires_at": int(row["expires_at"]),
            "operation": fixed["operation"],
            "content_sha256": fixed["content_sha256"],
            "response_required": fixed["response_required"],
        }
        return summary, client

    def prepare(self, rollout_id, request):
        require(request == {}, "invalid_rollout_prepare")
        meta = self.m.get(rollout_id)
        reviewer = self.authority(meta["agent_ids"])
        require(
            meta["access"] == access() and not meta.get("cancellation"),
            "rollout_access_or_cancellation",
            403,
        )
        if meta["state"] == "ready":
            return self.status(rollout_id)
        pending = [self.m.get(rollout_id, "TARGET#" + name) for name in meta["agent_ids"]]
        pending = [t for t in pending if t["state"] == "unresolved"][:8]

        def resolve(target):
            return target, self.core_review(meta, target)[0]

        with ThreadPoolExecutor(max_workers=8) as pool:
            resolved = list(pool.map(resolve, pending))
        for target, summary in resolved:
            try:
                self.table.update_item(
                    Key={"pk": rollout_id, "sk": target["sk"]},
                    UpdateExpression="SET #state = :planned, prepared = :prepared",
                    ConditionExpression="#state = :unresolved",
                    ExpressionAttributeNames={"#state": "state"},
                    ExpressionAttributeValues={
                        ":planned": "planned",
                        ":unresolved": "unresolved",
                        ":prepared": summary,
                    },
                )
            except ClientError as error:
                if error.response["Error"]["Code"] != "ConditionalCheckFailedException":
                    raise
        targets = [self.m.get(rollout_id, "TARGET#" + name) for name in meta["agent_ids"]]
        if all(t["state"] == "planned" for t in targets):
            summaries = [t["prepared"] for t in targets]
            content = {"kind": "rollout.execute", "rollout_id": rollout_id}
            dependencies = {"targets": summaries, "request_sha256": meta["request_sha256"]}
            fixed = plan(
                {
                    "operation": "package.apply",
                    "content_sha256": digest(content),
                    "dependencies_sha256": digest(dependencies),
                    "response_required": any(t["response_required"] for t in summaries),
                    "targets": [
                        {
                            "target_id": t["agent_id"],
                            "registration_rev": int(t["registration_rev"]),
                            "snapshot_sha256": digest(t),
                            "expected_revisions": {"core_approval": int(t["approval_rev"])},
                        }
                        for t in summaries
                    ],
                }
            )
            prepared = {
                "plan": fixed,
                "material": {"content": content, "dependencies": dependencies},
            }
            require(
                len(json_text(prepared["material"]).encode()) <= 128000,
                "rollout_review_material_limit",
                413,
            )
            self.m.put_blob(rollout_id, "REVIEW", prepared, int(meta["expires_at"]))
            Cases.transact(
                reviewer,
                [
                    {
                        "Update": {
                            "TableName": self.table.name,
                            "Key": wire({"pk": rollout_id, "sk": "META"}),
                            "UpdateExpression": (
                                "SET #state = :ready, review_digest = :digest, prepared_at = :at"
                            ),
                            "ConditionExpression": (
                                "#state = :planning AND attribute_not_exists(cancellation)"
                            ),
                            "ExpressionAttributeNames": {"#state": "state"},
                            "ExpressionAttributeValues": wire(
                                {
                                    ":ready": "ready",
                                    ":planning": "planning",
                                    ":digest": digest(prepared),
                                    ":at": now_iso(),
                                }
                            ),
                        }
                    },
                    *reviewer.authority.fences(),
                ],
            )
        reviewer.authority.fences()
        reviewer.check_access()
        return self.status(rollout_id)

    def proposal(self, operation):
        require(
            isinstance(operation, dict)
            and set(operation) == {"kind", "rollout_id"}
            and operation["kind"] == "rollout.execute",
            "unsupported_review_operation",
        )
        meta = self.m.get(operation["rollout_id"])
        self.authority(meta["agent_ids"])
        require(meta["state"] == "ready" and not meta.get("cancellation"), "rollout_not_ready", 409)
        prepared = self.m.blob(operation["rollout_id"], "REVIEW")
        require(digest(prepared) == meta["review_digest"], "rollout_review_checksum_mismatch", 409)
        return prepared

    def status(self, rollout_id):
        meta = self.m.get(rollout_id)
        self.visible(meta)
        result = self.m._status(rollout_id)
        return {
            **result,
            "state": meta["state"],
            "prepared_targets": sum(t["state"] != "unresolved" for t in result["targets"]),
            "target_count": len(meta["agent_ids"]),
            "authorization": meta.get("authorization"),
            "prepare_batch_size": 8,
            "allocation": meta.get("allocation"),
        }

    def enqueue(self, rollout_id, request):
        require(
            isinstance(request, dict)
            and set(request) == {"approval_id", "expected_rev", "request_id", "reason"},
            "invalid_rollout_authorization",
        )
        identifier(request["approval_id"])
        identifier(request["request_id"])
        integer(request["expected_rev"], 1)
        require(
            isinstance(request["reason"], str) and 1 <= len(request["reason"].strip()) <= 1000,
            "invalid_rollout_reason",
        )
        meta = self.m.get(rollout_id)
        require(
            meta["state"] == "ready"
            and meta["access"] == access()
            and not meta.get("cancellation"),
            "rollout_not_ready",
            409,
        )
        prepared = self.m.blob(rollout_id, "REVIEW")
        require(digest(prepared) == meta["review_digest"], "rollout_review_checksum_mismatch", 409)
        reviews = self.reviews()
        auth = reviews.authorize(request["approval_id"], prepared["plan"])
        require(
            auth["approval_revision"] == request["expected_rev"], "approval_revision_conflict", 409
        )
        deadline = min(
            auth["expires_at"],
            *(t["expires_at"] for t in prepared["material"]["dependencies"]["targets"]),
        )
        if CURRENT.get():
            deadline = min(deadline, CURRENT.get().expires_at)
        fingerprint = digest({"actor": reviews.actor, "request": request})
        saved = meta.get("authorization")
        if saved:
            require(saved["request_sha256"] == fingerprint, "rollout_authorization_conflict", 409)
            deadline = min(deadline, int(saved["expires_at"]))
            require(
                saved["executor"] == auth["authority"]["executor"]
                and saved["binding_sha256"] == auth["binding_sha256"],
                "queued_authority_changed",
                403,
            )
        require(time.time() + 5 < deadline, "queued_authority_expired", 403)
        authorization = {
            "actor": reviews.actor,
            "request_sha256": fingerprint,
            "approval_id": request["approval_id"],
            "approval_rev": request["expected_rev"],
            "executor": auth["authority"]["executor"],
            "binding_sha256": auth["binding_sha256"],
            "expires_at": int(deadline),
            "request_id": request["request_id"],
            "reason": request["reason"],
        }
        if not saved:
            Cases.transact(
                reviews,
                [
                    {
                        "Update": {
                            "TableName": self.table.name,
                            "Key": wire({"pk": rollout_id, "sk": "META"}),
                            "ExpressionAttributeNames": {"#authorization": "authorization"},
                            "UpdateExpression": "SET #authorization = :auth",
                            "ConditionExpression": (
                                "review_digest = :digest AND "
                                "attribute_not_exists(#authorization) AND "
                                "attribute_not_exists(cancellation)"
                            ),
                            "ExpressionAttributeValues": wire(
                                {":auth": authorization, ":digest": meta["review_digest"]}
                            ),
                        }
                    },
                    *auth["fences"],
                ],
            )
        # A repeated enqueue may repair unsent queue messages, never target claims.
        for name in meta["agent_ids"]:
            if self.m.get(rollout_id, "TARGET#" + name)["state"] == "planned":
                self.store.sqs.send_message(
                    QueueUrl=os.environ["ROLLOUT_QUEUE_URL"],
                    MessageBody=json_text({"rollout_id": rollout_id, "agent_id": name}),
                )
        return self.status(rollout_id)

    def fresh_authorization(self, meta, prepared):
        queued = meta.get("authorization")
        require(queued is not None, "rollout_approval_required", 403)
        reviews = self.reviews(queued["actor"])
        auth = reviews.authorize(queued["approval_id"], prepared["plan"])
        require(
            auth["approval_revision"] == queued["approval_rev"]
            and auth["binding_sha256"] == queued["binding_sha256"]
            and auth["authority"]["executor"] == queued["executor"],
            "queued_authority_changed",
            403,
        )
        require(
            time.time() + 5 < min(auth["expires_at"], queued["expires_at"]),
            "queued_authority_expired",
            403,
        )
        return reviews, auth

    def execution_body(self, meta, name):
        target = self.m.get(meta["pk"], "TARGET#" + name)
        return {
            "expected_rev": int(target["prepared"]["approval_rev"]),
            "request_id": digest({"rollout_id": meta["pk"], "agent_id": name})[:32],
            "reason": "Fleet rollout " + meta["pk"],
            "not_after": int(meta["authorization"]["expires_at"]),
        }

    def execute(self, rollout_id, name):
        meta = self.m.get(rollout_id)
        require(
            meta["schema"] == "reviewed-rollout/1"
            and meta["access"] == access()
            and name in meta["agent_ids"],
            "rollout_worker_access_mismatch",
            403,
        )
        target = self.m.get(rollout_id, "TARGET#" + name)
        if meta.get("cancellation"):
            return "cancelled"
        if target["state"] != "planned":
            return "already_claimed"
        prepared = self.m.blob(rollout_id, "REVIEW")
        require(digest(prepared) == meta["review_digest"], "rollout_review_checksum_mismatch", 409)
        try:
            reviews, auth = self.fresh_authorization(meta, prepared)
            summary, client = self.core_review(meta, target)
            require(summary == target["prepared"], "core_approval_binding_changed", 409)
            # Revalidate after external reads, immediately before the atomic claim.
            reviews, auth = self.fresh_authorization(meta, prepared)
        except CaseError as error:
            if error.status >= 500:
                raise  # Offline preflight never claimed or dispatched a write.
            try:
                self.table.update_item(
                    Key={"pk": rollout_id, "sk": "TARGET#" + name},
                    UpdateExpression=(
                        "SET #state = :blocked, error_code = :error, "
                        "dispatch_attempted = :no, finished_at = :at"
                    ),
                    ConditionExpression="#state = :planned",
                    ExpressionAttributeNames={"#state": "state"},
                    ExpressionAttributeValues={
                        ":blocked": "blocked",
                        ":error": error.code,
                        ":no": False,
                        ":at": now_iso(),
                        ":planned": "planned",
                    },
                )
            except ClientError as conflict:
                if conflict.response["Error"]["Code"] != "ConditionalCheckFailedException":
                    raise
                return "already_claimed"
            return "blocked"
        key = {"pk": rollout_id, "sk": "TARGET#" + name}
        try:
            Cases.transact(
                reviews,
                [
                    {
                        "ConditionCheck": {
                            "TableName": self.table.name,
                            "Key": wire({"pk": rollout_id, "sk": "META"}),
                            "ExpressionAttributeNames": {"#authorization": "authorization"},
                            "ConditionExpression": (
                                "review_digest = :digest AND #authorization = :auth AND "
                                "attribute_not_exists(cancellation)"
                            ),
                            "ExpressionAttributeValues": wire(
                                {":digest": meta["review_digest"], ":auth": meta["authorization"]}
                            ),
                        }
                    },
                    {
                        "ConditionCheck": {
                            "TableName": self.store.registry.name,
                            "Key": wire({"id": "AGENT#" + name}),
                            "ConditionExpression": (
                                "rev = :rev AND enabled = :yes AND allow_writes = :yes"
                            ),
                            "ExpressionAttributeValues": wire(
                                {":rev": summary["registration_rev"], ":yes": True}
                            ),
                        }
                    },
                    {
                        "Update": {
                            "TableName": self.table.name,
                            "Key": wire(key),
                            "ConditionExpression": "#state = :planned",
                            "UpdateExpression": "SET #state = :sending, started_at = :at",
                            "ExpressionAttributeNames": {"#state": "state"},
                            "ExpressionAttributeValues": wire(
                                {":planned": "planned", ":sending": "sending", ":at": now_iso()}
                            ),
                        }
                    },
                    *auth["fences"],
                ],
            )
        except CaseError:
            if self.m.get(rollout_id).get("cancellation"):
                return "cancelled"
            if self.m.get(rollout_id, "TARGET#" + name)["state"] != "planned":
                return "already_claimed"
            raise
        body = self.execution_body(meta, name)
        try:
            code, result = client.request(
                "POST", "/reviews/" + summary["approval_id"] + "/execute", body=body
            )
            execution = result.get("execution", {}) if isinstance(result, dict) else {}
            if 200 <= code < 300:
                require(
                    execution.get("request_id") == body["request_id"]
                    and execution.get("binding_sha256") == summary["binding_sha256"]
                    and execution.get("state") == "succeeded",
                    "core_execution_receipt_mismatch",
                    502,
                )
                outcome = "succeeded"
            else:
                outcome = "conflict" if code == 409 else "unknown" if code >= 500 else "failed"
        except (FleetError, CaseError) as error:
            code, result, outcome = error.status, {"error_code": error.code}, "unknown"
        self.m.put_blob(rollout_id, "RESULT#" + name, result, int(meta["expires_at"]))
        self.table.update_item(
            Key=key,
            UpdateExpression="SET #state = :state, status_code = :code, finished_at = :at",
            ConditionExpression="#state = :sending",
            ExpressionAttributeNames={"#state": "state"},
            ExpressionAttributeValues={
                ":state": outcome,
                ":code": code,
                ":at": now_iso(),
                ":sending": "sending",
            },
        )
        return outcome

    def drift(self, rollout_id, request):
        require(isinstance(request, dict) and set(request) <= {"after"}, "invalid_drift_request")
        meta = self.m.get(rollout_id)
        self.visible(meta)
        names = meta["agent_ids"]
        after = request.get("after")
        require(after is None or after in names, "invalid_drift_cursor")
        start = names.index(after) + 1 if after else 0
        selected = names[start : start + 8]

        def observe(name):
            target = self.m.get(rollout_id, "TARGET#" + name)
            if target["state"] != "succeeded":
                return name, {
                    "state": target["state"],
                    "stored_matches": None,
                    "runtime_activation": "not_verified",
                }
            try:
                self.validate_registration(meta, name)
                _, client = self.m.prepare_agent(name)
                code, result = client.request(
                    "GET", "/reviews/" + target["prepared"]["approval_id"] + "/verification"
                )
                if code == 200 and isinstance(result, dict):
                    return name, result
                return name, {
                    "status_code": code,
                    "stored_matches": None,
                    "runtime_activation": "not_verified",
                }
            except (FleetError, CaseError) as error:
                return name, {
                    "error_code": error.code,
                    "stored_matches": None,
                    "runtime_activation": "not_verified",
                }

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = dict(pool.map(observe, selected))
        self.visible(meta)
        return {
            "rollout_id": rollout_id,
            "targets": results,
            "report_only": True,
            "next_after": selected[-1] if start + len(selected) < len(names) else None,
            "target_count": len(names),
            "observed_targets": len(selected),
        }

    def reconcile(self, rollout_id, name):
        meta = self.m.get(rollout_id)
        self.visible(meta)
        require(name in meta["agent_ids"], "rollout_target_not_found", 404)
        target = self.m.get(rollout_id, "TARGET#" + name)
        require(
            target["state"] in {"sending", "unknown", "succeeded"},
            "rollout_has_no_uncertain_dispatch",
            409,
        )
        self.validate_registration(meta, name)
        _, client = self.m.prepare_agent(name)
        approval = target["prepared"]["approval_id"]
        code, result = client.request("GET", "/reviews/" + approval + "/execution")
        require(code == 200 and isinstance(result, dict), "core_receipt_unavailable", 409)
        execution = result.get("execution")
        if execution is None:
            self.visible(meta)
            return {
                "state": "unknown",
                "retry_allowed": False,
                "detail": "No receipt observed; this does not prove the request was never sent.",
            }
        expected = self.execution_body(meta, name)
        require(
            execution.get("request_id") == expected["request_id"]
            and execution.get("binding_sha256") == target["prepared"]["binding_sha256"]
            and execution.get("state") == "succeeded",
            "core_execution_receipt_mismatch",
            409,
        )
        verify_code, verification = client.request("GET", "/reviews/" + approval + "/verification")
        result = {
            **result,
            "verification": verification
            if verify_code == 200
            else {"stored_matches": None, "runtime_activation": "not_verified"},
        }
        self.visible(meta)
        self.m.put_blob(rollout_id, "RESULT#" + name, result, int(meta["expires_at"]))
        self.table.update_item(
            Key={"pk": rollout_id, "sk": "TARGET#" + name},
            UpdateExpression="SET #state = :state, reconciled_at = :at, verification = :v",
            ConditionExpression="#state IN (:sending, :unknown, :state)",
            ExpressionAttributeNames={"#state": "state"},
            ExpressionAttributeValues={
                ":state": "succeeded",
                ":sending": "sending",
                ":unknown": "unknown",
                ":at": now_iso(),
                ":v": result["verification"],
            },
        )
        return {
            "state": "succeeded",
            "retry_allowed": False,
            "verification": result["verification"],
        }
