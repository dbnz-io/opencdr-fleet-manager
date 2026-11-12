"""Durable, explicitly reviewed rule releases. An uncertain mutation is never replayed."""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from botocore.exceptions import ClientError

from .agent import Agent
from .models import FleetError, agent_id, json_text, now_iso
from .store import wire

ACCESS = {"operator": 1, "responder": 2, "administrator": 3}


def access():
    value = os.getenv("FLEET_MANAGEMENT_ACCESS", "operator")
    if value not in ACCESS:
        raise FleetError("rollout_write_access_required", 403)
    return value


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"(operator|responder|administrator)-[a-f0-9]{32}", value
    ):
        raise FleetError("invalid_rollout_id")
    return value


def digest(value):
    return hashlib.sha256(json_text(value).encode()).hexdigest()


class Rollouts:
    def __init__(self, store, agent_factory=Agent, *, authenticated_actor=None):
        self.store = store
        self.table = store.ddb.Table(os.environ["ROLLOUT_TABLE"])
        self.agent_factory = agent_factory
        self.actor = authenticated_actor

    def get(self, rollout_id, sk="META"):
        item = self.table.get_item(
            Key={"pk": identifier(rollout_id), "sk": sk}, ConsistentRead=True
        ).get("Item")
        if not item or int(item["expires_at"]) <= time.time():
            raise FleetError("rollout_not_found_or_expired", 404)
        return item

    def put_blob(self, rollout_id, name, value, expires):
        raw = json_text(value)
        if len(raw) > 2_000_000:
            raise FleetError("rollout_document_too_large", 413)
        chunks = [raw[i : i + 240_000] for i in range(0, len(raw), 240_000)]
        with self.table.batch_writer() as batch:
            for index, chunk in enumerate(chunks):
                batch.put_item(
                    Item={
                        "pk": rollout_id,
                        "sk": f"{name}#{index:03d}",
                        "payload": chunk,
                        "expires_at": expires,
                    }
                )
        self.table.put_item(
            Item={
                "pk": rollout_id,
                "sk": name,
                "parts": len(chunks),
                "sha256": digest(value),
                "expires_at": expires,
            }
        )

    def blob(self, rollout_id, name):
        manifest = self.get(rollout_id, name)
        raw = "".join(
            self.get(rollout_id, f"{name}#{i:03d}")["payload"]
            for i in range(int(manifest["parts"]))
        )
        value = json.loads(raw)
        if digest(value) != manifest["sha256"]:
            raise FleetError("rollout_document_checksum_mismatch", 502)
        return value

    def prepare_agent(self, name):
        record = self.store.get_agent(agent_id(name))
        if not record["enabled"] or not record["allow_writes"]:
            raise FleetError("agent_writes_disabled", 403)
        if record.get("auth_mode") != "iam":
            raise FleetError("durable_rollout_requires_iam", 409)
        if ACCESS[record.get("write_access", "operator")] > ACCESS[access()]:
            raise FleetError("fleet_response_authority_required", 403)
        client = self.agent_factory(record, "", "iam", deadline=time.monotonic() + 22)
        report = client.verify()
        from .reviewed_rollouts import enforced

        available = report.get("capabilities", {})
        supported = (
            available.get("reviewed_mutations") == "1.0.0"
            if enforced()
            else available.get("reviewed_rule_releases")
        )
        if not supported:
            raise FleetError("reviewed_release_contract_required", 409)
        return record, client

    def plan(self, request):
        from .reviewed_rollouts import ReviewedRollouts, enforced

        if enforced():
            return ReviewedRollouts(self).plan(request)
        if not isinstance(request, dict) or set(request) != {"agent_ids", "manifest"}:
            raise FleetError("rollout_requires_targets_and_manifest")
        names = request["agent_ids"]
        if (
            not isinstance(names, list)
            or not 1 <= len(names) <= 8
            or any(not isinstance(name, str) for name in names)
            or len(set(names)) != len(names)
        ):
            raise FleetError("select_1_to_8_unique_agents")
        if (
            not isinstance(request["manifest"], dict)
            or "expected_plan_digest" in request["manifest"]
        ):
            raise FleetError("rollout_requires_manifest_without_target_specific_digest")

        def review(name):
            record, client = self.prepare_agent(name)
            code, plan = client.request("POST", "/rule-releases/plan", body=request["manifest"])
            if (
                code != 200
                or not isinstance(plan, dict)
                or not plan.get("valid")
                or not plan.get("plan_digest")
            ):
                raise FleetError("agent_release_plan_failed", 409)
            return name, {"registration_rev": int(record["rev"]), "plan": plan}

        with ThreadPoolExecutor(max_workers=8) as pool:
            targets = dict(pool.map(review, names))
        reviewed = {"manifest": request["manifest"], "targets": targets, "access": access()}
        rollout_id = access() + "-" + uuid.uuid4().hex
        expires = int(time.time()) + 7 * 86400
        self.put_blob(rollout_id, "REVIEW", reviewed, expires)
        for name in names:
            self.table.put_item(
                Item={
                    "pk": rollout_id,
                    "sk": "TARGET#" + name,
                    "agent_id": name,
                    "state": "planned",
                    "expires_at": expires,
                }
            )
        self.table.put_item(
            Item={
                "pk": rollout_id,
                "sk": "META",
                "created_at": now_iso(),
                "created_ms": int(time.time() * 1000),
                "expires_at": expires,
                "review_digest": digest(reviewed),
                "agent_ids": names,
                "access": access(),
            }
        )
        return {
            "rollout_id": rollout_id,
            "review_digest": digest(reviewed),
            "targets": targets,
            "atomic": False,
            "plan_valid_seconds": 900,
        }

    def enqueue(self, rollout_id, request):
        from .reviewed_rollouts import ReviewedRollouts, enforced

        meta = self.get(rollout_id)
        if meta.get("schema") == "reviewed-rollout/1":
            return ReviewedRollouts(self).enqueue(rollout_id, request)
        if enforced():
            raise FleetError("legacy_rollout_requires_new_review", 409)
        if meta["access"] != access():
            raise FleetError("use_the_reviewed_management_access", 403)
        if not isinstance(request, dict) or request != {"review_digest": meta["review_digest"]}:
            raise FleetError("review_digest_required", 409)
        if int(meta["created_ms"]) < time.time() * 1000 - 900_000:
            raise FleetError("rollout_review_expired", 409)
        if meta.get("cancellation"):
            raise FleetError("rollout_cancelled", 409)
        # Repeating enqueue is safe: each target is conditionally claimed once.
        # Failed dispatch can be resumed without replacing any reviewed revision.
        for name in meta["agent_ids"]:
            if self.get(rollout_id, "TARGET#" + name)["state"] == "planned":
                self.store.sqs.send_message(
                    QueueUrl=os.environ["ROLLOUT_QUEUE_URL"],
                    MessageBody=json_text({"rollout_id": rollout_id, "agent_id": name}),
                )
        return self.status(rollout_id)

    def cancel(self, rollout_id, request, *, authenticated_actor):
        """Stop unclaimed targets; never undo or replay a possibly sent write.

        Internal P4 primitive. The eventual owner API supplies authenticated_actor;
        it is not accepted from a request body. Approval/policy wiring remains P4.
        """
        meta = self.get(rollout_id)
        if meta["access"] != access():
            raise FleetError("use_the_reviewed_management_access", 403)
        if (
            not isinstance(request, dict)
            or set(request) != {"review_digest", "request_id", "reason"}
            or request["review_digest"] != meta["review_digest"]
            or not isinstance(request["request_id"], str)
            or not re.fullmatch(r"[a-f0-9]{32}", request["request_id"])
            or not isinstance(request["reason"], str)
            or not 1 <= len(request["reason"].strip()) <= 1000
            or not isinstance(authenticated_actor, str)
            or not 1 <= len(authenticated_actor) <= 256
        ):
            raise FleetError("invalid_rollout_cancellation")
        fixed = {**request, "actor": authenticated_actor}
        from ._contracts.case_contract import CaseError
        from ._contracts.case_store import Cases
        from .reviewed_rollouts import ReviewedRollouts, enforced

        review_authority = None
        if enforced() or meta.get("schema") == "reviewed-rollout/1":
            review_authority = ReviewedRollouts(self).authority(
                meta["agent_ids"], principal=authenticated_actor
            )
        prior = meta.get("cancellation")
        if prior:
            if prior["request_sha256"] != digest(fixed):
                raise FleetError("rollout_cancellation_request_conflict", 409)
        else:
            record = {**fixed, "request_sha256": digest(fixed), "requested_at": now_iso()}
            try:
                if review_authority:
                    Cases.transact(
                        review_authority,
                        [
                            {
                                "Update": {
                                    "TableName": self.table.name,
                                    "Key": wire({"pk": rollout_id, "sk": "META"}),
                                    "UpdateExpression": "SET cancellation = :c",
                                    "ConditionExpression": (
                                        "review_digest = :d AND attribute_not_exists(cancellation)"
                                    ),
                                    "ExpressionAttributeValues": wire(
                                        {":c": record, ":d": meta["review_digest"]}
                                    ),
                                }
                            },
                            *review_authority.authority.fences(),
                        ],
                    )
                else:
                    self.table.update_item(
                        Key={"pk": rollout_id, "sk": "META"},
                        UpdateExpression="SET cancellation = :cancellation",
                        ConditionExpression=(
                            "review_digest = :digest AND attribute_not_exists(cancellation)"
                        ),
                        ExpressionAttributeValues={
                            ":digest": meta["review_digest"],
                            ":cancellation": record,
                        },
                    )
            except (ClientError, CaseError) as error:
                if (
                    isinstance(error, ClientError)
                    and error.response["Error"]["Code"] != "ConditionalCheckFailedException"
                ):
                    raise
                latest = self.get(rollout_id).get("cancellation", {})
                if not latest:
                    raise
                if latest.get("request_sha256") != digest(fixed):
                    raise FleetError("rollout_cancellation_request_conflict", 409) from None
        # The durable META fence is set first. An interruption here is retryable
        # without allowing any new claim; already sending targets retain state.
        for name in meta["agent_ids"]:
            try:
                self.table.update_item(
                    Key={"pk": rollout_id, "sk": "TARGET#" + name},
                    UpdateExpression="SET #state = :cancelled, finished_at = :at",
                    ConditionExpression="#state IN (:planned, :unresolved)",
                    ExpressionAttributeNames={"#state": "state"},
                    ExpressionAttributeValues={
                        ":planned": "planned",
                        ":unresolved": "unresolved",
                        ":cancelled": "cancelled",
                        ":at": now_iso(),
                    },
                )
            except ClientError as error:
                if error.response["Error"]["Code"] != "ConditionalCheckFailedException":
                    raise
        return self.status(rollout_id)

    def status(self, rollout_id):
        from .reviewed_rollouts import ReviewedRollouts, enforced

        meta = self.get(rollout_id)
        if meta.get("schema") == "reviewed-rollout/1":
            return ReviewedRollouts(self).status(rollout_id)
        if enforced():
            ReviewedRollouts(self).visible(meta)
        return self._status(rollout_id)

    def _status(self, rollout_id):
        meta = self.get(rollout_id)
        targets = []
        for name in meta["agent_ids"]:
            target = self.get(rollout_id, "TARGET#" + name)
            if (
                target["state"] == "sending"
                and time.time() - datetime.fromisoformat(target["started_at"]).timestamp() > 120
            ):
                target = {
                    **target,
                    "state": "unknown",
                    "detail": "worker_interrupted_inspect_agent_before_new_plan",
                }
            targets.append({k: v for k, v in target.items() if k not in {"pk", "sk", "expires_at"}})
        return {
            "rollout_id": rollout_id,
            "review_digest": meta["review_digest"],
            "targets": targets,
            "atomic": False,
            "cancellation": meta.get("cancellation"),
            "complete": all(
                t["state"] not in {"unresolved", "planned", "sending"} for t in targets
            ),
        }

    def execute(self, rollout_id, name):
        from .reviewed_rollouts import ReviewedRollouts, enforced

        meta = self.get(rollout_id)
        if meta.get("schema") == "reviewed-rollout/1":
            return ReviewedRollouts(self).execute(rollout_id, name)
        if enforced():
            raise FleetError("legacy_rollout_requires_new_review", 409)
        if meta["access"] != access() or name not in meta["agent_ids"]:
            raise FleetError("rollout_worker_access_mismatch", 403)
        key = {"pk": rollout_id, "sk": "TARGET#" + name}
        try:
            self.store.client.transact_write_items(
                TransactItems=[
                    {
                        "ConditionCheck": {
                            "TableName": self.table.name,
                            "Key": wire({"pk": rollout_id, "sk": "META"}),
                            "ConditionExpression": (
                                "review_digest = :digest AND attribute_not_exists(cancellation)"
                            ),
                            "ExpressionAttributeValues": wire({":digest": meta["review_digest"]}),
                        }
                    },
                    {
                        "Update": {
                            "TableName": self.table.name,
                            "Key": wire(key),
                            "ConditionExpression": "#state = :planned",
                            "UpdateExpression": "SET #state = :sending, started_at = :now",
                            "ExpressionAttributeNames": {"#state": "state"},
                            "ExpressionAttributeValues": wire(
                                {":planned": "planned", ":sending": "sending", ":now": now_iso()}
                            ),
                        }
                    },
                ]
            )
        except ClientError as error:
            if error.response["Error"]["Code"] != "TransactionCanceledException":
                raise
            # Only known fence conflicts count as a handled duplicate. Capacity
            # and validation failures must remain retryable failures.
            if self.get(rollout_id).get("cancellation"):
                return "cancelled"
            if self.get(rollout_id, "TARGET#" + name)["state"] != "planned":
                return "already_claimed"
            raise
        sent = False
        try:
            if int(meta["created_ms"]) < time.time() * 1000 - 900_000:
                raise FleetError("rollout_review_expired", 409)
            reviewed = self.blob(rollout_id, "REVIEW")
            if digest(reviewed) != meta["review_digest"]:
                raise FleetError("rollout_review_checksum_mismatch", 502)
            record, client = self.prepare_agent(name)
            target = reviewed["targets"][name]
            if int(record["rev"]) != target["registration_rev"]:
                raise FleetError("agent_registration_changed_since_review", 409)
            payload = {
                **reviewed["manifest"],
                "expected_plan_digest": target["plan"]["plan_digest"],
            }
            sent = True
            code, result = client.request("POST", "/rule-releases/apply", body=payload)
            outcome = (
                "succeeded"
                if 200 <= code < 300
                else "conflict"
                if code == 409
                else "unknown"
                if code >= 500
                else "failed"
            )
            if isinstance(result, dict) and result.get("completed") and code >= 300:
                outcome = "partial"
        except FleetError as error:
            code, result = error.status, {"error_code": error.code}
            outcome = "unknown" if sent else "not_sent"
        self.put_blob(rollout_id, "RESULT#" + name, result, int(meta["expires_at"]))
        self.table.update_item(
            Key=key,
            UpdateExpression="SET #state = :outcome, status_code = :code, finished_at = :now",
            ExpressionAttributeNames={"#state": "state"},
            ExpressionAttributeValues={":outcome": outcome, ":code": code, ":now": now_iso()},
        )
        return outcome

    def drift(self, rollout_id, request=None):
        from .reviewed_rollouts import ReviewedRollouts, enforced

        meta = self.get(rollout_id)
        if meta.get("schema") == "reviewed-rollout/1":
            return ReviewedRollouts(self).drift(rollout_id, request or {})
        if enforced():
            ReviewedRollouts(self).visible(meta)
        reviewed = self.blob(rollout_id, "REVIEW")

        def compare(name):
            _, client = self.prepare_agent(name)
            code, plan = client.request("POST", "/rule-releases/plan", body=reviewed["manifest"])
            return name, {
                "status_code": code,
                "plan": plan,
                "aligned": code == 200
                and isinstance(plan, dict)
                and bool(plan.get("valid"))
                and all(op["action"] == "unchanged" for op in plan.get("operations", [])),
            }

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = dict(pool.map(compare, reviewed["targets"]))
        return {"rollout_id": rollout_id, "targets": results, "report_only": True}
