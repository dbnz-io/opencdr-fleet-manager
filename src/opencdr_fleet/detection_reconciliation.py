"""Reviewed gap recovery, executed only by the original consumer's worker role."""

import hashlib
import os
import re
import time

from botocore.exceptions import ClientError

from ._contracts.detection_query import canonical
from .consumer_delivery import _owner, _state, consumer_id
from .models import FleetError, now_iso
from .store import wire


def request(store, name, body, actor, *, recovery=False):
    from .detections import Detections

    fields = {
        "expected_generation",
        "expected_registration_rev",
        "backfill_job_id",
        "plan_digest",
        "reason",
        "accept_unrecoverable",
        "request_id",
    }
    if recovery:
        fields |= {"target_epoch", "target_owner"}
        if os.getenv("DETECTION_POLLING_ENABLED", "true") != "false":
            raise FleetError("detection_recovery_requires_paused_polling", 409)
    if (
        not isinstance(body, dict)
        or set(body) - {"supersedes_request_id"} != fields
        or body["accept_unrecoverable"] is not True
    ):
        raise FleetError("invalid_detection_reconciliation")
    if any(
        type(body[k]) is not int or body[k] < 1
        for k in ("expected_generation", "expected_registration_rev")
    ):
        raise FleetError("invalid_detection_reconciliation")
    for key, pattern in [
        ("backfill_job_id", r"[A-Za-z0-9_-]{1,80}"),
        ("request_id", r"[a-f0-9]{32}"),
        ("plan_digest", r"[a-f0-9]{64}"),
    ]:
        if not isinstance(body[key], str) or not re.fullmatch(pattern, body[key]):
            raise FleetError("invalid_detection_reconciliation")
    if recovery:
        from .detection_handoff import OWNER

        for key, pattern in (("target_epoch", r"[a-f0-9]{32}"), ("target_owner", OWNER)):
            if not isinstance(body[key], str) or not re.fullmatch(pattern, body[key]):
                raise FleetError("invalid_detection_recovery")
    if not isinstance(body["reason"], str) or not 1 <= len(body["reason"]) <= 512 or not actor:
        raise FleetError("invalid_detection_reconciliation")
    collection = Detections(store)
    item = store.get_agent(name)
    digest = hashlib.sha256(
        canonical({**body, "recovery": True} if recovery else body).encode()
    ).hexdigest()
    prior = item.get("detection_reconciliation", {})
    if prior.get("request_id") == body["request_id"]:
        if prior["request_digest"] != digest:
            raise FleetError("detection_reconciliation_request_conflict", 409)
        from .detection_handoff import _enqueue

        pending = prior["request_id"] != collection.checkpoint(name).get("reconciled_request_id")
        return {
            "request_id": body["request_id"],
            "state": "accepted",
            "idempotent": True,
            "refresh_queued": _enqueue(store, item) if pending else False,
        }
    checkpoint = collection.checkpoint(name)
    handoff = item.get("detection_handoff", {})
    if handoff and handoff["request_id"] != checkpoint.get("handoff_request_id"):
        raise FleetError("detection_handoff_already_pending", 409)
    if body.get("supersedes_request_id") is not None and body["supersedes_request_id"] != prior.get(
        "request_id"
    ):
        raise FleetError("detection_reconciliation_request_conflict", 409)
    if (
        prior
        and prior["request_id"] != checkpoint.get("reconciled_request_id")
        and body.get("supersedes_request_id") != prior["request_id"]
    ):
        raise FleetError("detection_reconciliation_already_pending", 409)
    approved = {**body, "request_digest": digest, "requested_by": actor, "requested_at": now_iso()}
    if recovery:
        from .detection_recovery import checkpoint_context

        approved.update(recovery=True, previous_checkpoint=checkpoint_context(checkpoint))
    prior_condition = (
        "detection_reconciliation.request_digest = :prior"
        if prior
        else "attribute_not_exists(detection_reconciliation)"
    )
    handoff_condition = (
        "detection_handoff.request_digest = :handoff"
        if handoff
        else "attribute_not_exists(detection_handoff)"
    )
    try:
        store.client.transact_write_items(
            TransactItems=[
                {
                    "ConditionCheck": {
                        "TableName": collection.table.name,
                        "Key": wire({"pk": "AGENT#" + name, "sk": "CHECKPOINT"}),
                        "ConditionExpression": "generation = :generation"
                        + ("" if recovery else " AND #state = :gap"),
                        **({} if recovery else {"ExpressionAttributeNames": {"#state": "state"}}),
                        "ExpressionAttributeValues": wire(
                            {
                                ":generation": body["expected_generation"],
                                **({} if recovery else {":gap": "gap"}),
                            }
                        ),
                    }
                },
                {
                    "Update": {
                        "TableName": store.registry.name,
                        "Key": wire({"id": item["id"]}),
                        "ConditionExpression": (
                            "rev = :rev AND enabled = :yes AND auth_mode = :iam AND "
                            "(attribute_not_exists(detection_lease_until) OR "
                            "detection_lease_until < :now) AND "
                            + prior_condition
                            + " AND "
                            + handoff_condition
                        ),
                        "UpdateExpression": "SET detection_reconciliation = :request",
                        "ExpressionAttributeValues": wire(
                            {
                                ":rev": body["expected_registration_rev"],
                                ":yes": True,
                                ":iam": "iam",
                                ":now": int(time.time()),
                                ":request": approved,
                                **({":prior": prior["request_digest"]} if prior else {}),
                                **({":handoff": handoff["request_digest"]} if handoff else {}),
                            }
                        ),
                    }
                },
                {
                    "Put": {
                        "TableName": collection.table.name,
                        "Item": wire(
                            {
                                "pk": "RECONCILIATION#" + body["request_id"],
                                "sk": "REQUEST",
                                "agent_id": name,
                                **approved,
                            }
                        ),
                        "ConditionExpression": "attribute_not_exists(pk)",
                    }
                },
            ]
        )
    except ClientError as error:
        if error.response["Error"]["Code"] == "TransactionCanceledException":
            raise FleetError("detection_reconciliation_checkpoint_conflict", 409) from None
        raise
    queued = True
    try:
        store.enqueue_many(
            [item], int(time.time() * 1000), queue_url=os.environ["DETECTION_QUEUE_URL"]
        )
    except Exception:
        # Accepted intent remains durable; the next enabled schedule will retry.
        queued = False
    return {"request_id": body["request_id"], "state": "accepted", "refresh_queued": queued}


def execute(collection, item, token, previous, agent):
    approved = item["detection_reconciliation"]
    if item["rev"] != approved["expected_registration_rev"] or (
        previous.get("generation") != approved["expected_generation"]
        and previous.get("reconciliation_pending_request") != approved["request_id"]
    ):
        raise FleetError("detection_reconciliation_checkpoint_conflict", 409)
    code, job = agent.request("GET", "/detections/backfills/" + approved["backfill_job_id"])
    if code != 200:
        raise FleetError("detection_backfill_status_unavailable", 409)
    _owner(job, item)
    if job.get("state") != "completed" or job.get("plan_digest") != approved["plan_digest"]:
        raise FleetError("detection_backfill_not_eligible", 409)
    if approved.get("recovery"):
        from .detection_recovery import execute

        return execute(collection, item, token, previous, agent, job)
    name = previous.get("consumer_id") or consumer_id(item)
    path = "/detections/consumers/" + name
    if previous.get("consumer_id"):
        code, remote = agent.delivery_request("GET", path)
    else:
        initial = {}
        if previous.get("cursor"):
            initial = {
                "initial_cursor": previous["cursor"],
                "checkpoint_sha256": hashlib.sha256(
                    canonical(
                        {
                            "agent_id": item["agent_id"],
                            "cursor": previous["cursor"],
                            "last_sequence": previous.get("last_sequence", 0),
                        }
                    ).encode()
                ).hexdigest(),
            }
        code, remote = agent.delivery_request("POST", path, body=initial)
    if code != 200:
        raise FleetError("detection_consumer_reconciliation_unavailable", 409)
    _owner(remote, item)
    _state(remote, name)
    body = {
        k: approved[k]
        for k in ("backfill_job_id", "plan_digest", "reason", "accept_unrecoverable", "request_id")
    }
    body["expected_rev"] = remote["rev"]
    code, remote = agent.delivery_request("POST", path + "/reconcile", body=body)
    if code != 200:
        raise FleetError("detection_consumer_reconciliation_failed", 409)
    _owner(remote, item)
    _state(remote, name)
    audit = remote.get("last_reconciliation", {})
    if (
        audit.get("request_id") != approved["request_id"]
        or audit.get("plan_digest") != approved["plan_digest"]
        or remote.get("acknowledged_cursor") != job.get("start_cursor")
        or remote.get("acknowledged_sequence") != job.get("start_sequence")
    ):
        raise FleetError("invalid_detection_reconciliation_receipt", 502)
    state = {
        **previous,
        "state": "catching_up",
        "cursor": remote["acknowledged_cursor"],
        "last_sequence": remote["acknowledged_sequence"],
        "consumer_id": name,
        "consumer_rev": remote["rev"],
        "consumer_receipt_id": None,
        "consumer_acknowledged_sequence": remote["acknowledged_sequence"],
        "delivery_protocol": "receipts-v1",
        "reconciled_request_id": approved["request_id"],
        "verified_registration_rev": None,
        "last_reconciliation": {
            k: audit[k]
            for k in (
                "request_id",
                "backfill_job_id",
                "plan_digest",
                "reason",
                "at",
                "accept_unrecoverable",
                "history_complete",
                "backfill_counts",
                "missing_history_count",
            )
        },
    }
    state.pop("error_code", None)
    state.pop("reconciliation_pending_request", None)
    put, state = collection._checkpoint_put(item, previous, state)
    collection.store.client.transact_write_items(
        TransactItems=[collection._fence(item, token), put]
    )
    return state
