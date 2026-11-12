"""Durable reviewed handoff intent; only the detection worker accepts ownership."""

import hashlib
import os
import re
import time

from botocore.exceptions import ClientError

from ._contracts.detection_query import canonical
from .consumer_delivery import _owner, _reconcile
from .models import FleetError, now_iso
from .store import wire

OWNER = r"aws(?:-us-gov|-cn)?:[0-9]{12}:(?:AROA|AIDA)[A-Z0-9]{12,64}"


def _enqueue(store, item):
    try:
        store.enqueue_many(
            [item], int(time.time() * 1000), queue_url=os.environ["DETECTION_QUEUE_URL"]
        )
        return True
    except Exception:
        return False


def checkpoint(state):
    return {
        "cursor": state.get("cursor"),
        "sequence": int(state.get("last_sequence", 0)),
        "receipt_id": state.get("consumer_receipt_id"),
    }


def context(store, name):
    from .detections import Detections

    item = store.get_agent(name)
    state = Detections(store).checkpoint(name)
    if not state.get("consumer_id") or not state.get("cursor"):
        raise FleetError("detection_handoff_checkpoint_unavailable", 409)
    return {
        "agent_id": name,
        "consumer_id": state["consumer_id"],
        "previous_owner": state.get("consumer_owner"),
        "checkpoint": checkpoint(state),
        "expected_generation": int(state["generation"]),
        "expected_registration_rev": int(item["rev"]),
        "history_complete": False,
    }


def request(store, name, body, actor):
    from .detections import Detections

    fields = {
        "expected_generation",
        "expected_registration_rev",
        "handoff_id",
        "plan_digest",
        "target_owner",
        "reason",
        "request_id",
    }
    if not isinstance(body, dict) or set(body) - {"supersedes_request_id"} != fields or not actor:
        raise FleetError("invalid_detection_handoff")
    if any(
        type(body[k]) is not int or body[k] < 1
        for k in ("expected_generation", "expected_registration_rev")
    ):
        raise FleetError("invalid_detection_handoff")
    for field, pattern in [
        ("handoff_id", r"[A-Za-z0-9_-]{1,80}"),
        ("plan_digest", r"[a-f0-9]{64}"),
        ("target_owner", OWNER),
        ("request_id", r"[a-f0-9]{32}"),
    ]:
        if not isinstance(body[field], str) or not re.fullmatch(pattern, body[field]):
            raise FleetError("invalid_detection_handoff")
    if not isinstance(body["reason"], str) or not 1 <= len(body["reason"]) <= 512:
        raise FleetError("invalid_detection_handoff")
    collection = Detections(store)
    item, state = store.get_agent(name), collection.checkpoint(name)
    if not state.get("consumer_id") or not state.get("cursor"):
        raise FleetError("detection_handoff_checkpoint_unavailable", 409)
    reconciliation = item.get("detection_reconciliation", {})
    if reconciliation and reconciliation["request_id"] != state.get("reconciled_request_id"):
        raise FleetError("detection_reconciliation_already_pending", 409)
    prior = item.get("detection_handoff", {})
    digest = hashlib.sha256(canonical(body).encode()).hexdigest()
    if prior.get("request_id") == body["request_id"]:
        if prior["request_digest"] != digest:
            raise FleetError("detection_handoff_request_conflict", 409)
        pending = prior["request_id"] != state.get("handoff_request_id")
        return {
            "request_id": body["request_id"],
            "state": "accepted",
            "idempotent": True,
            "refresh_queued": _enqueue(store, item) if pending else False,
        }
    if body.get("supersedes_request_id") is not None and body["supersedes_request_id"] != prior.get(
        "request_id"
    ):
        raise FleetError("detection_handoff_request_conflict", 409)
    if (
        prior
        and prior["request_id"] != state.get("handoff_request_id")
        and body.get("supersedes_request_id") != prior["request_id"]
    ):
        raise FleetError("detection_handoff_already_pending", 409)
    approved = {
        **body,
        "request_digest": digest,
        "requested_by": actor,
        "requested_at": now_iso(),
        "checkpoint": checkpoint(state),
        "consumer_id": state["consumer_id"],
        "previous_owner": state.get("consumer_owner"),
    }
    prior_condition = (
        "detection_handoff.request_digest = :prior"
        if prior
        else "attribute_not_exists(detection_handoff)"
    )
    reconcile_condition = (
        "detection_reconciliation.request_digest = :reconcile"
        if reconciliation
        else "attribute_not_exists(detection_reconciliation)"
    )
    try:
        store.client.transact_write_items(
            TransactItems=[
                {
                    "ConditionCheck": {
                        "TableName": collection.table.name,
                        "Key": wire({"pk": "AGENT#" + name, "sk": "CHECKPOINT"}),
                        "ConditionExpression": "generation = :generation",
                        "ExpressionAttributeValues": wire(
                            {":generation": body["expected_generation"]}
                        ),
                    }
                },
                {
                    "Update": {
                        "TableName": store.registry.name,
                        "Key": wire({"id": item["id"]}),
                        "ConditionExpression": "rev = :rev AND enabled = :yes "
                        "AND auth_mode = :iam AND (attribute_not_exists(detection_lease_until) "
                        "OR detection_lease_until < :now) AND "
                        + prior_condition
                        + " AND "
                        + reconcile_condition,
                        "UpdateExpression": "SET detection_handoff = :request",
                        "ExpressionAttributeValues": wire(
                            {
                                ":rev": body["expected_registration_rev"],
                                ":yes": True,
                                ":iam": "iam",
                                ":now": int(time.time()),
                                ":request": approved,
                                **({":prior": prior["request_digest"]} if prior else {}),
                                **(
                                    {":reconcile": reconciliation["request_digest"]}
                                    if reconciliation
                                    else {}
                                ),
                            }
                        ),
                    }
                },
                {
                    "Put": {
                        "TableName": collection.table.name,
                        "Item": wire(
                            {
                                "pk": "HANDOFF#" + body["request_id"],
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
            raise FleetError("detection_handoff_checkpoint_conflict", 409) from None
        raise
    queued = _enqueue(store, item)
    return {"request_id": body["request_id"], "state": "accepted", "refresh_queued": queued}


def execute(collection, item, token, previous, agent):
    approved = item["detection_handoff"]
    # A retry after an uncertain result must use exactly the same durable cursor.
    if (
        item["rev"] != approved["expected_registration_rev"]
        or checkpoint(previous) != approved["checkpoint"]
        or previous.get("consumer_id") != approved["consumer_id"]
    ):
        raise FleetError("detection_handoff_checkpoint_conflict", 409)
    name = approved["consumer_id"]
    code, reviewed = agent.request("GET", "/detections/handoffs/" + approved["handoff_id"])
    if code != 200:
        raise FleetError("detection_handoff_plan_unavailable", 409)
    _owner(reviewed, item)
    if (
        reviewed.get("handoff_id") != approved["handoff_id"]
        or reviewed.get("plan_digest") != approved["plan_digest"]
        or reviewed.get("target_owner") != approved["target_owner"]
        or reviewed.get("checkpoint") != approved["checkpoint"]
        or reviewed.get("consumer_id") != name
        or approved.get("previous_owner")
        and reviewed.get("previous_owner") != approved["previous_owner"]
    ):
        raise FleetError("detection_handoff_plan_conflict", 409)
    code, result = agent.delivery_request(
        "POST",
        "/detections/consumers/" + name + "/handoff",
        body={"handoff_id": approved["handoff_id"], "plan_digest": approved["plan_digest"]},
    )
    if code != 200:
        raise FleetError("detection_handoff_acceptance_failed", 409)
    _owner(result, item)
    plan, remote = result.get("handoff", {}), result.get("consumer", {})
    if (
        plan.get("state") != "accepted"
        or plan.get("handoff_id") != approved["handoff_id"]
        or plan.get("plan_digest") != approved["plan_digest"]
        or plan.get("target_owner") != approved["target_owner"]
        or plan.get("checkpoint") != approved["checkpoint"]
        or approved.get("previous_owner")
        and plan.get("previous_owner") != approved["previous_owner"]
        or remote.get("principal") != approved["target_owner"]
        or remote.get("last_handoff_id") != approved["handoff_id"]
    ):
        raise FleetError("invalid_detection_handoff_receipt", 502)
    receipt = _reconcile(remote, {**previous, "consumer_owner": approved["target_owner"]}, name)
    state = {
        **previous,
        "consumer_owner": approved["target_owner"],
        "consumer_rev": remote["rev"],
        "consumer_receipt_id": receipt.get("receipt_id"),
        "consumer_acknowledged_sequence": remote["acknowledged_sequence"],
        "delivery_protocol": "receipts-v1",
        "handoff_request_id": approved["request_id"],
        "last_handoff": {
            k: plan[k]
            for k in (
                "handoff_id",
                "plan_digest",
                "previous_owner",
                "target_owner",
                "accepted_at",
                "history_complete",
            )
        },
        "verified_registration_rev": None,
        "state": "gap" if previous.get("state") == "gap" else "catching_up",
    }
    state.pop("error_code", None)
    state.pop("handoff_pending_request", None)
    put, state = collection._checkpoint_put(item, previous, state)
    collection.store.client.transact_write_items(
        TransactItems=[collection._fence(item, token), put]
    )
    return state
