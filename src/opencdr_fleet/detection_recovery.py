"""Explicit replay into a fresh consumer; retained Fleet records are preserved."""

from .consumer_delivery import _owner, _state
from .models import FleetError


def checkpoint_context(state):
    return {
        "cursor": state.get("cursor"),
        "sequence": int(state.get("last_sequence", 0)),
        "receipt_id": state.get("consumer_receipt_id"),
        "principal": state.get("consumer_owner"),
    }


def context(store, name):
    from .detections import Detections

    item, state = store.get_agent(name), Detections(store).checkpoint(name)
    return {
        "agent_id": name,
        "previous_checkpoint": checkpoint_context(state),
        "previous_consumer_id": state.get("consumer_id"),
        "expected_generation": int(state.get("generation", 0)),
        "expected_registration_rev": int(item["rev"]),
        "history_complete": False,
    }


def execute(collection, item, token, previous, agent, job):
    approved = item["detection_reconciliation"]
    if checkpoint_context(previous) != approved["previous_checkpoint"]:
        raise FleetError("detection_recovery_checkpoint_conflict", 409)
    name = "recovery-" + approved["request_id"]
    body = {
        k: approved[k]
        for k in (
            "backfill_job_id",
            "plan_digest",
            "reason",
            "accept_unrecoverable",
            "request_id",
            "target_epoch",
            "target_owner",
            "previous_checkpoint",
        )
    }
    code, remote = agent.delivery_request(
        "POST", "/detections/consumers/" + name + "/recover", body=body
    )
    if code != 200:
        raise FleetError("detection_consumer_recovery_failed", 409)
    _owner(remote, item)
    _state(remote, name)
    audit = remote.get("last_recovery", {})
    if (
        remote.get("principal") != approved["target_owner"]
        or audit.get("accepted_by") != approved["target_owner"]
        or any(audit.get(k) != v for k, v in body.items())
        or remote.get("acknowledged_cursor") != job.get("start_cursor")
        or remote.get("acknowledged_sequence") != job.get("start_sequence")
        or remote.get("pending")
        or audit.get("history_complete") is not False
        or audit.get("previous_checkpoint_verified") is not False
    ):
        raise FleetError("invalid_detection_recovery_receipt", 502)
    state = {
        **previous,
        "state": "recovery_paused",
        "cursor": remote["acknowledged_cursor"],
        "last_sequence": remote["acknowledged_sequence"],
        "consumer_id": name,
        "consumer_owner": remote["principal"],
        "consumer_rev": remote["rev"],
        "consumer_receipt_id": None,
        "consumer_acknowledged_sequence": remote["acknowledged_sequence"],
        "delivery_protocol": "receipts-v1",
        "reconciled_request_id": approved["request_id"],
        "verified_registration_rev": None,
        "last_recovery": {
            k: audit[k]
            for k in (
                "request_id",
                "backfill_job_id",
                "plan_digest",
                "target_epoch",
                "reason",
                "at",
                "accept_unrecoverable",
                "history_complete",
                "missing_history_count",
                "backfill_counts",
                "table_id",
                "previous_checkpoint_verified",
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
