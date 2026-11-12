"""Consumer receipt negotiation and recovery; callers persist before supplying ACK."""

import hashlib
import os
import re

from ._contracts.detection_query import canonical
from .models import FleetError


def consumer_id(item):
    identity = ":".join(
        (
            os.environ["SECURITY_ACCOUNT_ID"],
            os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "")),
            os.environ["FLEET_STAGE"],
            item["agent_id"],
        )
    )
    return "fleet-" + hashlib.sha256(identity.encode()).hexdigest()[:40]


def _owner(value, item):
    if not isinstance(value, dict) or value.get("deployment") != {
        "account_id": item["account_id"],
        "home_region": item["region"],
        "stage": item["stage"],
    }:
        raise FleetError("invalid_detection_consumer_identity", 502)


def _state(value, name):
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != "1.0.0"
        or value.get("consumer_id") != name
        or type(value.get("rev")) is not int
        or value["rev"] < 1
    ):
        raise FleetError("invalid_detection_consumer_state", 502)
    if value.get("principal") is not None and (
        not isinstance(value["principal"], str)
        or not re.fullmatch(
            r"aws(?:-us-gov|-cn)?:[0-9]{12}:(?:AROA|AIDA)[A-Z0-9]{12,64}", value["principal"]
        )
    ):
        raise FleetError("invalid_detection_consumer_state", 502)


def _principal(remote, previous):
    if previous.get("consumer_owner") and remote.get("principal") != previous["consumer_owner"]:
        raise FleetError("detection_consumer_owner_changed", 409)


def _reconcile(remote, previous, name):
    _state(remote, name)
    _principal(remote, previous)
    body = {"expected_rev": remote["rev"]}
    sequence = int(previous.get("last_sequence", 0))
    pending = remote.get("pending") or {}
    if remote.get("acknowledged_sequence") == sequence and (
        remote.get("acknowledged_cursor") == previous.get("cursor")
        or sequence == 0
        and not previous.get("cursor")
    ):
        return body
    if (
        previous.get("consumer_receipt_id")
        and pending.get("receipt_id") == previous["consumer_receipt_id"]
        and pending.get("to_cursor") == previous.get("cursor")
        and pending.get("to_sequence") == sequence
    ):
        return {**body, "receipt_id": previous["consumer_receipt_id"]}
    raise FleetError("detection_consumer_checkpoint_conflict", 409)


def read_page(agent, item, previous, limit):
    name = previous.get("consumer_id") or consumer_id(item)
    path = "/detections/consumers/" + name
    if previous.get("consumer_id"):
        body = {"expected_rev": int(previous["consumer_rev"])}
        if previous.get("consumer_receipt_id"):
            body["receipt_id"] = previous["consumer_receipt_id"]
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
            raise FleetError(f"detection_consumer_registration_http_{code}", 502)
        _owner(remote, item)
        body = _reconcile(remote, previous, name)
    code, page = agent.delivery_request("POST", path + "/read", body={**body, "limit": limit})
    if code == 409:
        # A previous read/ACK may have committed before its response was lost.
        # Reconcile only against the locally durable cursor/receipt; never adopt
        # remote progress beyond the records actually held in Fleet.
        status, remote = agent.delivery_request("GET", path)
        if status != 200:
            raise FleetError(f"detection_consumer_status_http_{status}", 502)
        _owner(remote, item)
        body = _reconcile(remote, previous, name)
        code, page = agent.delivery_request("POST", path + "/read", body={**body, "limit": limit})
    if code == 410:
        raise FleetError("detection_retention_gap", 409)
    if code != 200:
        raise FleetError(f"detection_consumer_read_http_{code}", 502)
    _owner(page, item)
    remote = page.get("consumer")
    _state(remote, name)
    _principal(remote, previous)
    pending = remote.get("pending")
    try:
        if remote["acknowledged_sequence"] != int(previous.get("last_sequence", 0)):
            raise ValueError
        if previous.get("cursor") and remote["acknowledged_cursor"] != previous["cursor"]:
            raise ValueError
        if page["items"]:
            if (
                not isinstance(pending, dict)
                or not isinstance(pending.get("receipt_id"), str)
                or len(pending["receipt_id"]) != 32
                or pending["from_cursor"] != remote["acknowledged_cursor"]
                or pending["to_cursor"] != page["next_cursor"]
                or pending["to_sequence"] != page["items"][-1]["sequence"]
                or pending["count"] != len(page["items"])
            ):
                raise ValueError
        elif pending or page["next_cursor"] != remote["acknowledged_cursor"]:
            raise ValueError
    except (ValueError, TypeError, KeyError, IndexError):
        raise FleetError("invalid_detection_consumer_receipt", 502) from None
    return page, {
        "consumer_id": name,
        **({"consumer_owner": remote["principal"]} if remote.get("principal") else {}),
        "consumer_rev": remote["rev"],
        "consumer_receipt_id": pending["receipt_id"] if pending else None,
        "consumer_acknowledged_sequence": remote["acknowledged_sequence"],
        "delivery_protocol": "receipts-v1",
    }
