"""Principal-isolated delivery relay. No management key or consumer reset route."""

import hashlib
import os
import re

from ._contracts.approval_contract import require
from ._contracts.case_api import Access
from ._contracts.case_contract import principal
from ._contracts.delegation import CURRENT
from .agent import Agent


def handle(store, method, name, consumer, action, body, identity):
    require(not CURRENT.get(), "subscription_requires_service_iam", 403)
    actor = principal(identity)
    require(isinstance(body, dict), "invalid_delivery_request")
    allowed = {
        None: {"initial_cursor", "checkpoint_sha256"} if method == "POST" else set(),
        "read": {"expected_rev", "limit"},
        "ack": {"expected_rev", "receipt_id"},
    }
    require(action in allowed and set(body) <= allowed[action], "invalid_delivery_request")
    if action is None and body:
        require(
            set(body) == {"initial_cursor", "checkpoint_sha256"}
            and isinstance(body["initial_cursor"], str)
            and 1 <= len(body["initial_cursor"]) <= 4096
            and isinstance(body["checkpoint_sha256"], str)
            and re.fullmatch(r"[a-f0-9]{64}", body["checkpoint_sha256"]) is not None,
            "invalid_subscription_checkpoint",
        )
    # Core registration is create-only: a different initial checkpoint conflicts.
    # Existing receipts, consumer recovery and reset routes are never exposed.
    require(
        re.fullmatch(r"[A-Za-z0-9_-]{1,64}", consumer) is not None
        and action in {None, "read", "ack"}
        and method in {"GET", "POST"}
        and (method != "GET" or action is None),
        "invalid_delivery_route",
    )
    access = Access(store.client, os.environ["CASE_TABLE_NAME"], actor, store.get_agent)
    before = access.read(actor)
    require(name in before["agent_ids"], "delivery_scope_forbidden", 403)
    registration = store.get_agent(name)
    require(
        registration["enabled"] and registration.get("auth_mode") == "iam",
        "delivery_agent_unavailable",
        409,
    )
    # The Core caller is this Lambda role. Include the actual external principal
    # in its consumer ID so two Fleet principals never share receipts.
    fixed = "subscriber-" + hashlib.sha256((actor + ":" + consumer).encode()).hexdigest()
    agent = Agent(registration, "")
    report = agent.verify()
    require(
        report.get("capabilities", {}).get("detection_consumers") == "1.0.0",
        "delivery_capability_unavailable",
        409,
    )
    require(
        access.read(actor)["rev"] == before["rev"]
        and store.get_agent(name)["rev"] == registration["rev"],
        "delivery_authority_changed",
        403,
    )
    code, result = agent.delivery_request(
        method,
        "/detections/consumers/" + fixed + ("/" + action if action else ""),
        body=body if method == "POST" else None,
    )
    require(access.read(actor)["rev"] == before["rev"], "delivery_authority_changed", 403)
    if code == 200:
        require(isinstance(result, dict), "delivery_response_invalid", 502)
        if action == "read":
            require(
                result.get("deployment")
                == {
                    "account_id": registration["account_id"],
                    "home_region": registration["region"],
                    "stage": registration["stage"],
                },
                "delivery_owner_identity_mismatch",
                502,
            )
        state = result.get("consumer", result)
        require(isinstance(state, dict), "delivery_response_invalid", 502)
        require(state.get("consumer_id") == fixed, "delivery_consumer_identity_mismatch", 502)
        state["consumer_id"], state["principal"] = consumer, actor
    return code, result
