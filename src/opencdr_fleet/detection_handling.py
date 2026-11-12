"""One-account triage forwarding; central browsing remains entirely local."""

import os
import time

from .agent import Agent
from .consumer_delivery import _owner
from .handling_projection import validate_state
from .models import FleetError


def handle(store, name, method, history, query, body, agent_factory=Agent):
    item = store.get_agent(name)
    if method not in {"GET", "PUT"} or history and method != "GET":
        raise FleetError("method_not_allowed", 405)
    if method == "PUT":
        if os.getenv("FLEET_MANAGEMENT_ACCESS", "administrator") not in {
            "triage",
            "operator",
            "responder",
            "administrator",
        }:
            raise FleetError("triage_access_required", 403)
        if not item.get("allow_triage", False):
            raise FleetError("agent_triage_disabled", 403)
    if not item["enabled"] or item["auth_mode"] != "iam":
        raise FleetError("agent_triage_unavailable", 409)
    agent = agent_factory(item, "", deadline=time.monotonic() + 20)
    report = agent.verify()
    from ._contracts.delegation import CURRENT

    if CURRENT.get() and report.get("capabilities", {}).get("trusted_identity") != "1.0.0":
        raise FleetError("agent_delegation_unavailable", 409)
    if report.get("capabilities", {}).get("detection_handling") != "1.0.0":
        raise FleetError("agent_handling_unavailable", 409)
    path = "/detections/handling" + ("/history" if history else "")
    code, result = agent.handling_request(
        method, path, query=query, body=body if method == "PUT" else None
    )
    if code == 200:
        _owner(result, item)
        if result.get("detection_id") != query.get("detection_id"):
            raise FleetError("invalid_detection_handling_identity", 502)
        if not history:
            try:
                validate_state(result.get("handling"), allow_initial=method == "GET")
            except (ValueError, TypeError, KeyError):
                raise FleetError("invalid_detection_handling_response", 502) from None
        if method == "PUT":
            from .detection_handoff import _enqueue

            result = {
                **result,
                "projection_state": "pending",
                "refresh_queued": _enqueue(store, item),
            }
    return code, result
