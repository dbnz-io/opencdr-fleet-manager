"""Explicit one-Core outcome reads. Detection lists never fan out for these."""

import time

from .agent import Agent
from .consumer_delivery import _owner
from .models import FleetError


def handle(store, name, method, history, query, agent_factory=Agent):
    if method != "GET":
        raise FleetError("method_not_allowed", 405)
    item = store.get_agent(name)
    if not item["enabled"] or item["auth_mode"] != "iam":
        raise FleetError("agent_outcomes_unavailable", 409)
    agent = agent_factory(item, "", deadline=time.monotonic() + 20)
    report = agent.verify()
    from ._contracts.delegation import CURRENT

    if CURRENT.get() and report.get("capabilities", {}).get("trusted_identity") != "1.0.0":
        raise FleetError("agent_delegation_unavailable", 409)
    if report.get("capabilities", {}).get("response_outcomes") != "1.0.0":
        raise FleetError("agent_outcomes_unavailable", 409)
    code, result = agent.outcomes_request(
        "/detections/outcomes" + ("/history" if history else ""), query=query
    )
    if code == 200:
        _owner(result, item)
        if (
            result.get("detection_id") != query.get("detection_id")
            or not isinstance(result.get("items"), list)
            or len(result["items"]) > 50
            or any(
                not isinstance(row, dict)
                or row.get("source_detection_id") != query.get("detection_id")
                or (history and row.get("attempt_id") != query.get("attempt_id"))
                for row in result["items"]
            )
        ):
            raise FleetError("invalid_outcome_identity", 502)
    return code, result
