from unittest.mock import MagicMock

import pytest

from opencdr_fleet import response_outcomes
from opencdr_fleet.models import FleetError


def test_selected_outcome_read_verifies_capability_and_identity():
    item = {
        "enabled": True,
        "auth_mode": "iam",
        "account_id": "111111111111",
        "region": "us-east-1",
        "stage": "dev",
    }
    store = MagicMock()
    store.get_agent.return_value = item
    agent = MagicMock()
    agent.verify.return_value = {"capabilities": {"response_outcomes": "1.0.0"}}
    result = {
        "deployment": {
            "account_id": item["account_id"],
            "home_region": item["region"],
            "stage": "dev",
        },
        "detection_id": "d",
        "items": [{"source_detection_id": "d", "attempt_id": "a" * 32}],
    }
    agent.outcomes_request.return_value = (200, result)
    factory = MagicMock(return_value=agent)
    assert response_outcomes.handle(store, "a", "GET", False, {"detection_id": "d"}, factory) == (
        200,
        result,
    )
    factory.assert_called_once()
    agent.outcomes_request.assert_called_once_with(
        "/detections/outcomes", query={"detection_id": "d"}
    )
    result["items"][0]["source_detection_id"] = "another"
    with pytest.raises(FleetError, match="invalid_outcome_identity"):
        response_outcomes.handle(store, "a", "GET", False, {"detection_id": "d"}, factory)
    agent.verify.return_value = {"capabilities": {}}
    agent.outcomes_request.reset_mock()
    with pytest.raises(FleetError, match="unavailable"):
        response_outcomes.handle(store, "a", "GET", False, {"detection_id": "d"}, factory)
    agent.outcomes_request.assert_not_called()


def test_delegated_outcomes_fail_closed_when_core_lacks_identity():
    from opencdr_fleet._contracts.delegation import CURRENT

    store, agent = MagicMock(), MagicMock()
    store.get_agent.return_value = {"enabled": True, "auth_mode": "iam"}
    agent.verify.return_value = {"capabilities": {"response_outcomes": "1.0.0"}}
    token = CURRENT.set(MagicMock())
    try:
        with pytest.raises(FleetError, match="agent_delegation_unavailable"):
            response_outcomes.handle(store, "a", "GET", False, {}, lambda *a, **k: agent)
        agent.outcomes_request.assert_not_called()
    finally:
        CURRENT.reset(token)
