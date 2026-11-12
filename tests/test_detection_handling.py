import hashlib
import time
from unittest.mock import MagicMock

import pytest
from test_detections import iam_agent as iam_agent_fixture
from test_detections import page

from opencdr_fleet._contracts.detection_handling import initial
from opencdr_fleet.agent import Agent, route
from opencdr_fleet.detection_handling import handle
from opencdr_fleet.detection_queries import handle as query
from opencdr_fleet.detections import Detections, validate_page
from opencdr_fleet.models import FleetError

iam_agent = iam_agent_fixture


def state(rev=1, status="acknowledged"):
    return {
        **initial(),
        "rev": rev,
        "status": status,
        "updated_by": "aws:111111111111:AROAABCDEFGHIJKLMNOP",
        "updated_at": "2026-01-01T00:00:00Z",
    }


def test_projection_preserves_evidence_expiry_and_newer_metadata_on_every_replay(
    detection_store, iam_agent
):
    collection = Detections(detection_store)
    original = page()["items"][0]

    def persist(entry):
        detection_store.client.transact_write_items(
            TransactItems=[collection._record(iam_agent, entry)]
        )

    def stored():
        return collection.table.get_item(
            Key={"pk": "AGENT#account-a", "sk": "DETECTION#" + hashlib.sha256(b"d-1").hexdigest()}
        )["Item"]

    persist(original)
    first = stored()
    edited = {
        **original,
        "schema_version": "1.2.0",
        "change_type": "detection.handling_updated",
        "handling": state(2, "resolved"),
        "revision": 2,
        "indexed_committed_at": original["committed_at"],
        "source_expires_at": int(time.time()) + 86400,
    }
    persist(edited)
    result = stored()
    assert result["handling"]["rev"] == 2
    assert {k: v for k, v in result.items() if k != "handling"} == first
    for replay in [
        original,
        {**edited, "handling": state(1), "revision": 1},
        {
            **original,
            "change_type": "detection.backfilled",
            "indexed_committed_at": original["committed_at"],
            "source_expires_at": int(time.time()) + 86400,
        },
    ]:
        persist(replay)
        assert stored() == result
    with pytest.raises(FleetError, match="revision_conflict"):
        persist({**edited, "handling": state(2, "open")})
    with pytest.raises(FleetError, match="evidence_conflict"):
        persist({**edited, "payload": {**edited["payload"], "tampered": True}})
    _, listing = query("/v1/detections", {"status": "resolved"}, detection_store)
    assert listing["items"][0]["handling"]["status"] == "resolved"
    _, summary = query("/v1/detections/summary", {}, detection_store)
    assert summary["counts_by_status"]["resolved"] == 1


def test_handling_event_first_arrival_uses_original_time_and_never_extends_retention(
    detection_store, iam_agent
):
    collection = Detections(detection_store)
    entry = page()["items"][0]
    entry.update(
        schema_version="1.2.0",
        change_type="detection.handling_updated",
        handling=state(),
        indexed_committed_at=entry["committed_at"],
        source_expires_at=int(time.time()) + 60,
    )
    operation = collection._record(iam_agent, entry)
    detection_store.client.transact_write_items(TransactItems=[operation])
    rows = collection.table.scan()["Items"]
    assert rows[0]["expires_at"] == entry["source_expires_at"]
    assert rows[0]["handling"]["rev"] == 1 and rows[0]["revision"] == 1
    value = page()
    value.update(schema_version="1.2.0", items=[entry])
    validate_page(value, iam_agent, {})
    for bad in [
        {**entry, "revision": 2},
        {**entry, "handling": {**state(), "rev": True}},
        {**entry, "handling": {**state(), "updated_by": None}},
        {**entry, "schema_version": "1.1.0"},
    ]:
        with pytest.raises(FleetError, match="invalid_detection_feed_page"):
            validate_page({**value, "items": [bad]}, iam_agent, {})


def test_dedicated_forwarding_requires_triage_opt_in_and_verified_owner(
    detection_store, iam_agent, monkeypatch
):
    make = MagicMock()
    with pytest.raises(FleetError, match="agent_triage_disabled"):
        handle(detection_store, "account-a", "PUT", False, {"detection_id": "id"}, {}, make)
    make.assert_not_called()
    item = {**iam_agent, "allow_triage": True}
    monkeypatch.setattr(detection_store, "get_agent", lambda _: item)
    monkeypatch.setenv("FLEET_MANAGEMENT_ACCESS", "observer")
    with pytest.raises(FleetError, match="triage_access_required"):
        handle(detection_store, "account-a", "PUT", False, {"detection_id": "id"}, {}, make)
    monkeypatch.setenv("FLEET_MANAGEMENT_ACCESS", "triage")
    agent = make.return_value
    agent.verify.return_value = {"capabilities": {"detection_handling": "1.0.0"}}
    agent.handling_request.return_value = (
        200,
        {
            "deployment": {
                "account_id": item["account_id"],
                "home_region": item["region"],
                "stage": item["stage"],
            },
            "detection_id": "id",
            "handling": state(),
        },
    )
    code, result = handle(
        detection_store,
        "account-a",
        "PUT",
        False,
        {"detection_id": "id"},
        {"expected_rev": 0},
        make,
    )
    assert code == 200 and result["projection_state"] == "pending"
    assert result["handling"]["rev"] == 1
    agent.handling_request.assert_called_once_with(
        "PUT", "/detections/handling", query={"detection_id": "id"}, body={"expected_rev": 0}
    )
    agent.handling_request.return_value = (200, {"deployment": {}, "detection_id": "id"})
    with pytest.raises(FleetError, match="identity"):
        handle(detection_store, "account-a", "GET", False, {"detection_id": "id"}, None, make)


def test_generic_proxy_cannot_bypass_handling_opt_in_and_signer_uses_triage(
    detection_store, iam_agent
):
    with pytest.raises(FleetError, match="unsupported_core_route"):
        route("PUT", "/detections/handling")
    agent = Agent({**iam_agent, "allow_triage": True}, "")
    response = MagicMock()
    response.__enter__.return_value = response
    response.code = 200
    response.read.return_value = b"{}"
    agent.opener.open = MagicMock(return_value=response)
    agent.handling_request(
        "PUT", "/detections/handling", query={"detection_id": "id/1"}, body={"expected_rev": 0}
    )
    request = agent.opener.open.call_args.args[0]
    assert "/management/triage/detections/handling?detection_id=id%2F1" in request.full_url
    assert request.get_header("Authorization").startswith("AWS4-HMAC-SHA256")
    with pytest.raises(FleetError, match="unsupported_handling_route"):
        agent.handling_request("PUT", "/rules/example", body={})
