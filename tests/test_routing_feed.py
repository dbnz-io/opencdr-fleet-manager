import time

import pytest
from test_detections import factory, message, page
from test_detections import iam_agent as iam_agent_fixture

from opencdr_fleet._contracts.case_contract import CaseError
from opencdr_fleet.detections import collect_detections
from opencdr_fleet.routing_feed import RoutingFeed

iam_agent = iam_agent_fixture


def test_projection_cutover_pages_and_provenance(detection_store, iam_agent):
    collect_detections(detection_store, message(int(time.time() * 1000)), factory(page())[0])
    feed = RoutingFeed(detection_store)
    start = feed.start(["account-a"])["account-a"]
    value = page(sequence=2, count=3)
    value["items"][0]["payload"]["_opencdr_delivery"] = {"schema": "1.0.0", "origin": "live"}
    collect_detections(detection_store, message(int(time.time() * 1000) + 1), factory(value)[0])
    result = feed.read("account-a", start, 2)
    assert len(result["items"]) == 2 and result["has_more"]
    assert result["position"]["sequence"] == 3
    assert feed.resolve("account-a", result["items"][0])["routing_eligibility"]["source"] == "live"
    assert (
        feed.resolve("account-a", result["items"][1])["routing_eligibility"]["source"]
        == "ineligible"
    )
    assert len(feed.read("account-a", result["position"], 20)["items"]) == 1


def test_projection_gap_and_registration_change_fail_closed(detection_store, iam_agent):
    collect_detections(detection_store, message(int(time.time() * 1000)), factory(page())[0])
    feed = RoutingFeed(detection_store)
    start = feed.start(["account-a"])["account-a"]
    collect_detections(
        detection_store, message(int(time.time() * 1000) + 1), factory(page(sequence=2, count=2))[0]
    )
    feed.collection.table.delete_item(
        Key={"pk": "ROUTING_FEED#account-a#" + start["epoch"], "sk": f"{2:020d}"}
    )
    with pytest.raises(CaseError, match="routing_retention_gap"):
        feed.read("account-a", start, 20)
    detection_store.registry.update_item(
        Key={"id": iam_agent["id"]},
        UpdateExpression="SET rev=:rev",
        ExpressionAttributeValues={":rev": 2},
    )
    with pytest.raises(CaseError, match="routing_projection_unavailable"):
        feed.read("account-a", start, 20)
