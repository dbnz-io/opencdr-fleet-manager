import time

import pytest
from test_polling import factory, message

from opencdr_fleet.api import dispatch
from opencdr_fleet.models import FleetError
from opencdr_fleet.polling import poll
from opencdr_fleet.polling_policy import intervals, monthly_requests, stale_after_seconds


def test_five_minute_polling_scales_cost_and_staleness(monkeypatch):
    monkeypatch.setenv("POLL_INTERVAL_MINUTES", "5")
    monkeypatch.setenv("FULL_REFRESH_MINUTES", "60")
    assert intervals()[:2] == (300, 3600)
    assert stale_after_seconds() == 900
    assert monthly_requests(10, generation_supported=True) == 15624
    assert monthly_requests(10, generation_supported=False) == 89280


@pytest.mark.parametrize("poll,refresh", [(0, 60), (61, 60), (5, 2), (5, 1441), ("bad", 60)])
def test_invalid_intervals_fail_closed(monkeypatch, poll, refresh):
    monkeypatch.setenv("POLL_INTERVAL_MINUTES", str(poll))
    monkeypatch.setenv("FULL_REFRESH_MINUTES", str(refresh))
    with pytest.raises(FleetError, match="invalid_polling_configuration"):
        intervals()


def test_refresh_is_limited_by_snapshot_retention(monkeypatch):
    monkeypatch.setenv("POLL_INTERVAL_MINUTES", "5")
    monkeypatch.setenv("FULL_REFRESH_MINUTES", "1440")
    monkeypatch.setenv("SNAPSHOT_RETENTION_HOURS", "2")
    assert monthly_requests(10, generation_supported=True) == 15624


def test_configured_refresh_age_recollects_unchanged_configuration(
    monkeypatch, store, agent_record, report
):
    monkeypatch.setenv("FULL_REFRESH_MINUTES", "2")
    report["configuration"] = {"supported": True, "generation": "v1", "writing": False}
    seq = int(time.time() * 1000)
    poll(store, message(seq), factory(report))
    store.status.update_item(
        Key={"agent_id": "account-a"},
        UpdateExpression="SET full_snapshot_ms = :old",
        ExpressionAttributeValues={":old": seq - 180_000},
    )
    poll(store, message(seq + 1), factory(report))
    assert store.get_status("account-a")["poll_request_count"] > 1


def test_status_reports_scope_and_actual_configured_intervals(monkeypatch, store):
    monkeypatch.setenv("POLL_INTERVAL_MINUTES", "5")
    monkeypatch.setenv("FULL_REFRESH_MINUTES", "120")
    code, result = dispatch({"httpMethod": "GET", "path": "/v1/status"}, store)
    assert code == 200
    assert result["poll_interval_seconds"] == 300
    assert result["full_refresh_interval_seconds"] == 7200
    assert result["polling_scope"] == ["health", "configuration"]
    assert result["capabilities"]["detection_delivery"] is False


def test_five_minute_agent_not_marked_stale_after_four_minutes(
    monkeypatch, store, agent_record, report
):
    monkeypatch.setenv("POLL_INTERVAL_MINUTES", "5")
    seq = int(time.time() * 1000)
    poll(store, message(seq), factory(report))
    store.status.update_item(
        Key={"agent_id": "account-a"},
        UpdateExpression="SET status_success_ms = :old",
        ExpressionAttributeValues={":old": seq - 240_000},
    )
    assert store.view_status(store.get_agent("account-a"))["status_stale"] is False
