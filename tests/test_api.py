import json
import time
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from opencdr_fleet import api, handlers
from opencdr_fleet.models import FleetError


def event(method, path, body=None, **params):
    return {
        "httpMethod": method,
        "path": path,
        "pathParameters": params,
        "body": json.dumps(body) if body is not None else None,
        "requestContext": {"identity": {"userArn": "arn:aws:iam::123456789012:role/operator"}},
    }


def test_fleet_read_endpoint_cannot_be_used_to_write(store):
    with pytest.raises(FleetError, match="requires_get"):
        api.dispatch(
            event(
                "POST",
                "/v1/fleet/read",
                {"agent_ids": ["account-a"], "method": "PUT", "path": "/rules/x"},
            ),
            store,
        )


@pytest.mark.parametrize("access", ["observer", "operator", "responder"])
def test_detection_reconciliation_requires_administrator(store, monkeypatch, access):
    monkeypatch.setenv("FLEET_MANAGEMENT_ACCESS", access)
    with pytest.raises(FleetError, match="requires_administrator"):
        api.dispatch(event("POST", "/v1/agents/member/detections/reconcile", {}), store)
    for method in ("GET", "POST"):
        with pytest.raises(FleetError):
            api.dispatch(event(method, "/v1/agents/member/detections/recover", {}), store)
    for method in ("GET", "POST"):
        with pytest.raises(FleetError, match="requires_administrator"):
            api.dispatch(event(method, "/v1/agents/member/detections/handoff", {}), store)


def test_manager_reports_its_security_account_region_and_stage(store):
    code, status = api.dispatch(event("GET", "/v1/status"), store)
    assert code == 200
    assert status["deployment"] == {
        "account_id": "123456789012",
        "home_region": "us-east-1",
        "stage": "test",
    }


def test_forwarding_checks_live_identity_and_preserves_partial_agent_result(store, agent_record):
    store.credentials = Mock(return_value=("read", "write"))
    agent = Mock()
    agent.verify.return_value = {}
    agent.request.return_value = (
        409,
        {"message": "conflict", "completed": [{"rule_id": "applied"}]},
    )
    results = api.forward_many(
        store,
        ["account-a"],
        "POST",
        "/rule-releases/apply",
        body={},
        agent_factory=lambda *a, **k: agent,
    )
    assert results[0]["body"]["completed"] == [{"rule_id": "applied"}]
    assert agent.method_calls[0][0] == "verify"
    agent.request.assert_called_once()


def test_mismatched_identity_is_not_a_write_with_an_unknown_outcome(store, agent_record):
    store.credentials = Mock(return_value=("read", "write"))
    agent = Mock()
    agent.verify.side_effect = FleetError("agent_identity_mismatch", 409)
    result = api.forward_many(
        store, ["account-a"], "PUT", "/rules/x", body={}, agent_factory=lambda *a, **k: agent
    )[0]
    assert result["attempted"] is False and result["outcome"] == "not_sent"
    agent.request.assert_not_called()


def test_refresh_enqueue_failure_does_not_turn_an_accepted_write_into_a_failed_write(
    store, agent_record
):
    store.credentials = Mock(return_value=("read", "write"))
    store.enqueue = Mock(side_effect=RuntimeError("queue unavailable"))
    agent = Mock()
    agent.verify.return_value = {}
    agent.request.return_value = (202, {"run_id": "one-run"})
    result = api.forward_many(
        store,
        ["account-a"],
        "POST",
        "/integrations/runtime/jobs/job/replay",
        agent_factory=lambda *a, **k: agent,
    )[0]
    assert result["status_code"] == 202 and result["refresh_queued"] is False
    assert result["body"]["run_id"] == "one-run"
    agent.request.assert_called_once()


def test_bulk_is_explicit_bounded_and_keeps_per_target_failures(store, agent_record):
    for names in ([], ["account-a"] * 2, [f"a{x}" for x in range(9)]):
        with pytest.raises(FleetError, match="select_1_to_8"):
            api.forward_many(store, names, "GET", "/status")
    store.credentials = Mock(return_value=("read", None))
    agent = Mock()
    agent.verify.return_value = {"status": "ok"}
    result = api.forward_many(
        store, ["account-a", "missing"], "GET", "/status", agent_factory=lambda *a, **k: agent
    )
    assert result[0]["status_code"] == 200
    assert result[1]["error_code"] == "agent_not_found"
    assert result[1]["attempted"] is False


def test_failed_write_is_never_retried_by_fleet(store, agent_record):
    store.credentials = Mock(return_value=("read", "write"))
    agent = Mock()
    agent.request.side_effect = FleetError("agent_unreachable", 502)
    result = api.forward_many(
        store,
        ["account-a"],
        "POST",
        "/ir-actions/d/rollback",
        body={},
        agent_factory=lambda *a, **k: agent,
    )[0]
    assert result["outcome"] == "unknown"
    agent.request.assert_called_once()


def test_bulk_payload_budget_keeps_statuses_after_writes(store, agent_record):
    store.get_agent = lambda name: {**agent_record, "agent_id": name}
    store.credentials = lambda *a, **k: ("read", "write")
    store.enqueue = lambda *a: None
    agent = Mock()
    agent.request.return_value = (200, {"large": "x" * 1_800_000})
    results = api.forward_many(
        store,
        ["a", "b", "c"],
        "POST",
        "/rules/evaluate",
        body={},
        agent_factory=lambda *a, **k: agent,
    )
    assert [row["status_code"] for row in results] == [200, 200, 200]
    assert any(row.get("body_omitted") for row in results)


def test_api_refuses_missing_iam_identity_and_wrong_security_account(store):
    context = SimpleNamespace(
        invoked_function_arn="arn:aws:lambda:us-east-1:123456789012:function:fleet",
        aws_request_id="request",
    )
    assert handlers.api({"path": "/v1/status", "httpMethod": "GET"}, context)["statusCode"] == 403
    context.invoked_function_arn = "arn:aws:lambda:us-east-1:999999999999:function:fleet"
    assert handlers.api(event("GET", "/v1/status"), context)["statusCode"] == 503


def test_scheduled_dispatch_uses_minute_sequences_and_batches_only_enabled_agents(
    store, agent_record
):
    context = SimpleNamespace(
        invoked_function_arn="arn:aws:lambda:us-east-1:123456789012:function:fleet",
        aws_request_id="request",
    )
    with patch.object(handlers, "Store", return_value=store):
        assert handlers.schedule({}, context) == {"queued": 1}
    messages = store.sqs.receive_message(QueueUrl=__import__("os").environ["POLL_QUEUE_URL"])[
        "Messages"
    ]
    message = json.loads(messages[0]["Body"])
    assert message["sequence"] % 60000 == 0
    assert message["agent_id"] == "account-a" and message["rev"] == 1


def test_worker_returns_only_failed_record_ids(store):
    context = SimpleNamespace(
        invoked_function_arn="arn:aws:lambda:us-east-1:123456789012:function:fleet",
        aws_request_id="request",
    )
    records = [
        {"messageId": "bad", "body": "{}"},
        {
            "messageId": "good",
            "body": json.dumps(
                {"agent_id": "missing", "rev": 1, "sequence": int(time.time() * 1000)}
            ),
        },
    ]
    with patch.object(handlers, "Store", return_value=store):
        assert handlers.worker({"Records": records}, context) == {
            "batchItemFailures": [{"itemIdentifier": "bad"}]
        }
