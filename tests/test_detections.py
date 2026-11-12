import copy
import json
import os
import time
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from opencdr_fleet import handlers
from opencdr_fleet.api import dispatch
from opencdr_fleet.detections import Detections, collect_detections, policy
from opencdr_fleet.models import FleetError, registration


@pytest.fixture
def iam_agent(detection_store):
    return detection_store.save_agent(
        registration(
            {
                "agent_id": "account-a",
                "auth_mode": "iam",
                "account_id": "111111111111",
                "region": "us-east-1",
                "stage": "prod",
                "api_url": "https://abc123.execute-api.us-east-1.amazonaws.com/prod",
            }
        ),
        create=True,
    )


def message(sequence=None, rev=1):
    return {"agent_id": "account-a", "rev": rev, "sequence": sequence or int(time.time() * 1000)}


def page(sequence=1, count=1, more=False):
    return {
        "schema_version": "1.0.0",
        "deployment": {"account_id": "111111111111", "home_region": "us-east-1", "stage": "prod"},
        "items": [
            {
                "schema_version": "1.0.0",
                "change_type": "detection.created",
                "sequence": n,
                "detection_id": f"d-{n}",
                "revision": 1,
                "kind": "correlation" if n % 2 else "signal",
                "committed_at": datetime.now(UTC).isoformat(),
                "payload": {"detection_id": f"d-{n}", "severity": "high", "rule_id": "r-1"},
            }
            for n in range(sequence, sequence + count)
        ],
        "next_cursor": f"cursor-{sequence + count - 1}",
        "has_more": more,
    }


def factory(*pages):
    agent = MagicMock()
    agent.requests = len(pages) + 1
    agent.verify.return_value = {"capabilities": {"detection_feed": "1.0.0"}}
    agent.request.side_effect = [(200, p) if isinstance(p, dict) else p for p in pages]
    return MagicMock(return_value=agent), agent


def detections(store):
    return [i for i in Detections(store).table.scan()["Items"] if i["sk"].startswith("DETECTION#")]


def test_both_kinds_and_duplicate_tick(detection_store, iam_agent):
    make, agent = factory(page(count=2))
    msg = message()
    assert collect_detections(detection_store, msg, make)["records"] == 2
    assert collect_detections(detection_store, msg, make)["state"] == "skipped"
    assert make.call_count == 1
    assert {row["kind"] for row in detections(detection_store)} == {"signal", "correlation"}
    cp = Detections(detection_store).checkpoint("account-a")
    assert cp["cursor"] == "cursor-2" and cp["last_sequence"] == 2
    status = Detections(detection_store).status(iam_agent)
    assert not status["stale"] and status["registration_current"]
    assert "cursor" not in status and status["state"] == "ready"
    assert agent.request.call_args.args == ("GET", "/detections/feed")
    assert not detection_store.get_status("account-a")


def test_storage_failure_does_not_advance_then_recovers(detection_store, iam_agent, monkeypatch):
    original = detection_store.client.transact_write_items
    data = page(count=2)
    monkeypatch.setattr(
        detection_store.client,
        "transact_write_items",
        MagicMock(side_effect=RuntimeError("unavailable")),
    )
    with pytest.raises(RuntimeError):
        collect_detections(detection_store, message(), factory(data)[0])
    assert not detections(detection_store)
    assert not Detections(detection_store).checkpoint("account-a")
    monkeypatch.setattr(detection_store.client, "transact_write_items", original)
    detection_store.registry.update_item(
        Key={"id": iam_agent["id"]},
        UpdateExpression="SET detection_lease_until = :past",
        ExpressionAttributeValues={":past": 0},
    )
    assert collect_detections(detection_store, message(), factory(data)[0])["records"] == 2


def test_interruption_between_pages_resumes_after_receipt(detection_store, iam_agent):
    make, agent = factory(page(count=2, more=True))
    agent.request.side_effect = [
        (200, page(count=2, more=True)),
        FleetError("agent_unreachable", 502),
    ]
    tick = int(time.time() * 1000)
    result = collect_detections(detection_store, message(tick), make)
    assert result["state"] == "failed" and len(detections(detection_store)) == 2
    make, agent = factory(page(sequence=3))
    assert collect_detections(detection_store, message(tick + 1), make)["records"] == 1
    assert agent.request.call_args.kwargs["query"]["cursor"] == "cursor-2"
    assert len(detections(detection_store)) == 3


def test_gap_is_sticky_never_reset_to_head(detection_store, iam_agent):
    tick = int(time.time() * 1000)
    collect_detections(detection_store, message(tick), factory(page())[0])
    collect_detections(
        detection_store, message(tick + 1), factory((410, {"head_cursor": "skip"}))[0]
    )
    cp = Detections(detection_store).checkpoint("account-a")
    assert cp["state"] == "gap" and cp["cursor"] == "cursor-1"
    make = MagicMock(side_effect=AssertionError("must not contact unresolved gap"))
    assert collect_detections(detection_store, message(tick + 2), make)["state"] == "gap"


@pytest.mark.parametrize(
    "change",
    [
        lambda p: p.update(schema_version="2.0.0"),
        lambda p: p["deployment"].update(account_id="222222222222"),
        lambda p: p.update(next_cursor=None),
        lambda p: p["items"][0].update(sequence=2),
        lambda p: p["items"][0].update(revision=True),
        lambda p: p["items"][0].update(kind="unknown"),
        lambda p: p["items"][0]["payload"].update(detection_id="another"),
        lambda p: p["items"].append(copy.deepcopy(p["items"][0])),
        lambda p: p.update(items=[], has_more=True),
        lambda p: p["items"][0].update(committed_at="2026-01-01"),
    ],
)
def test_invalid_pages_have_no_partial_receipt(detection_store, iam_agent, change):
    value = page()
    change(value)
    result = collect_detections(detection_store, message(), factory(value)[0])
    assert result["error_code"] == "invalid_detection_feed_page"
    assert not detections(detection_store)
    assert not Detections(detection_store).checkpoint("account-a").get("cursor")


@pytest.mark.parametrize("change", ["revision", "expired", "token"])
def test_stale_worker_cannot_publish(detection_store, iam_agent, change):
    collection = Detections(detection_store)
    item, token = collection.claim(message())
    field, value = {
        "revision": ("rev", 2),
        "expired": ("detection_lease_until", 0),
        "token": ("detection_token", "new-worker"),
    }[change]
    detection_store.registry.update_item(
        Key={"id": iam_agent["id"]},
        UpdateExpression=f"SET {field} = :new",
        ExpressionAttributeValues={":new": value},
    )
    with pytest.raises(ClientError):
        collection.persist(item, token, {}, page())
    assert not detections(detection_store)
    assert not collection.checkpoint("account-a")


def test_large_evidence_is_durable_and_not_in_day_index(detection_store, iam_agent):
    value = page()
    value["items"][0]["payload"]["raw_event"] = {"large": "x" * 200_000}
    collect_detections(detection_store, message(), factory(value)[0])
    record = detections(detection_store)[0]
    assert "payload" not in record
    body = detection_store.s3.get_object(
        Bucket="fleet-detection-evidence", Key=record["payload_key"]
    )["Body"].read()
    assert json.loads(body) == value["items"][0]["payload"]
    index = Detections(detection_store).table.scan(IndexName="by-day")["Items"][0]
    assert "payload" not in index and "payload_key" not in index


def test_upload_failure_does_not_acknowledge(detection_store, iam_agent, monkeypatch):
    value = page()
    value["items"][0]["payload"]["raw"] = "x" * 200_000
    monkeypatch.setattr(
        detection_store.s3, "put_object", MagicMock(side_effect=RuntimeError("unavailable"))
    )
    with pytest.raises(RuntimeError):
        collect_detections(detection_store, message(), factory(value)[0])
    assert not Detections(detection_store).checkpoint("account-a")
    assert not detections(detection_store)


def test_bounded_catchup_and_100_agent_scheduling(detection_store, iam_agent, monkeypatch):
    pages = [page(sequence=n * 20 + 1, count=20, more=True) for n in range(10)]
    result = collect_detections(detection_store, message(), factory(*pages)[0])
    assert result["records"] == 200 and result["has_more"] and result["state"] == "catching_up"
    assert Detections(detection_store).checkpoint("account-a")["last_sequence"] == 200
    for n in range(1, 100):
        value = {
            k: v
            for k, v in iam_agent.items()
            if k not in {"id", "record_type", "rev", "created_at", "updated_at"}
        }
        value.update(agent_id=f"account-{n:03}", account_id=f"{n:012}")
        detection_store.save_agent(value, create=True)
    monkeypatch.setattr(handlers, "Store", lambda: detection_store)
    ctx = SimpleNamespace(
        invoked_function_arn="arn:aws:lambda:us-east-1:123456789012:function:test"
    )
    assert handlers.detection_schedule({}, ctx) == {"queued": 100}
    attrs = detection_store.sqs.get_queue_attributes(
        QueueUrl=os.environ["DETECTION_QUEUE_URL"], AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"]
    assert int(attrs["ApproximateNumberOfMessages"]) == 100


def test_configuration_lease_is_independent(detection_store, iam_agent):
    assert detection_store.claim("account-a", 1, int(time.time() * 1000))
    assert collect_detections(detection_store, message(), factory(page())[0])["records"] == 1


def test_legacy_has_no_fallback(detection_store, agent_record):
    make = MagicMock(side_effect=AssertionError("no key fallback"))
    assert collect_detections(detection_store, message(), make)["state"] == "skipped"


def test_status_and_independent_policy(detection_store, iam_agent, monkeypatch):
    monkeypatch.setenv("DETECTION_POLL_INTERVAL_MINUTES", "5")
    monkeypatch.setenv("POLL_INTERVAL_MINUTES", "10")
    _, status = dispatch({"httpMethod": "GET", "path": "/v1/status"}, detection_store)
    assert status["detection_poll_interval_seconds"] == 300
    assert status["poll_interval_seconds"] == 600
    assert status["capabilities"]["detection_delivery"] is True
    assert status["capabilities"]["central_detection_queries"] == "1.0.0"
    code, state = dispatch(
        {
            "httpMethod": "GET",
            "path": "/v1/agents/account-a/detections/status",
            "pathParameters": {"agent_id": "account-a"},
        },
        detection_store,
    )
    assert code == 200 and state["stale"] and state["state"] == "not_collected"
    monkeypatch.setenv("DETECTION_POLL_INTERVAL_MINUTES", "0")
    with pytest.raises(FleetError, match="invalid_detection_polling_configuration"):
        policy()


def test_real_core_feed_roundtrip_including_late_event_and_empty_page(
    detection_store, iam_agent, monkeypatch
):
    from pathlib import Path

    core = Path(__file__).resolve().parents[2] / "opencdr-internal"
    if not (core / "src/infra/detection_feed.py").is_file():
        pytest.skip("Cross-repository feed contract test requires the sibling Core checkout")
    monkeypatch.syspath_prepend(str(core))
    from src.infra.detection_feed import DetectionFeed
    from src.infra.serialization import json_default

    client = detection_store.client
    client.create_table(
        TableName="core-feed",
        BillingMode="PAY_PER_REQUEST",
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sequence", "AttributeType": "N"},
        ],
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sequence", "KeyType": "RANGE"},
        ],
    )
    client.create_table(
        TableName="signals",
        BillingMode="PAY_PER_REQUEST",
        AttributeDefinitions=[
            {"AttributeName": key, "AttributeType": "S"} for key in ("severity_bucket", "timestamp")
        ],
        KeySchema=[
            {"AttributeName": "severity_bucket", "KeyType": "HASH"},
            {"AttributeName": "timestamp", "KeyType": "RANGE"},
        ],
    )
    feed = DetectionFeed(client, "core-feed")
    feed.commit_detection(
        "signals",
        {
            "detection_id": "late",
            "severity_bucket": "high#0",
            "timestamp": "2020-01-01T00:00:00Z",
            "event_time": "2020-01-01T00:00:00Z",
            "expires_at": int(time.time()) + 86400,
            "rule_id": "r1",
        },
    )
    make, agent = factory()

    def get_page(method, path, query):
        assert method == "GET" and path == "/detections/feed"
        result = feed.page(cursor=query.get("cursor"), limit=int(query["limit"]))
        result["deployment"] = {
            "account_id": "111111111111",
            "home_region": "us-east-1",
            "stage": "prod",
        }
        return 200, json.loads(json.dumps(result, default=json_default))

    agent.request.side_effect = get_page
    tick = int(time.time() * 1000)
    assert collect_detections(detection_store, message(tick), make)["records"] == 1
    assert collect_detections(detection_store, message(tick + 1), make)["records"] == 0
    assert len(detections(detection_store)) == 1
    assert Detections(detection_store).checkpoint("account-a")["last_sequence"] == 1


def test_worker_reports_partial_failure_and_emits_no_evidence(
    detection_store, iam_agent, monkeypatch, capsys
):
    import opencdr_fleet.detections as module

    monkeypatch.setattr(handlers, "Store", lambda: detection_store)
    monkeypatch.setattr(
        module, "collect_detections", lambda *args: {"state": "ready", "records": 2}
    )
    ctx = SimpleNamespace(
        invoked_function_arn="arn:aws:lambda:us-east-1:123456789012:function:test"
    )
    result = handlers.detection_worker(
        {
            "Records": [
                {"messageId": "good", "body": json.dumps(message())},
                {"messageId": "bad", "body": json.dumps(message(rev=True))},
            ]
        },
        ctx,
    )
    assert result == {"batchItemFailures": [{"itemIdentifier": "bad"}]}
    metrics = json.loads(capsys.readouterr().out)
    assert metrics["DetectionRecordsCollected"] == 2
    assert metrics["_aws"]["CloudWatchMetrics"][0]["Namespace"] == "OpenCDR/Fleet"


def test_unchanged_registration_uses_one_feed_read_and_rechecks_live_identity(
    detection_store, iam_agent
):
    tick = int(time.time() * 1000)
    first, agent = factory(page())
    collect_detections(detection_store, message(tick), first)
    agent.verify.assert_called_once()
    value = page(sequence=2)
    value["deployment"]["account_id"] = "222222222222"
    second, agent = factory(value)
    result = collect_detections(detection_store, message(tick + 1), second)
    agent.verify.assert_not_called()
    assert result["error_code"] == "invalid_detection_feed_page"
    assert Detections(detection_store).checkpoint("account-a")["cursor"] == "cursor-1"
    assert detection_store.view_status(iam_agent)["detections"]["state"] == "failed"


def test_registration_update_requires_capability_verification_again(detection_store, iam_agent):
    tick = int(time.time() * 1000)
    collect_detections(detection_store, message(tick), factory(page())[0])
    detection_store.registry.update_item(
        Key={"id": iam_agent["id"]},
        UpdateExpression="SET rev = :rev",
        ExpressionAttributeValues={":rev": 2},
    )
    make, agent = factory(page(sequence=2))
    assert collect_detections(detection_store, message(tick + 1, rev=2), make)["records"] == 1
    agent.verify.assert_called_once()


def test_unknown_transaction_result_resumes_from_committed_checkpoint(
    detection_store, iam_agent, monkeypatch
):
    original = detection_store.client.transact_write_items

    def commit_then_disconnect(**kwargs):
        original(**kwargs)
        raise RuntimeError("connection lost after commit")

    monkeypatch.setattr(detection_store.client, "transact_write_items", commit_then_disconnect)
    tick = int(time.time() * 1000)
    with pytest.raises(RuntimeError):
        collect_detections(detection_store, message(tick), factory(page())[0])
    assert Detections(detection_store).checkpoint("account-a")["cursor"] == "cursor-1"
    assert len(detections(detection_store)) == 1
    monkeypatch.setattr(detection_store.client, "transact_write_items", original)
    detection_store.registry.update_item(
        Key={"id": iam_agent["id"]},
        UpdateExpression="SET detection_lease_until = :past",
        ExpressionAttributeValues={":past": 0},
    )
    make, agent = factory(page(sequence=2))
    collect_detections(detection_store, message(tick + 1), make)
    assert agent.request.call_args.kwargs["query"]["cursor"] == "cursor-1"
    assert len(detections(detection_store)) == 2


def test_slow_catchup_stops_before_worker_deadline(detection_store, iam_agent, monkeypatch):
    from opencdr_fleet import detections as module

    clock = iter([0, 0, 33])
    monkeypatch.setattr(
        module, "time", SimpleNamespace(time=time.time, monotonic=lambda: next(clock))
    )
    make, agent = factory(page(count=20, more=True))
    result = collect_detections(detection_store, message(), make)
    assert result["records"] == 20 and result["has_more"]
    assert agent.request.call_count == 1
    assert Detections(detection_store).checkpoint("account-a")["last_sequence"] == 20
