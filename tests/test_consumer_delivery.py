import json
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from opencdr_fleet.consumer_delivery import _reconcile, consumer_id
from opencdr_fleet.detections import Detections, collect_detections
from opencdr_fleet.models import FleetError, registration


@pytest.fixture
def system(detection_store, monkeypatch):
    core = Path(__file__).resolve().parents[2] / "opencdr-internal"
    if not (core / "src/infra/detection_consumers.py").exists():
        pytest.skip("Cross-repository receipt test requires the sibling Core checkout")
    monkeypatch.syspath_prepend(str(core))
    from src.handlers.detection_consumers import handle
    from src.infra.detection_consumers import DetectionConsumers, principal
    from src.infra.detection_feed import DetectionFeed
    from src.infra.serialization import json_default

    store = detection_store
    for table, pk, sk, kind in [
        ("core-feed", "pk", "sequence", "N"),
        ("core-signals", "severity_bucket", "timestamp", "S"),
    ]:
        store.client.create_table(
            TableName=table,
            BillingMode="PAY_PER_REQUEST",
            AttributeDefinitions=[
                {"AttributeName": pk, "AttributeType": "S"},
                {"AttributeName": sk, "AttributeType": kind},
            ],
            KeySchema=[
                {"AttributeName": pk, "KeyType": "HASH"},
                {"AttributeName": sk, "KeyType": "RANGE"},
            ],
        )
    monkeypatch.setenv("DETECTION_FEED_TABLE_NAME", "core-feed")
    monkeypatch.setenv("SIGNALS_TABLE_NAME", "core-signals")
    store.client.update_table(
        TableName="core-feed",
        AttributeDefinitions=[
            {"AttributeName": key, "AttributeType": "S"} for key in ("day", "order")
        ],
        GlobalSecondaryIndexUpdates=[
            {
                "Create": {
                    "IndexName": "by-day",
                    "KeySchema": [
                        {"AttributeName": "day", "KeyType": "HASH"},
                        {"AttributeName": "order", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                }
            }
        ],
    )
    monkeypatch.setenv("INGESTION_BUCKET", "fleet-detection-evidence")
    identity = {
        "userArn": "arn:aws:sts::123456789012:assumed-role/detection-reader/session",
        "caller": "AROAABCDEFGHIJKLMNOP:session",
    }
    item = store.save_agent(
        registration(
            {
                "agent_id": "member",
                "account_id": "111111111111",
                "region": "us-east-1",
                "stage": "prod",
                "auth_mode": "iam",
                "api_url": "https://abc123.execute-api.us-east-1.amazonaws.com/prod",
            }
        ),
        create=True,
    )
    deployment = {
        "account_id": item["account_id"],
        "home_region": item["region"],
        "stage": item["stage"],
    }
    feed = DetectionFeed(store.client, "core-feed")
    receipt = DetectionConsumers(feed, principal(identity), consumer_id(item))

    class Client:
        def __init__(self):
            self.requests = 0
            self.calls = []
            self.fail_after_read = False
            self.fail_after_reconcile = False
            self.fail_after_handoff = False
            self.fail_after_recovery = False
            self.identity = identity.copy()

        def verify(self):
            return {"capabilities": {"detection_feed": "1.1.0", "detection_consumers": "1.0.0"}}

        def request(self, method, path, **kwargs):
            if method == "GET" and path.startswith("/detections/handoffs/"):
                from src.handlers.detection_handoffs import handle as handoff

                code, value = handoff(method, path, {}, {}, self.identity)
                value["deployment"] = deployment
                return code, json.loads(json.dumps(value, default=json_default))
            if method == "GET" and path.startswith("/detections/backfills/"):
                from src.handlers.detection_backfill import handle as backfill

                code, value = backfill(method, path, {}, {}, deployment, identity)
                return code, json.loads(json.dumps(value, default=json_default))
            raise AssertionError("Receipt mode must never fall back to stateless reads")

        def delivery_request(self, method, path, body=None):
            self.requests += 1
            self.calls.append((method, path, body))
            code, value = handle(
                method,
                path,
                json.loads(json.dumps(body or {}, default=json_default)),
                {},
                self.identity,
            )
            value["deployment"] = deployment
            if path.endswith("/read") and code == 200 and self.fail_after_read:
                self.fail_after_read = False
                raise FleetError("agent_unreachable", 502)
            if path.endswith("/reconcile") and code == 200 and self.fail_after_reconcile:
                self.fail_after_reconcile = False
                raise FleetError("agent_unreachable", 502)
            if path.endswith("/handoff") and code == 200 and self.fail_after_handoff:
                self.fail_after_handoff = False
                raise FleetError("agent_unreachable", 502)
            if path.endswith("/recover") and code == 200 and self.fail_after_recovery:
                self.fail_after_recovery = False
                raise FleetError("agent_unreachable", 502)
            return code, json.loads(json.dumps(value, default=json_default))

    client = Client()
    tick = int(time.time() * 1000)

    def run():
        nonlocal tick
        tick += 1
        return collect_detections(
            store, {"agent_id": "member", "rev": 1, "sequence": tick}, lambda *a, **kw: client
        )

    def emit(name):
        feed.commit_detection(
            "core-signals",
            {
                "detection_id": name,
                "severity_bucket": "HIGH#2020-01-01",
                "timestamp": name,
                "item_type": "correlation" if name == "two" else "signal",
                "expires_at": int(time.time()) + 86400,
            },
        )

    return store, client, receipt, run, emit


def test_receipts_ack_only_after_fleet_persistence_and_idle_is_one_request(system):
    store, client, receipt, run, emit = system
    emit("one")
    assert run()["records"] == 1
    assert receipt.view()["acknowledged_sequence"] == 0
    assert Detections(store).checkpoint("member")["last_sequence"] == 1
    before = client.requests
    assert run()["records"] == 0 and client.requests - before == 1
    assert receipt.view()["acknowledged_sequence"] == 1
    revision = receipt.view()["rev"]
    before = client.requests
    assert run()["records"] == 0 and client.requests - before == 1
    assert receipt.view()["rev"] == revision
    status = Detections(store).status(store.get_agent("member"))
    assert not status["receipt_pending"] and "consumer_receipt_id" not in status


def test_lost_initial_read_response_replays_without_acknowledging(system):
    store, client, receipt, run, emit = system
    emit("one")
    client.fail_after_read = True
    assert run()["state"] == "failed"
    assert not Detections(store).checkpoint("member").get("cursor")
    assert receipt.view()["pending"]["to_sequence"] == 1
    assert run()["records"] == 1
    assert receipt.view()["acknowledged_sequence"] == 0


def test_lost_ack_and_next_page_response_reconciles_only_durable_cursor(system):
    store, client, receipt, run, emit = system
    emit("one")
    run()
    emit("two")
    client.fail_after_read = True
    assert run()["state"] == "failed"
    assert receipt.view()["acknowledged_sequence"] == 1
    assert receipt.view()["pending"]["to_sequence"] == 2
    assert Detections(store).checkpoint("member")["last_sequence"] == 1
    before = client.requests
    assert run()["records"] == 1 and client.requests - before == 3
    assert Detections(store).checkpoint("member")["last_sequence"] == 2
    assert receipt.view()["acknowledged_sequence"] == 1
    rows = Detections(store).table.scan()["Items"]
    assert len([row for row in rows if row["sk"].startswith("DETECTION#")]) == 2


def test_failed_fleet_transaction_never_acknowledges_core(system, monkeypatch):
    store, _, receipt, run, emit = system
    emit("one")
    original = store.client.transact_write_items
    monkeypatch.setattr(
        store.client, "transact_write_items", MagicMock(side_effect=RuntimeError("storage offline"))
    )
    with pytest.raises(RuntimeError):
        run()
    assert receipt.view()["acknowledged_sequence"] == 0
    assert not Detections(store).checkpoint("member")
    monkeypatch.setattr(store.client, "transact_write_items", original)
    store.registry.update_item(
        Key={"id": "AGENT#member"},
        UpdateExpression="SET detection_lease_until = :old",
        ExpressionAttributeValues={":old": 0},
    )
    assert run()["records"] == 1
    assert receipt.view()["acknowledged_sequence"] == 0


def test_remote_progress_cannot_replace_missing_local_detections():
    remote = {
        "consumer_id": "fleet",
        "schema_version": "1.0.0",
        "rev": 4,
        "acknowledged_sequence": 20,
        "acknowledged_cursor": "remote",
    }
    with pytest.raises(FleetError, match="checkpoint_conflict"):
        _reconcile(remote, {"cursor": "local", "last_sequence": 10}, "fleet")


def gap_and_backfill(system):
    from src.infra.detection_backfill import DetectionBackfill
    from src.infra.detection_feed import _encode

    store, _, receipt, run, emit = system
    emit("one")
    run()
    run()  # Persist the ACK before making the next journal record unavailable.
    emit("two")
    store.client.delete_item(
        TableName="core-feed", Key=_encode({"pk": "detections", "sequence": 2})
    )
    run()
    assert Detections(store).checkpoint("member")["state"] == "gap"
    job = DetectionBackfill(
        receipt.feed,
        "core-signals",
        {"account_id": "111111111111", "home_region": "us-east-1", "stage": "prod"},
        "repair",
    )
    state = job.create({"reason": "retained history repair"}, "admin")
    state = job.step({"expected_rev": 1, "plan_digest": state["plan_digest"]})
    assert state["state"] == "completed"
    return {
        "expected_generation": int(Detections(store).checkpoint("member")["generation"]),
        "expected_registration_rev": 1,
        "backfill_job_id": "repair",
        "plan_digest": state["plan_digest"],
        "reason": "accept unknown missing history",
        "accept_unrecoverable": True,
        "request_id": "a" * 32,
    }


@pytest.mark.parametrize("lost_response", [False, True])
def test_gap_recovery_uses_original_consumer_and_preserves_existing_records(system, lost_response):
    from opencdr_fleet.detection_reconciliation import request

    store, client, receipt, run, _ = system
    body = gap_and_backfill(system)
    collection = Detections(store)
    rows = collection.table.scan()["Items"]
    original = next(row for row in rows if row["sk"].startswith("DETECTION#"))
    original["handling"] = {"status": "addressed"}
    collection.table.put_item(Item=original)
    request(store, "member", body, "fleet-admin")
    assert request(store, "member", body, "fleet-admin")["idempotent"]
    client.fail_after_reconcile = lost_response
    if lost_response:
        assert run()["error_code"] == "agent_unreachable"
        assert collection.checkpoint("member")["state"] == "gap"
        assert receipt.view()["acknowledged_sequence"] == 2
    result = run()
    assert result["state"] == "ready" and result["records"] == 2
    state = collection.checkpoint("member")
    assert state["last_sequence"] == 4 and state["reconciled_request_id"] == body["request_id"]
    assert state["last_reconciliation"]["missing_history_count"] is None
    assert not state["last_reconciliation"]["history_complete"]
    rows = collection.table.scan()["Items"]
    detections = [r for r in rows if r["sk"].startswith("DETECTION#")]
    assert len(detections) == 2
    assert next(r for r in detections if r["detection_id"] == "one") == original
    imported = next(r for r in detections if r["detection_id"] == "two")
    assert imported["summary"]["delivery_origin"] == "backfill"
    assert imported["expires_at"] <= int(time.time()) + 86400
    assert len(receipt.reconciliations({})["items"]) == 1
    assert run()["records"] == 0


def test_reconciliation_intents_require_exact_checkpoint_and_explicit_supersession(system):
    from opencdr_fleet.detection_reconciliation import request

    store, _, _, _, _ = system
    body = gap_and_backfill(system)
    for change in (
        {"expected_generation": 999},
        {"expected_registration_rev": 2},
        {"accept_unrecoverable": False},
    ):
        with pytest.raises(FleetError):
            request(store, "member", {**body, **change}, "admin")
    request(store, "member", body, "admin")
    with pytest.raises(FleetError, match="already_pending"):
        request(store, "member", {**body, "request_id": "b" * 32}, "admin")
    with pytest.raises(FleetError, match="request_conflict"):
        request(store, "member", {**body, "reason": "different"}, "admin")
    request(
        store,
        "member",
        {**body, "request_id": "b" * 32, "supersedes_request_id": body["request_id"]},
        "admin",
    )
    rows = Detections(store).table.scan()["Items"]
    assert len([r for r in rows if r["pk"].startswith("RECONCILIATION#")]) == 2


def test_rejected_generation_never_becomes_authorized_by_a_retry_marker(system):
    from opencdr_fleet.detection_reconciliation import request

    store, _, receipt, run, _ = system
    body = gap_and_backfill(system)
    request(store, "member", body, "admin")
    collection = Detections(store)
    # Emulate an out-of-band checkpoint replacement after the approved request.
    state = collection.checkpoint("member")
    state["generation"] += 1
    collection.table.put_item(Item=state)
    for _ in range(2):
        assert run()["error_code"] == "detection_reconciliation_checkpoint_conflict"
        assert "reconciliation_pending_request" not in collection.checkpoint("member")
    assert "last_reconciliation" not in receipt.view()


def test_upgrade_declares_existing_durable_checkpoint_without_replaying_it(system):
    store, client, receipt, run, emit = system
    emit("one")
    cursor = receipt.feed.page()["next_cursor"]
    collection = Detections(store)
    # Fixture represents an existing stateless collector's persisted checkpoint.
    collection.table.put_item(
        Item={
            "pk": "AGENT#member",
            "sk": "CHECKPOINT",
            "cursor": cursor,
            "last_sequence": 1,
            "generation": 1,
            "registration_rev": 1,
            "state": "ready",
        }
    )
    emit("two")
    assert run()["records"] == 1
    assert receipt.view()["initialization"] == "declared_checkpoint"
    assert receipt.view()["acknowledged_sequence"] == 1
    assert receipt.view()["pending"]["to_sequence"] == 2
    initial = client.calls[0][2]
    assert initial["initial_cursor"] == cursor and len(initial["checkpoint_sha256"]) == 64


@pytest.mark.parametrize(
    "field,value", [("to_cursor", "other"), ("to_sequence", 99), ("count", 99)]
)
def test_mismatched_receipt_never_persists_or_acknowledges(system, monkeypatch, field, value):
    store, client, receipt, run, emit = system
    emit("one")
    request = client.delivery_request

    def corrupt(method, path, body=None):
        code, result = request(method, path, body)
        if path.endswith("/read"):
            result["consumer"]["pending"][field] = value
        return code, result

    monkeypatch.setattr(client, "delivery_request", corrupt)
    result = run()
    assert (
        result["state"] == "failed" and result["error_code"] == "invalid_detection_consumer_receipt"
    )
    assert not Detections(store).checkpoint("member").get("cursor")
    assert receipt.view()["acknowledged_sequence"] == 0


def handoff_plan(system):
    from src.infra.detection_consumers import principal
    from src.infra.detection_handoffs import DetectionHandoffs

    from opencdr_fleet.detection_handoff import context

    store, client, receipt, run, emit = system
    emit("one")
    run()
    client.identity["caller"] = "AROAQRSTUVWXYZABCDEF:session"
    assert run()["error_code"] == "detection_consumer_read_http_404"
    reviewed = context(store, "member")
    plan = DetectionHandoffs(receipt.feed, "replacement").create(
        {
            "consumer_id": reviewed["consumer_id"],
            "previous_owner": reviewed["previous_owner"],
            "target_owner": principal(client.identity),
            "checkpoint": reviewed["checkpoint"],
            "reason": "recreated detection worker",
        },
        "administrator",
    )
    return {
        "expected_generation": reviewed["expected_generation"],
        "expected_registration_rev": reviewed["expected_registration_rev"],
        "handoff_id": plan["handoff_id"],
        "plan_digest": plan["plan_digest"],
        "target_owner": plan["target_owner"],
        "reason": "reviewed storage continuity",
        "request_id": "c" * 32,
    }


@pytest.mark.parametrize("failure", [None, "response", "fleet_commit"])
def test_recreated_worker_handoff_recovers_without_reset_or_record_changes(
    system, monkeypatch, failure
):
    from src.infra.detection_consumers import ConsumerError, DetectionConsumers, principal

    from opencdr_fleet.detection_handoff import request

    store, client, old, run, _ = system
    body = handoff_plan(system)
    rows_before = [
        r for r in Detections(store).table.scan()["Items"] if r["sk"].startswith("DETECTION#")
    ]
    request(store, "member", body, "administrator")
    if failure == "response":
        client.fail_after_handoff = True
    transaction = store.client.transact_write_items
    if failure == "fleet_commit":
        from botocore.exceptions import ClientError

        def fail_checkpoint(**kwargs):
            items = kwargs["TransactItems"]
            if any(
                "Put" in item
                and item["Put"].get("Item", {}).get("handoff_request_id", {}).get("S")
                == body["request_id"]
                for item in items
            ):
                raise ClientError({"Error": {"Code": "InternalServerError"}}, "TransactWriteItems")
            return transaction(**kwargs)

        monkeypatch.setattr(store.client, "transact_write_items", fail_checkpoint)
        with pytest.raises(ClientError):
            run()
        monkeypatch.setattr(store.client, "transact_write_items", transaction)
        # Lambda died with its lease held; emulate expiry before retry.
        store.registry.update_item(
            Key={"id": "AGENT#member"},
            UpdateExpression="SET detection_lease_until = :expired",
            ExpressionAttributeValues={":expired": 0},
        )
    elif failure == "response":
        assert run()["state"] == "failed"
        assert (
            Detections(store).checkpoint("member")["handoff_pending_request"] == body["request_id"]
        )
    assert run()["handoff_complete"] is True
    assert (
        DetectionConsumers(old.feed, principal(client.identity), old.name).view()[
            "acknowledged_sequence"
        ]
        == 0
    )
    assert run()["state"] == "ready"
    current = Detections(store).checkpoint("member")
    assert current["last_sequence"] == 1 and current["consumer_owner"] == body["target_owner"]
    assert current["handoff_request_id"] == body["request_id"]
    assert current["last_handoff"]["history_complete"] is False
    assert rows_before == [
        r for r in Detections(store).table.scan()["Items"] if r["sk"].startswith("DETECTION#")
    ]
    with pytest.raises(ConsumerError, match="retired"):
        old.view()
    assert (
        DetectionConsumers(old.feed, principal(client.identity), old.name).view()[
            "acknowledged_sequence"
        ]
        == 1
    )


def test_handoff_rejects_wrong_review_before_changing_core_owner(system):
    from opencdr_fleet.detection_handoff import request

    store, client, old, run, _ = system
    body = handoff_plan(system)
    request(
        store,
        "member",
        {**body, "target_owner": "aws:123456789012:AROAOTHERPRINCIPALX"},
        "administrator",
    )
    assert run()["error_code"] == "detection_handoff_plan_conflict"
    assert old.view()["acknowledged_sequence"] == 0
    assert not any(path.endswith("/handoff") for _, path, _ in client.calls)


def test_handoff_does_not_clear_gap_or_enable_polling(system, monkeypatch):
    from opencdr_fleet.detection_handoff import context, request

    store, _, _, run, _ = system
    body = handoff_plan(system)
    collection = Detections(store)
    collection.table.update_item(
        Key={"pk": "AGENT#member", "sk": "CHECKPOINT"},
        UpdateExpression="SET #state = :gap",
        ExpressionAttributeNames={"#state": "state"},
        ExpressionAttributeValues={":gap": "gap"},
    )
    monkeypatch.setenv("DETECTION_POLLING_ENABLED", "false")
    body["expected_generation"] = context(store, "member")["expected_generation"]
    request(store, "member", body, "administrator")
    assert run()["state"] == "gap"
    status = collection.status(store.get_agent("member"))
    assert status["handoff_request_id"] == body["request_id"] and status["enabled"] is False
    assert status["state"] == "gap"


def test_handoff_guards_conflicting_reconciliation_and_retries_queue_failure(system, monkeypatch):
    from opencdr_fleet.detection_handoff import request
    from opencdr_fleet.detection_reconciliation import request as reconcile

    store, _, _, _, _ = system
    body = handoff_plan(system)
    queue = MagicMock(side_effect=RuntimeError("queue unavailable"))
    monkeypatch.setenv("DETECTION_QUEUE_URL", "queue")
    monkeypatch.setattr(store, "enqueue_many", queue)
    assert request(store, "member", body, "administrator")["refresh_queued"] is False
    queue.side_effect = None
    assert request(store, "member", body, "administrator")["refresh_queued"] is True
    assert queue.call_count == 2
    changed = {**body, "reason": "not the approved body"}
    with pytest.raises(FleetError, match="request_conflict"):
        request(store, "member", changed, "administrator")
    with pytest.raises(FleetError, match="handoff_already_pending"):
        reconcile(
            store,
            "member",
            {
                "expected_generation": body["expected_generation"],
                "expected_registration_rev": 1,
                "backfill_job_id": "job",
                "plan_digest": "a" * 64,
                "reason": "gap",
                "accept_unrecoverable": True,
                "request_id": "e" * 32,
            },
            "administrator",
        )


def test_paused_handoff_and_duplicate_worker_message_do_not_ack_or_fetch_more(system, monkeypatch):
    from src.infra.detection_consumers import DetectionConsumers, principal

    from opencdr_fleet.detection_handoff import request
    from opencdr_fleet.models import public_registration

    store, client, old, run, emit = system
    body = handoff_plan(system)
    emit("two")
    monkeypatch.setenv("DETECTION_POLLING_ENABLED", "false")
    request(store, "member", body, "administrator")
    assert "detection_handoff" not in public_registration(store.get_agent("member"))
    assert run()["handoff_complete"] is True
    before = len(client.calls)
    assert run()["state"] == "paused"
    assert len(client.calls) == before
    row = DetectionConsumers(old.feed, principal(client.identity), old.name).view()
    assert row["acknowledged_sequence"] == 0 and row["pending"]["to_sequence"] == 1
    assert Detections(store).checkpoint("member")["last_sequence"] == 1


def prepare_feed_recovery(system, monkeypatch, *, rotate=True, new_owner=False):
    from src.infra.detection_backfill import DetectionBackfill
    from src.infra.detection_consumers import principal
    from src.infra.detection_recovery import FeedRecovery, storage_context

    store, client, receipt, run, emit = system
    emit("one")
    assert run()["records"] == 1
    before = Detections(store).checkpoint("member")
    monkeypatch.setenv("DETECTION_POLLING_ENABLED", "false")
    if rotate:
        recovery = FeedRecovery(receipt.feed, "restored")
        plan = recovery.create(
            {
                "storage_digest": storage_context(receipt.feed)["storage_digest"],
                "reason": "Restored feed reviewed",
                "accept_unrecoverable": True,
            },
            receipt.owner,
        )
        recovery.apply({"plan_digest": plan["plan_digest"]}, receipt.owner)
    if new_owner:
        client.identity["caller"] = "AROAQRSTUVWXYZABCDEF:replacement"
    emit("two")
    item = store.get_agent("member")
    job = DetectionBackfill(
        receipt.feed,
        "core-signals",
        {"account_id": item["account_id"], "home_region": item["region"], "stage": item["stage"]},
        "restore-history",
    )
    state = job.create({"reason": "Restore retained detections"}, receipt.owner)
    state = job.step({"expected_rev": int(state["rev"]), "plan_digest": state["plan_digest"]})
    assert state["state"] == "completed"
    return before, {
        "expected_generation": int(before["generation"]),
        "expected_registration_rev": 1,
        "backfill_job_id": job.job_id,
        "plan_digest": state["plan_digest"],
        "target_epoch": receipt.feed._head()["epoch"],
        "target_owner": principal(client.identity),
        "reason": "Retained history reviewed; unavailable history accepted",
        "request_id": "c" * 32,
        "accept_unrecoverable": True,
    }


@pytest.mark.parametrize("rotate,new_owner", [(True, False), (True, True), (False, False)])
def test_reviewed_recovery_replays_into_fresh_consumer_and_preserves_fleet_records(
    system, monkeypatch, rotate, new_owner
):
    from src.infra.detection_feed import _decode, _encode

    from opencdr_fleet.detection_reconciliation import request

    store, client, receipt, run, _ = system
    before, body = prepare_feed_recovery(system, monkeypatch, rotate=rotate, new_owner=new_owner)
    # Record keys are derived by the existing collector; enumerate to preserve
    # the exact row including its evidence/retention/index metadata.
    old_rows = [
        row for row in Detections(store).table.scan()["Items"] if row.get("detection_id") == "one"
    ]
    # Both the immutable detection and its routing journal must survive replay.
    assert len(old_rows) == 2
    assert sum(row["sk"].startswith("DETECTION#") for row in old_rows) == 1
    assert sum(row["pk"].startswith("ROUTING_FEED#") for row in old_rows) == 1
    request(store, "member", body, "admin", recovery=True)
    from opencdr_fleet.models import public_registration

    assert "detection_reconciliation" not in public_registration(store.get_agent("member"))
    completed = run()
    assert completed.get("recovery_complete") and completed["records"] == 0, completed
    after = Detections(store).checkpoint("member")
    assert after["consumer_id"] == "recovery-" + body["request_id"]
    assert after["consumer_owner"] == body["target_owner"]
    assert after["state"] == "recovery_paused" and "last_recovery" in after
    raw_old = _decode(
        store.client.get_item(TableName="core-feed", Key=_encode(receipt.key))["Item"]
    )
    assert raw_old["acknowledged_sequence"] == 0  # original consumer was never ACKed
    assert before["consumer_id"] != after["consumer_id"]
    calls = len(client.calls)
    run()
    assert len(client.calls) == calls  # duplicate queued work cannot fetch/ACK while paused
    monkeypatch.setenv("DETECTION_POLLING_ENABLED", "true")
    assert run()["error_code"] is None
    rows = Detections(store).table.scan()["Items"]
    assert {r["detection_id"] for r in rows if r.get("detection_id")} == {"one", "two"}
    retained = {(r["pk"], r["sk"]): r for r in rows}
    assert all(retained[(r["pk"], r["sk"])] == r for r in old_rows)
    original_keys = {(r["pk"], r["sk"]) for r in old_rows}
    replay = [r for r in rows if r.get("detection_id") == "one"
              and (r["pk"], r["sk"]) not in original_keys]
    assert len(replay) == 1
    assert replay[0]["change_type"] == "detection.backfilled"
    assert replay[0]["automation_origin"] == "ineligible"
    assert after["last_recovery"]["history_complete"] is False


@pytest.mark.parametrize("lost", ["core_response", "fleet_commit"])
def test_feed_recovery_uncertain_result_retries_without_checkpoint_adoption(
    system, monkeypatch, lost
):
    from opencdr_fleet.detection_reconciliation import request

    store, client, _, run, _ = system
    before, body = prepare_feed_recovery(system, monkeypatch)
    request(store, "member", body, "admin", recovery=True)
    transaction = store.client.transact_write_items
    if lost == "core_response":
        client.fail_after_recovery = True
    else:

        def fail(**kwargs):
            if any('"recovery_paused"' in json.dumps(tx) for tx in kwargs["TransactItems"]):
                raise FleetError("injected_checkpoint_failure", 502)
            return transaction(**kwargs)

        monkeypatch.setattr(store.client, "transact_write_items", fail)
    assert run()["state"] == "failed"
    failed = Detections(store).checkpoint("member")
    assert failed["cursor"] == before["cursor"] and failed["consumer_id"] == before["consumer_id"]
    monkeypatch.setattr(store.client, "transact_write_items", transaction)
    assert request(store, "member", body, "admin", recovery=True)["idempotent"]
    assert run()["recovery_complete"]
    assert len([c for c in client.calls if c[1].endswith("/recover")]) == 2


def test_feed_recovery_rejects_wrong_target_before_core_mutation_and_requires_pause(
    system, monkeypatch
):
    from src.infra.detection_consumers import ConsumerError, DetectionConsumers

    from opencdr_fleet.detection_reconciliation import request

    store, _, receipt, run, _ = system
    before, body = prepare_feed_recovery(system, monkeypatch)
    monkeypatch.setenv("DETECTION_POLLING_ENABLED", "true")
    with pytest.raises(FleetError, match="requires_paused"):
        request(store, "member", body, "admin", recovery=True)
    monkeypatch.setenv("DETECTION_POLLING_ENABLED", "false")
    body["target_owner"] = "aws:123456789012:AROAQRSTUVWXYZABCDEF"
    request(store, "member", body, "admin", recovery=True)
    assert run()["error_code"] == "detection_consumer_recovery_failed"
    assert Detections(store).checkpoint("member")["cursor"] == before["cursor"]
    with pytest.raises(ConsumerError, match="not_found"):
        DetectionConsumers(receipt.feed, receipt.owner, "recovery-" + body["request_id"]).view()


def test_recovery_service_failure_resumes_after_worker_lease_expiry(system, monkeypatch):
    from botocore.exceptions import ClientError

    from opencdr_fleet.detection_reconciliation import request

    store, client, _, run, _ = system
    before, body = prepare_feed_recovery(system, monkeypatch)
    request(store, "member", body, "admin", recovery=True)
    transaction = store.client.transact_write_items

    def unavailable(**kwargs):
        if any('"recovery_paused"' in json.dumps(tx) for tx in kwargs["TransactItems"]):
            raise ClientError(
                {"Error": {"Code": "TransactionCanceledException"}}, "TransactWriteItems"
            )
        return transaction(**kwargs)

    monkeypatch.setattr(store.client, "transact_write_items", unavailable)
    with pytest.raises(ClientError):
        run()
    assert Detections(store).checkpoint("member") == before
    monkeypatch.setattr(store.client, "transact_write_items", transaction)
    store.registry.update_item(
        Key={"id": "AGENT#member"},
        UpdateExpression="SET detection_lease_until = :past",
        ExpressionAttributeValues={":past": 0},
    )
    assert run()["recovery_complete"]
    assert len([call for call in client.calls if call[1].endswith("/recover")]) == 2


def test_real_core_handling_is_delivered_once_with_lost_receipt_and_replay(system):
    from src.infra.detection_backfill import DetectionBackfill
    from src.infra.detection_handling import DetectionHandling

    from opencdr_fleet.detection_queries import handle as query

    store, client, receipt, run, emit = system
    emit("one")
    run()
    run()
    collection = Detections(store)
    original = next(
        row for row in collection.table.scan()["Items"] if row["sk"].startswith("DETECTION#")
    )
    core = DetectionHandling(receipt.feed, "core-signals", "one")
    body = {
        "expected_rev": 0,
        "request_id": "1" * 32,
        "reason": "Confirmed by SIEM analyst",
        "changes": {"status": "resolved", "disposition": "true-positive"},
    }
    accepted = core.update(body, "aws:111111111111:AROAABCDEFGHIJKLMNOP")
    client.fail_after_read = True
    assert run()["error_code"] == "agent_unreachable"
    assert (
        collection.table.get_item(Key={"pk": original["pk"], "sk": original["sk"]})["Item"]
        == original
    )
    assert run()["records"] == 1
    assert core.update(body, "aws:111111111111:AROAABCDEFGHIJKLMNOP")["idempotent"]
    assert run()["records"] == 0
    projected = collection.table.get_item(Key={"pk": original["pk"], "sk": original["sk"]})["Item"]
    assert projected["handling"] == accepted["handling"]
    assert {k: v for k, v in projected.items() if k != "handling"} == original
    _, listing = query("/v1/detections", {"status": "resolved"}, store)
    assert listing["items"][0]["handling"]["status"] == "resolved"
    job = DetectionBackfill(
        receipt.feed,
        "core-signals",
        {"account_id": "111111111111", "home_region": "us-east-1", "stage": "prod"},
        "after-triage",
    )
    planned = job.create({"reason": "retained history revalidation"}, "admin")
    assert (
        job.step({"expected_rev": 1, "plan_digest": planned["plan_digest"]})["state"] == "completed"
    )
    assert run()["records"] == 1
    assert (
        collection.table.get_item(Key={"pk": original["pk"], "sk": original["sk"]})["Item"]
        == projected
    )
    assert len(core.history({})["items"]) == 1
