import hashlib
import time
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from unittest.mock import MagicMock

import pytest

from opencdr_fleet._contracts.detection_query import (
    canonical,
    index_record,
    parameters,
    query_index,
)
from opencdr_fleet.detection_queries import handle
from opencdr_fleet.detections import Detections
from opencdr_fleet.models import FleetError, registration


@pytest.fixture
def indexed(detection_store):
    collection = Detections(detection_store)
    for name, account in [("a", "111111111111"), ("b", "222222222222")]:
        detection_store.save_agent(
            registration(
                {
                    "agent_id": name,
                    "account_id": account,
                    "region": "us-east-1",
                    "stage": "prod",
                    "auth_mode": "iam",
                    "api_url": "https://abc123.execute-api.us-east-1.amazonaws.com/prod",
                }
            ),
            create=True,
        )
        for n in range(6):
            stamp = (datetime.now(UTC) - timedelta(days=n // 2, minutes=1)).isoformat()
            payload = {
                "detection_id": f"{name}-{n}",
                "event_id": f"event-{n}",
                "severity": "HIGH" if n % 2 else "LOW",
                "rule_id": "r1",
                "source": "cloudtrail",
                "item_type": "correlation" if n % 2 else "signal",
                "raw_event": {"score": 1.0},
                "timestamp": "2020-01-01T00:00:00Z",
            }
            row = index_record(
                name,
                {"account_id": account, "home_region": "us-east-1", "stage": "prod"},
                payload,
                stamp,
                1,
                int(time.time()) + 86400,
            )
            row.update(
                pk="AGENT#" + name,
                sk="DETECTION#" + hashlib.sha256(payload["detection_id"].encode()).hexdigest(),
                payload=payload,
                payload_sha256=hashlib.sha256(canonical(payload).encode()).hexdigest(),
            )
            row["payload"]["raw_event"]["score"] = Decimal("1.0")
            collection.table.put_item(Item=row)
    return detection_store, collection


def test_list_is_summary_only_without_member_or_s3_reads(indexed, monkeypatch):
    store, _ = indexed
    from opencdr_fleet.agent import Agent

    monkeypatch.setattr(Agent, "verify", MagicMock(side_effect=AssertionError("fanout")))
    monkeypatch.setattr(
        store.s3, "get_object", MagicMock(side_effect=AssertionError("list evidence"))
    )
    code, page = handle("/v1/detections", {}, store)
    assert code == 200 and len(page["items"]) == 12
    assert all("raw_event" not in canonical(row) and "payload" not in row for row in page["items"])
    assert page["coverage"]["stale"] and page["coverage"]["ready_agents"] == 0
    assert page["coverage"]["history_complete"] is False
    assert all(row["summary"]["timestamp"].startswith("2020") for row in page["items"])


def test_cursor_pages_scoped_ordered_and_complete(indexed):
    store, _ = indexed
    query, results = {"limit": "2", "agent_ids": "a"}, []
    for _ in range(10):
        _, page = handle("/v1/detections", query, store)
        results.extend(page["items"])
        if not page["next_token"]:
            break
        query["next_token"] = page["next_token"]
    assert len(results) == len({row["detection_id"] for row in results}) == 6
    assert all(row["agent_id"] == "a" for row in results)
    assert [r["committed_at"] for r in results] == sorted(
        (r["committed_at"] for r in results), reverse=True
    )
    _, first = handle("/v1/detections", {"limit": "2", "agent_ids": "a"}, store)
    with pytest.raises(FleetError, match="invalid_detection_query"):
        handle(
            "/v1/detections",
            {"limit": "2", "agent_ids": "b", "next_token": first["next_token"]},
            store,
        )
    with pytest.raises(ValueError, match="scoped"):
        query_index(
            Detections(store).table,
            {"limit": "2", "agent_ids": "a", "next_token": first["next_token"]},
            scope="another-installation",
        )


def test_filters_and_exact_summary(indexed):
    store, _ = indexed
    filters = {
        "account_ids": "222222222222",
        "kind": "correlation",
        "severity": "HIGH",
        "rule_id": "r1",
        "source": "cloudtrail",
    }
    _, page = handle("/v1/detections", filters, store)
    assert len(page["items"]) == 3
    _, summary = handle("/v1/detections/summary", filters, store)
    assert summary["total"] == 3 and summary["counts"]["HIGH"] == 3 and summary["complete"]
    assert summary["counts_by_kind"] == {"signal": 0, "correlation": 3}
    _, missing = handle("/v1/detections", {"agent_ids": "unknown"}, store)
    assert not missing["items"] and missing["coverage"]["missing_agent_ids"] == ["unknown"]


def test_detail_identity_and_integrity(indexed):
    store, collection = indexed
    _, detail = handle("/v1/detections/detail", {"agent_id": "a", "detection_id": "a-0"}, store)
    assert detail["evidence"]["raw_event"]["score"] == 1
    with pytest.raises(FleetError, match="detection_not_found"):
        handle("/v1/detections/detail", {"agent_id": "b", "detection_id": "a-0"}, store)
    collection.table.update_item(
        Key={"pk": "AGENT#a", "sk": "DETECTION#" + hashlib.sha256(b"a-0").hexdigest()},
        UpdateExpression="SET payload_sha256 = :bad",
        ExpressionAttributeValues={":bad": "0" * 64},
    )
    with pytest.raises(FleetError, match="integrity"):
        handle("/v1/detections/detail", {"agent_id": "a", "detection_id": "a-0"}, store)


def test_expiry_enforced_before_ttl_purge(indexed):
    store, collection = indexed
    key = {"pk": "AGENT#a", "sk": "DETECTION#" + hashlib.sha256(b"a-0").hexdigest()}
    collection.table.update_item(
        Key=key, UpdateExpression="SET expires_at = :past", ExpressionAttributeValues={":past": 1}
    )
    _, page = handle("/v1/detections", {}, store)
    assert len(page["items"]) == 11
    with pytest.raises(FleetError, match="detection_not_found"):
        handle("/v1/detections/detail", {"agent_id": "a", "detection_id": "a-0"}, store)


def test_sparse_window_bounded_with_continuation(indexed):
    store, _ = indexed
    end = datetime.now(UTC).date()
    raw = {
        "date_from": (end - timedelta(days=89)).isoformat(),
        "date_to": end.isoformat(),
        "rule_id": "absent",
    }
    _, page = handle("/v1/detections", raw, store)
    assert page["index_queries"] == 16 and page["has_more"] and not page["items"]
    _, summary = handle("/v1/detections/summary", raw, store)
    assert summary["index_queries"] == 32 and summary["total"] == 0 and not summary["complete"]


@pytest.mark.parametrize(
    "query",
    [
        {"severity": "foo"},
        {"limit": "101"},
        {"limit": "true"},
        {"kind": "incident"},
        {"agent_ids": "a/../../"},
        {"account_ids": "123"},
        {"status": "closed"},
        {"date_from": "2020-01-01"},
        {"next_token": "bad"},
    ],
)
def test_bad_query_fails_closed(query):
    with pytest.raises(ValueError):
        parameters(query, scope="test")


def test_large_evidence_is_read_only_on_detail_and_corruption_is_explicit(indexed):
    store, collection = indexed
    item = store.get_agent("a")
    payload = {"detection_id": "large", "raw_event": {"text": "x" * 200_000}, "severity": "HIGH"}
    entry = {
        "payload": payload,
        "detection_id": "large",
        "kind": "signal",
        "revision": 1,
        "committed_at": datetime.now(UTC).isoformat(),
    }
    put = collection._record(item, entry)["Put"]
    store.client.put_item(TableName=put["TableName"], Item=put["Item"])
    _, detail = handle("/v1/detections/detail", {"agent_id": "a", "detection_id": "large"}, store)
    assert detail["evidence"] == payload
    key = put["Item"]["payload_key"]["S"]
    store.s3.put_object(Bucket=collection.bucket, Key=key, Body=b"corrupt")
    with pytest.raises(FleetError, match="integrity"):
        handle("/v1/detections/detail", {"agent_id": "a", "detection_id": "large"}, store)
    store.s3.delete_object(Bucket=collection.bucket, Key=key)
    with pytest.raises(FleetError, match="evidence_expired_or_missing") as missing:
        handle("/v1/detections/detail", {"agent_id": "a", "detection_id": "large"}, store)
    assert missing.value.status == 410


def test_cursor_expiry_and_byte_bound(indexed):
    store, collection = indexed
    now = datetime.now(UTC)
    first = query_index(collection.table, {"limit": "1"}, scope="test", now=now)
    with pytest.raises(ValueError, match="expired"):
        query_index(
            collection.table,
            {"limit": "1", "next_token": first["next_token"]},
            scope="test",
            now=now + timedelta(hours=2),
        )
    # Emulate a page of wide projected summaries; the unread row must survive continuation.
    sample = collection.table.scan(IndexName="by-day")["Items"][0]
    rows = [
        {
            **sample,
            "detection_id": str(n),
            "order": f"{now.date()}T00:00:00+00:00#{n:03}",
            "summary": {**sample["summary"], "rule_name": "x" * 30_000},
        }
        for n in reversed(range(80))
    ]

    class Table:
        def query(self, **kwargs):
            before = (
                kwargs["KeyConditionExpression"]
                .get_expression()["values"][1]
                .get_expression()["values"][1]
            )
            return {"Items": [row for row in rows if row["order"] < before]}

    result = query_index(
        Table(), {"limit": "100", "date_from": now.date().isoformat()}, scope="test", now=now
    )
    assert len(canonical(result).encode()) < 1_100_000
    assert result["has_more"] and 1 < len(result["items"]) < 80

    seen = list(result["items"])
    raw = {"limit": "100", "date_from": now.date().isoformat()}
    while result["next_token"]:
        result = query_index(
            Table(), {**raw, "next_token": result["next_token"]}, scope="test", now=now
        )
        seen.extend(result["items"])
    assert len(seen) == len({row["detection_id"] for row in seen}) == 80


def test_hundred_account_coverage_uses_batch_receipts_without_live_fanout(indexed, monkeypatch):
    store, _ = indexed
    for n in range(98):
        store.save_agent(
            registration(
                {
                    "agent_id": f"account-{n}",
                    "account_id": f"{n:012}",
                    "region": "us-east-1",
                    "stage": "dev",
                    "auth_mode": "iam",
                    "api_url": "https://abc123.execute-api.us-east-1.amazonaws.com/dev",
                }
            ),
            create=True,
        )
    from opencdr_fleet.agent import Agent

    monkeypatch.setattr(
        Agent, "request", MagicMock(side_effect=AssertionError("live account fanout"))
    )
    batch = MagicMock(wraps=store.client.batch_get_item)
    monkeypatch.setattr(store.client, "batch_get_item", batch)
    _, result = handle("/v1/detections", {}, store)
    assert result["coverage"]["selected_agents"] == 100
    assert result["coverage"]["coverage_truncated"] is False
    batch.assert_called_once()
    assert len(batch.call_args.kwargs["RequestItems"]["detections"]["Keys"]) == 100
