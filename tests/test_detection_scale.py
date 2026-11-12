"""Opt-in 100-account local workload; this is not AWS latency or cost evidence.

Run with OPENCDR_SCALE_TEST=1; optionally set OPENCDR_SCALE_REPORT to a JSON path.
Moto exercises DynamoDB serialization, projection and pagination. Real capacity,
throttling, eventual-consistency delay and collection lag require the AWS rehearsal.
"""

import hashlib
import json
import math
import os
import time
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from botocore.client import BaseClient

from opencdr_fleet._contracts.detection_query import index_record
from opencdr_fleet.agent import Agent
from opencdr_fleet.detection_queries import handle
from opencdr_fleet.detections import Detections
from opencdr_fleet.models import registration


@pytest.mark.skipif(os.getenv("OPENCDR_SCALE_TEST") != "1", reason="opt-in local scale workload")
def test_100_accounts_90_days_pagination_and_query_budgets(detection_store, monkeypatch):
    store = detection_store
    table = Detections(store).table
    end = datetime.now(UTC).replace(hour=12, minute=0, second=0, microsecond=0) - timedelta(days=1)
    accounts = [str(100_000_000_000 + n) for n in range(100)]
    expected = set()
    seed_started = time.perf_counter()
    for n, account in enumerate(accounts):
        store.save_agent(
            registration(
                {
                    "agent_id": f"scale-{n:03}",
                    "account_id": account,
                    "region": "us-east-1",
                    "stage": "test",
                    "auth_mode": "iam",
                    "api_url": "https://abc123.execute-api.us-east-1.amazonaws.com/test",
                }
            ),
            create=True,
        )
    with table.batch_writer() as writer:
        for n, account in enumerate(accounts):
            agent = f"scale-{n:03}"
            for day in range(90):
                for kind, severity in (("signal", "LOW"), ("correlation", "HIGH")):
                    identity = f"{agent}-{day:02}-{kind}"
                    row = index_record(
                        agent,
                        {"account_id": account, "home_region": "us-east-1", "stage": "test"},
                        {"detection_id": identity, "item_type": kind, "severity": severity},
                        (end - timedelta(days=day)).isoformat(),
                        1,
                        int(time.time()) + 86400,
                    )
                    row.update(
                        pk="AGENT#" + agent,
                        sk="DETECTION#" + hashlib.sha256(identity.encode()).hexdigest(),
                    )
                    writer.put_item(Item=row)
                    expected.add((agent, identity))
    seed_seconds = time.perf_counter() - seed_started

    # Any member HTTP, evidence fetch, scan or query-time mutation fails this run.
    forbidden = MagicMock(side_effect=AssertionError("live member fanout"))
    monkeypatch.setattr(Agent, "verify", forbidden)
    monkeypatch.setattr(Agent, "request", forbidden)
    operations = Counter()
    api_call = BaseClient._make_api_call

    def tracked(client, operation, params):
        assert client.meta.service_model.service_name == "dynamodb", "non-index service call"
        assert operation in {"Query", "BatchGetItem"}, "scan, detail read or mutation"
        if operation == "Query":
            assert params["Limit"] <= 100
            target = params["TableName"]
        else:
            assert sum(len(v["Keys"]) for v in params["RequestItems"].values()) <= 100
            target = ",".join(sorted(params["RequestItems"]))
        operations[f"{operation}:{target}"] += 1
        return api_call(client, operation, params)

    monkeypatch.setattr(BaseClient, "_make_api_call", tracked)
    base = {
        "account_ids": ",".join(accounts),
        "date_from": (end - timedelta(days=89)).date().isoformat(),
        "date_to": end.date().isoformat(),
        "limit": "50",
    }
    measurements = {}

    def pages(label, path, query):
        samples, examined, index_queries = [], 0, 0
        before_ops = operations.copy()
        tokens = set()
        raw = dict(query)
        for _ in range(1000):
            started = time.perf_counter()
            code, result = handle(path, raw, store)
            samples.append(time.perf_counter() - started)
            assert code == 200
            summary = path.endswith("summary")
            assert result["index_queries"] <= (32 if summary else 16)
            assert result["evaluated_records"] <= (5000 if summary else 1000)
            coverage = result["coverage"]
            assert coverage["selected_agents"] == len(query["account_ids"].split(","))
            assert not coverage["coverage_truncated"]
            assert coverage["history_complete"] is False
            examined += result["evaluated_records"]
            index_queries += result["index_queries"]
            yield result
            token = result["next_token"]
            if not token:
                break
            assert token not in tokens, "cursor must advance even on an empty filtered page"
            tokens.add(token)
            raw["next_token"] = token
        else:
            pytest.fail("scale query did not exhaust its continuation")
        ordered = sorted(samples)
        measurements[label] = {
            "pages": len(samples),
            "evaluated_records": examined,
            "index_queries": index_queries,
            "local_page_seconds_max": max(samples),
            "local_page_seconds_total": sum(samples),
            "local_page_seconds_percentiles": {
                str(p): ordered[math.ceil(p / 100 * len(ordered)) - 1] for p in (50, 95, 99)
            },
            "percentile_method": "nearest_rank",
            "dynamodb_operations": dict(operations - before_ops),
        }

    listed = []
    committed = []
    for page in pages("all_accounts_list", "/v1/detections", base):
        listed.extend((item["agent_id"], item["detection_id"]) for item in page["items"])
        committed.extend(item["committed_at"] for item in page["items"])
        assert all("payload" not in item for item in page["items"])
    assert len(listed) == len(set(listed)) == 18_000
    assert set(listed) == expected
    assert committed == sorted(committed, reverse=True)

    kinds, severities = Counter(), Counter()
    total = 0
    for page in pages("all_accounts_summary", "/v1/detections/summary", base):
        total += page["total"]
        kinds.update(page["counts_by_kind"])
        severities.update(page["counts"])
    assert total == 18_000
    assert kinds == {"signal": 9000, "correlation": 9000}
    assert severities["LOW"] == severities["HIGH"] == 9000

    selected = []
    for page in pages(
        "single_account_sparse_list", "/v1/detections", {**base, "account_ids": accounts[0]}
    ):
        selected.extend((item["agent_id"], item["detection_id"]) for item in page["items"])
    assert len(selected) == len(set(selected)) == 180
    assert set(selected) == {item for item in expected if item[0] == "scale-000"}
    forbidden.assert_not_called()

    report = {
        "environment": "local_moto",
        "aws_acceptance": False,
        "accounts": 100,
        "days": 90,
        "detections": 18_000,
        "list_page_limit": 50,
        "seed_seconds": seed_seconds,
        "member_requests": 0,
        "evidence_requests": 0,
        "scans": 0,
        "measurements": measurements,
        "not_measured": ["AWS latency/cost", "collection lag/backlog", "throttling", "GSI lag"],
    }
    if destination := os.getenv("OPENCDR_SCALE_REPORT"):
        Path(destination).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
