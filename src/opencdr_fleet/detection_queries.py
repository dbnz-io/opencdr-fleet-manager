"""Fleet index reads. Never call member Core endpoints from a query."""

import hashlib
import json
import os
import time

from boto3.dynamodb.types import TypeDeserializer
from botocore.exceptions import ClientError

from ._contracts.detection_query import (
    VERSION,
    canonical,
    hydrate_handling,
    public_record,
    query_index,
)
from .detections import Detections
from .models import FleetError, agent_id
from .store import wire


def coverage(store, query):
    selected = set(query.get("agent_ids", []))
    accounts = set(query.get("account_ids", []))
    records, cursor, exhausted = [], None, False
    # Bound registry work separately from detection-index work. No member HTTP calls.
    for _ in range(20):
        page, cursor = store.agents(50, cursor)
        records.extend(
            item
            for item in page
            if (not selected or item["agent_id"] in selected)
            and (not accounts or item["account_id"] in accounts)
        )
        if not cursor:
            exhausted = True
            break
    collection = Detections(store)
    pending = [{"pk": "AGENT#" + item["agent_id"], "sk": "CHECKPOINT"} for item in records[:100]]
    receipts = {}
    decoder = TypeDeserializer()
    for _ in range(3):
        if not pending:
            break
        batch = store.client.batch_get_item(
            RequestItems={
                collection.table.name: {
                    "Keys": [wire(key) for key in pending],
                    "ConsistentRead": True,
                }
            }
        )
        for raw in batch.get("Responses", {}).get(collection.table.name, []):
            row = {key: decoder.deserialize(value) for key, value in raw.items()}
            receipts[row["pk"]] = row
        pending = [
            {k: decoder.deserialize(v) for k, v in raw.items()}
            for raw in batch.get("UnprocessedKeys", {})
            .get(collection.table.name, {})
            .get("Keys", [])
        ]
    states = [
        collection.status(item, receipts.get("AGENT#" + item["agent_id"], {}))
        for item in records[:100]
    ]
    found = {item["agent_id"] for item in records}
    missing = sorted(selected - found)
    stale = [item for item in states if item["stale"] or not item["enabled"]]
    return {
        "mode": "fleet",
        "source": "fleet_index",
        "history_complete": False,
        "history_reason": "historical_completeness_unverified",
        "agents": states,
        "selected_agents": len(records),
        "ready_agents": len(states) - len(stale),
        "stale": bool(stale or missing or not exhausted or len(records) > 100),
        "missing_agent_ids": missing,
        "coverage_truncated": not exhausted or len(records) > 100,
    }


def handle(path, query, store):
    collection = Detections(store)
    deployment = {
        "account_id": os.environ["SECURITY_ACCOUNT_ID"],
        "home_region": os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "")),
        "stage": os.environ["FLEET_STAGE"],
    }
    scope = "fleet:" + ":".join(deployment.values())
    try:
        if path == "/v1/detections/detail":
            if set(query) - {"agent_id", "detection_id"}:
                raise ValueError("Unsupported detail parameters")
            name = agent_id(query.get("agent_id", ""))
            identity = query.get("detection_id", "")
            if not isinstance(identity, str) or not 1 <= len(identity) <= 512:
                raise ValueError("Detection identity is required")
            store.get_agent(name)  # Remains visible when disabled, with explicit stale coverage.
            row = collection.table.get_item(
                Key={
                    "pk": "AGENT#" + name,
                    "sk": "DETECTION#" + hashlib.sha256(identity.encode()).hexdigest(),
                },
                ConsistentRead=True,
            ).get("Item")
            if not row or int(row["expires_at"]) <= time.time():
                raise FleetError("detection_not_found", 404)
            if "payload_key" in row:
                try:
                    body = store.s3.get_object(Bucket=collection.bucket, Key=row["payload_key"])[
                        "Body"
                    ]
                except ClientError as error:
                    if error.response["Error"]["Code"] == "NoSuchKey":
                        raise FleetError("detection_evidence_expired_or_missing", 410) from None
                    raise
                try:
                    raw = body.read(1_000_001)
                finally:
                    body.close()
                if len(raw) > 1_000_000 or hashlib.sha256(raw).hexdigest() != row["payload_sha256"]:
                    raise FleetError("detection_evidence_integrity_failure", 502)
                payload = json.loads(raw)
            else:
                payload = row["payload"]
                if hashlib.sha256(canonical(payload).encode()).hexdigest() != row["payload_sha256"]:
                    raise FleetError("detection_evidence_integrity_failure", 502)
            return 200, {
                "schema_version": VERSION,
                "item": public_record(row),
                "evidence": payload,
                "coverage": coverage(store, {"agent_ids": [name]}),
                "deployment": deployment,
            }
        result = query_index(
            collection.table,
            query,
            scope=scope,
            summary=path == "/v1/detections/summary",
            hydrate=lambda rows: hydrate_handling(collection.table, rows, "sk"),
        )
        result.update(
            coverage=coverage(store, result["query"]),
            deployment=deployment,
            time_basis="committed_at",
        )
        return 200, result
    except ValueError:
        raise FleetError("invalid_detection_query", 400) from None
