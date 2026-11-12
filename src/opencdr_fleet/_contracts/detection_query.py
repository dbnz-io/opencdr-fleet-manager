"""Shared detection query contract 1.0.0; canonical source in OpenCDR Core.

Fleet vendors this module with a checked SHA-256 pin. Cursors are pagination
positions, not authorization. Every page reapplies all requested filters.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal

from .detection_handling import DISPOSITIONS, STATUSES, initial

VERSION = "1.0.0"
SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "INFORMATIONAL"}
PUBLIC_FIELDS = (
    "agent_id",
    "account_id",
    "region",
    "stage",
    "detection_id",
    "kind",
    "committed_at",
    "revision",
    "summary",
)


def canonical(value):
    def number(value):
        if isinstance(value, Decimal):
            return int(value) if value == int(value) else float(value)
        raise TypeError("Unsupported JSON value")

    def normalize(item):
        if isinstance(item, float) and item.is_integer():
            return int(item)
        if isinstance(item, dict):
            return {k: normalize(v) for k, v in item.items()}
        if isinstance(item, list):
            return [normalize(v) for v in item]
        return item

    return json.dumps(
        normalize(value), default=number, sort_keys=True, separators=(",", ":"), allow_nan=False
    )


def summarize(payload):
    context = payload.get("primary_signal") or payload
    if not isinstance(context, dict):
        context = {}
    result = {}
    for key in (
        "event_id",
        "alert_id",
        "timestamp",
        "event_time",
        "rule_id",
        "rule_name",
        "rule_revision",
        "rule_version",
        "content_fingerprint",
        "release_id",
        "release_version",
        "evaluation_mode",
        "contract_version",
        "match_count",
    ):
        value = payload.get(key)
        if type(value) in (str, int, float) or isinstance(value, Decimal):
            if len(canonical(value).encode()) <= 1024:
                result[key] = value
    severity = str(payload.get("severity", "UNKNOWN")).upper()
    result["severity"] = severity if severity in SEVERITIES else "UNKNOWN"
    for key in ("source", "integration_id", "activity_name", "category", "runtime_entity"):
        value = context.get(key)
        if isinstance(value, str) and len(value) <= 256:
            result[key] = value
    for key, fields in {
        "actor": ("arn", "user_name", "principal_id"),
        "api": ("event_name", "operation"),
        "network": ("source_ip",),
    }.items():
        value = context.get(key)
        if isinstance(value, dict):
            result[key] = {
                k: value[k]
                for k in fields
                if isinstance(value.get(k), str) and len(value[k]) <= 512
            }
    return result


def index_record(agent_id, deployment, payload, committed_at, revision, expires_at):
    stamp = datetime.fromisoformat(committed_at.replace("Z", "+00:00")).astimezone(UTC)
    identity = hashlib.sha256(payload["detection_id"].encode()).hexdigest()
    return {
        "agent_id": agent_id,
        "account_id": deployment["account_id"],
        "region": deployment["home_region"],
        "stage": deployment["stage"],
        "detection_id": payload["detection_id"],
        "kind": "correlation" if payload.get("item_type") == "correlation" else "signal",
        "committed_at": stamp.isoformat(timespec="microseconds"),
        "revision": revision,
        "expires_at": int(expires_at),
        "summary": summarize(payload),
        "day": "DAY#" + stamp.date().isoformat(),
        "order": stamp.isoformat(timespec="microseconds") + "#" + agent_id + "#" + identity,
    }


def public_record(row):
    return {**{key: row[key] for key in PUBLIC_FIELDS}, "handling": row.get("handling", initial())}


def parameters(raw, *, scope, now=None):
    now = now or datetime.now(UTC)
    allowed = {
        "date_from",
        "date_to",
        "limit",
        "next_token",
        "agent_ids",
        "account_ids",
        "severity",
        "kind",
        "rule_id",
        "source",
        "integration_id",
        "status",
        "disposition",
        "has_incident",
    }
    if (
        not isinstance(raw, dict)
        or set(raw) - allowed
        or any(not isinstance(v, str) for v in raw.values())
    ):
        raise ValueError("Unsupported detection query parameters")
    end = date.fromisoformat(raw.get("date_to", now.date().isoformat()))
    start = date.fromisoformat(raw.get("date_from", (end - timedelta(days=6)).isoformat()))
    if start > end or (end - start).days >= 90 or end > now.date():
        raise ValueError(
            "Detection queries require an inclusive window of 1–90 days, ending today or earlier"
        )
    limit = int(raw.get("limit", "50"))
    if not 1 <= limit <= 100:
        raise ValueError("Detection page limit must be 1–100")
    result = {"date_from": start.isoformat(), "date_to": end.isoformat(), "limit": limit}
    for key, count, pattern in (
        ("agent_ids", 100, r"[A-Za-z0-9_.:-]{1,128}"),
        ("account_ids", 100, r"[0-9]{12}"),
        ("severity", 6, r"[A-Z]+"),
    ):
        values = sorted(set(raw[key].split(","))) if key in raw else []
        if len(values) > count or any(not re.fullmatch(pattern, v) for v in values):
            raise ValueError("Invalid detection scope or severity")
        if key == "severity" and not set(values) <= SEVERITIES:
            raise ValueError("Invalid severity")
        result[key] = values
    for key in ("kind", "rule_id", "source", "integration_id"):
        value = raw.get(key)
        if value is not None and (not 1 <= len(value) <= 128 or any(ord(c) < 32 for c in value)):
            raise ValueError("Invalid detection filter")
        result[key] = value
    if result["kind"] is not None and result["kind"] not in {"signal", "correlation"}:
        raise ValueError("Detection kind must be signal or correlation")
    for key, choices in (
        ("status", STATUSES),
        ("disposition", DISPOSITIONS),
        ("has_incident", {"true", "false"}),
    ):
        value = raw.get(key)
        if value is not None and value not in choices:
            raise ValueError("Invalid handling filter")
        result[key] = value
    binding = hashlib.sha256(canonical({"scope": scope, "query": result}).encode()).hexdigest()
    as_of = now.isoformat(timespec="microseconds")
    day, before = end.isoformat(), min(end.isoformat() + "T~", as_of + "~")
    token = raw.get("next_token")
    if token:
        try:
            if len(token) > 4096:
                raise ValueError
            cursor = json.loads(
                base64.b64decode(token + "=" * (-len(token) % 4), altchars=b"-_", validate=True)
            )
            if (
                set(cursor) != {"version", "binding", "as_of", "day", "before"}
                or cursor["version"] != VERSION
                or cursor["binding"] != binding
            ):
                raise ValueError
            stamp = datetime.fromisoformat(cursor["as_of"])
            if stamp.tzinfo is None or stamp > now or now.timestamp() - stamp.timestamp() > 3600:
                raise ValueError
            day, before, as_of = cursor["day"], cursor["before"], cursor["as_of"]
            if (
                not start <= date.fromisoformat(day) <= end
                or not isinstance(before, str)
                or len(before) > 1024
                or not before.startswith(day + "T")
            ):
                raise ValueError
            if before > min(day + "T~", as_of + "~"):
                raise ValueError
        except (ValueError, TypeError, KeyError, UnicodeError):
            raise ValueError("Invalid, expired or differently scoped detection cursor") from None
    return result, {
        "version": VERSION,
        "binding": binding,
        "as_of": as_of,
        "day": day,
        "before": before,
    }


def _token(cursor):
    return base64.urlsafe_b64encode(canonical(cursor).encode()).decode().rstrip("=")


def matches(row, query):
    summary = row.get("summary", {})
    handling = row.get("handling", initial())
    if query.get("status") and handling["status"] != query["status"]:
        return False
    if query.get("disposition") and handling["disposition"] != query["disposition"]:
        return False
    if query.get("has_incident") and bool(handling["external_refs"]) != (
        query["has_incident"] == "true"
    ):
        return False
    if query["agent_ids"] and row["agent_id"] not in query["agent_ids"]:
        return False
    if query["account_ids"] and row["account_id"] not in query["account_ids"]:
        return False
    if query["severity"] and summary.get("severity") not in query["severity"]:
        return False
    if query["kind"] and row["kind"] != query["kind"]:
        return False
    return all(
        not query[key] or summary.get(key) == query[key]
        for key in ("rule_id", "source", "integration_id")
    )


def hydrate_handling(table, rows, sort_key):
    """Read current metadata in bounded local batches without replacing the existing GSI."""
    if not rows:
        return rows
    pending = {
        table.name: {
            "Keys": [{"pk": row["pk"], sort_key: row[sort_key]} for row in rows],
            "ConsistentRead": True,
            "ProjectionExpression": "pk, #sk, handling, expires_at",
            "ExpressionAttributeNames": {"#sk": sort_key},
        }
    }
    found = {}
    for _ in range(3):
        result = table.meta.client.batch_get_item(RequestItems=pending)
        for row in result.get("Responses", {}).get(table.name, []):
            found[(row["pk"], row[sort_key])] = row
        pending = result.get("UnprocessedKeys", {})
        if not pending:
            break
    if pending:
        raise RuntimeError("Detection handling metadata is temporarily unavailable")
    return [
        {
            **row,
            "handling": found.get((row["pk"], row[sort_key]), {}).get("handling", initial()),
            "expires_at": found.get((row["pk"], row[sort_key]), {}).get("expires_at", 0),
        }
        for row in rows
    ]


def query_index(table, raw, *, scope, summary=False, now=None, hydrate=None):
    from boto3.dynamodb.conditions import Key

    query, cursor = parameters(raw, scope=scope, now=now)
    day = date.fromisoformat(cursor["day"])
    start = date.fromisoformat(query["date_from"])
    before, items, calls, examined = cursor["before"], [], 0, 0
    counts = {key: 0 for key in sorted(SEVERITIES | {"UNKNOWN"})}
    kinds = {"signal": 0, "correlation": 0}
    statuses = {key: 0 for key in sorted(STATUSES)}
    total_bytes, byte_limit_hit = 0, False
    budget = 5000 if summary else 1000
    max_calls = 32 if summary else 16
    deadline = time.monotonic() + 8
    while day >= start and calls < max_calls and examined < budget and time.monotonic() < deadline:
        page = table.query(
            IndexName="by-day",
            KeyConditionExpression=Key("day").eq("DAY#" + day.isoformat())
            & Key("order").lt(before),
            ScanIndexForward=False,
            Limit=min(100, budget - examined),
        )
        calls += 1
        rows = page.get("Items", [])
        if not rows and page.get("LastEvaluatedKey"):
            raise ValueError("Detection index returned a nonadvancing page")
        if hydrate:
            rows = hydrate(rows)
        consumed = 0
        for row in rows:
            examined += 1
            consumed += 1
            prior = before
            before = row["order"]
            if int(row["expires_at"]) <= time.time() or not matches(row, query):
                continue
            if summary:
                counts[
                    row["summary"].get("severity")
                    if row["summary"].get("severity") in counts
                    else "UNKNOWN"
                ] += 1
                kinds[row["kind"]] += 1
                statuses[row.get("handling", initial())["status"]] += 1
            else:
                public = public_record(row)
                size = len(canonical(public).encode())
                if items and total_bytes + size > 1_000_000:
                    before, consumed, byte_limit_hit = prior, consumed - 1, True
                    break
                items.append(public)
                total_bytes += size
                if len(items) >= query["limit"]:
                    break
        if consumed == len(rows) and not page.get("LastEvaluatedKey"):
            day -= timedelta(days=1)
            before = day.isoformat() + "T~"
        if byte_limit_hit or (not summary and len(items) >= query["limit"]):
            break
    more = day >= start
    cursor.update(day=day.isoformat(), before=before)
    result = {
        "schema_version": VERSION,
        "query": query,
        "as_of": cursor["as_of"],
        "next_token": _token(cursor) if more else None,
        "has_more": more,
        "consistency": "eventual",
        "evaluated_records": examined,
        "index_queries": calls,
    }
    if summary:
        result.update(
            counts=counts,
            counts_by_kind=kinds,
            counts_by_status=statuses,
            total=sum(kinds.values()),
            complete=not more,
        )
    else:
        result["items"] = items
    return result
