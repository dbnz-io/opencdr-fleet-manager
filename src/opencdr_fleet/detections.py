"""Independent, bounded detection collection with transactional receipt/checkpoint.

Configuration generations never control this worker. A page becomes visible in
Fleet only in the same transaction that advances its per-agent checkpoint.
"""

from __future__ import annotations

import hashlib
import os
import time
import uuid
from datetime import datetime

from botocore.exceptions import ClientError

from ._contracts.detection_query import canonical, index_record
from .agent import Agent
from .handling_projection import existing_operation, validate_state
from .models import FleetError, json_text, now_iso
from .store import conditional, wire

PAGE_LIMIT = 20
# A 2,000-record burst needs more than 100 records per one-minute tick.
# The independent 40-second deadline still bounds slow or large-payload polls.
MAX_PAGES = 10


def policy():
    try:
        minutes = int(os.getenv("DETECTION_POLL_INTERVAL_MINUTES", "1"))
        days = int(os.getenv("DETECTION_RETENTION_DAYS", "90"))
        if not 1 <= minutes <= 60 or not 7 <= days <= 365:
            raise ValueError
    except ValueError:
        raise FleetError("invalid_detection_polling_configuration", 503) from None
    return minutes * 60, days


def installed():
    return bool(os.getenv("DETECTION_TABLE") and os.getenv("DETECTION_BUCKET"))


class Detections:
    def __init__(self, store):
        if not installed():
            raise FleetError("detection_collection_not_installed", 503)
        self.store = store
        self.table = store.ddb.Table(os.environ["DETECTION_TABLE"])
        self.bucket = os.environ["DETECTION_BUCKET"]
        self.s3 = store.s3
        self.interval, self.retention_days = policy()

    def checkpoint(self, name):
        return self.table.get_item(
            Key={"pk": "AGENT#" + name, "sk": "CHECKPOINT"}, ConsistentRead=True
        ).get("Item", {})

    def status(self, registration, state=None):
        state = self.checkpoint(registration["agent_id"]) if state is None else state
        success = int(state.get("success_ms", 0))
        return {
            "agent_id": registration["agent_id"],
            "state": state.get("state", "not_collected"),
            "enabled": registration["enabled"]
            and registration.get("auth_mode") == "iam"
            and os.getenv("DETECTION_POLLING_ENABLED", "true") == "true",
            "registration_current": state.get("registration_rev") == registration["rev"],
            "stale": not success
            or state.get("registration_rev") != registration["rev"]
            or not registration["enabled"]
            or state.get("state") != "ready"
            or time.time() * 1000 - success > self.interval * 3000,
            "poll_interval_seconds": self.interval,
            "receipt_pending": bool(state.get("consumer_receipt_id")),
            "checkpoint_generation": int(state.get("generation", 0)),
            "reconciliation_request_id": registration.get("detection_reconciliation", {}).get(
                "request_id"
            ),
            "handoff_intent_id": registration.get("detection_handoff", {}).get("request_id"),
            **{
                k: v
                for k, v in state.items()
                if k not in {"pk", "sk", "cursor", "generation", "consumer_receipt_id"}
            },
        }

    def claim(self, message):
        token = uuid.uuid4().hex
        try:
            value = self.store.registry.update_item(
                Key={"id": "AGENT#" + message["agent_id"]},
                ConditionExpression=(
                    "rev = :rev AND enabled = :yes AND auth_mode = :iam AND "
                    "(attribute_not_exists(detection_lease_until) OR detection_lease_until < :now) "
                    "AND (attribute_not_exists(detection_completed_sequence) OR "
                    "detection_completed_sequence < :sequence)"
                ),
                UpdateExpression="SET detection_token = :token, detection_lease_until = :until",
                ExpressionAttributeValues={
                    ":rev": message["rev"],
                    ":yes": True,
                    ":iam": "iam",
                    ":now": int(time.time()),
                    ":until": int(time.time()) + 90,
                    ":token": token,
                    ":sequence": message["sequence"],
                },
                ReturnValues="ALL_NEW",
            )["Attributes"]
            return value, token
        except ClientError as error:
            if conditional(error):
                return None
            raise

    def _fence(self, item, token, sequence=None):
        values = {":rev": item["rev"], ":token": token, ":now": int(time.time()), ":yes": True}
        args = {
            "TableName": self.store.registry.name,
            "Key": wire({"id": item["id"]}),
            "ConditionExpression": (
                "rev = :rev AND enabled = :yes AND detection_token = :token "
                "AND detection_lease_until > :now"
            ),
        }
        if sequence is not None:
            values[":sequence"] = sequence
            args["UpdateExpression"] = (
                "SET detection_completed_sequence = :sequence "
                "REMOVE detection_token, detection_lease_until"
            )
        args["ExpressionAttributeValues"] = wire(values)
        return {"Update" if sequence is not None else "ConditionCheck": args}

    def _checkpoint_put(self, item, previous, state):
        value = {
            **state,
            "pk": "AGENT#" + item["agent_id"],
            "sk": "CHECKPOINT",
            "registration_rev": item["rev"],
            "generation": int(previous.get("generation", 0)) + 1,
        }
        args = {"TableName": self.table.name, "Item": wire(value)}
        if previous:
            args.update(
                ConditionExpression="generation = :generation",
                ExpressionAttributeValues=wire({":generation": previous["generation"]}),
            )
        else:
            args["ConditionExpression"] = "attribute_not_exists(pk)"
        return {"Put": args}, value

    def _record(self, item, entry):
        payload = canonical(entry["payload"]).encode()
        digest = hashlib.sha256(payload).hexdigest()
        identity = hashlib.sha256(entry["detection_id"].encode()).hexdigest()
        historical = entry.get("change_type") == "detection.backfilled"
        metadata = entry.get("change_type") == "detection.handling_updated"
        indexed_at = (
            entry["indexed_committed_at"] if historical or metadata else entry["committed_at"]
        )
        committed = datetime.fromisoformat(indexed_at.replace("Z", "+00:00"))
        expires = int(committed.timestamp()) + self.retention_days * 86400
        if historical or metadata:
            expires = min(expires, entry["source_expires_at"])
        key = {"pk": "AGENT#" + item["agent_id"], "sk": "DETECTION#" + identity}
        existing = self.table.get_item(Key=key, ConsistentRead=True).get("Item")
        if existing:
            return existing_operation(self, key, existing, entry, digest)
        record = {
            **index_record(
                item["agent_id"],
                {
                    "account_id": item["account_id"],
                    "home_region": item["region"],
                    "stage": item["stage"],
                },
                entry["payload"],
                indexed_at,
                1,
                expires,
            ),
            "pk": "AGENT#" + item["agent_id"],
            "sk": "DETECTION#" + identity,
            "kind": entry["kind"],
            "payload_sha256": digest,
        }
        if "handling" in entry:
            record["handling"] = entry["handling"]
        if historical:
            record["summary"].update(
                delivery_origin="backfill",
                backfill_job_id=entry["backfill_job_id"],
                original_commit_time_known=entry["original_commit_time_known"],
            )
        if len(payload) > 100_000:
            key = "detections/" + item["agent_id"] + "/" + digest + ".json"
            try:
                self.s3.put_object(
                    Bucket=self.bucket,
                    Key=key,
                    Body=payload,
                    ContentType="application/json",
                    ServerSideEncryption="AES256",
                    IfNoneMatch="*",
                )
            except ClientError as error:
                if error.response["Error"]["Code"] != "PreconditionFailed":
                    raise
            record["payload_key"] = key
        else:
            record["payload"] = entry["payload"]
        return {
            "Put": {
                "TableName": self.table.name,
                "Item": wire(record),
                "ConditionExpression": "attribute_not_exists(pk)",
            }
        }

    def persist(self, item, token, previous, page, consumer_state=None):
        records = [self._record(item, entry) for entry in page["items"]]
        state = {
            **previous,
            **(consumer_state or {}),
            "cursor": page["next_cursor"],
            "last_attempt_at": now_iso(),
            "last_success_at": now_iso(),
            "success_ms": int(time.time() * 1000),
            "has_more": page["has_more"],
            "state": "catching_up" if page["has_more"] else "ready",
            "last_page_records": len(records),
            "verified_registration_rev": item["rev"],
            "last_sequence": page["items"][-1]["sequence"]
            if records
            else previous.get("last_sequence", 0),
        }
        state.pop("error_code", None)
        # Independent downstream subscribers consume every collected sequence.
        # These small references share the collector's receipt transaction.
        state["automation_epoch"] = previous.get("automation_epoch") or uuid.uuid4().hex
        journal = []
        for entry in page["items"]:
            row = {
                "pk": "ROUTING_FEED#" + item["agent_id"] + "#" + state["automation_epoch"],
                "sk": f"{int(entry['sequence']):020d}",
                "sequence": entry["sequence"],
                "detection_id": entry["detection_id"],
                "change_type": entry["change_type"],
                "payload_sha256": hashlib.sha256(canonical(entry["payload"]).encode()).hexdigest(),
                "automation_origin": "live"
                if entry["payload"].get("_opencdr_delivery")
                == {"schema": "1.0.0", "origin": "live"}
                and entry["change_type"] == "detection.created"
                else "ineligible",
                "expires_at": int(time.time()) + self.retention_days * 86400,
            }
            journal.append(
                {
                    "Put": {
                        "TableName": self.table.name,
                        "Item": wire(row),
                        "ConditionExpression": "attribute_not_exists(pk)",
                    }
                }
            )
        put, state = self._checkpoint_put(item, previous, state)
        self.store.client.transact_write_items(
            TransactItems=[self._fence(item, token), *records, *journal, put]
        )
        return state

    def finish(self, item, token, sequence, previous, error=None):
        state = {**previous, "last_attempt_at": now_iso()}
        if error:
            state.update(
                state="gap"
                if error.code == "detection_retention_gap" or previous.get("state") == "gap"
                else "failed",
                error_code=error.code,
            )
        put, _ = self._checkpoint_put(item, previous, state)
        self.store.client.transact_write_items(
            TransactItems=[self._fence(item, token, sequence), put]
        )


def validate_page(page, item, previous):
    """Reject unknown contracts, missing/duplicate records and cursor stalls before receipt."""
    try:
        if not isinstance(page, dict) or page.get("schema_version") not in {
            "1.0.0",
            "1.1.0",
            "1.2.0",
        }:
            raise ValueError
        if page["deployment"] != {
            "account_id": item["account_id"],
            "home_region": item["region"],
            "stage": item["stage"],
        }:
            raise ValueError
        entries = page["items"]
        if not isinstance(entries, list) or len(entries) > PAGE_LIMIT:
            raise ValueError
        if type(page["has_more"]) is not bool or len(json_text(page).encode()) > 1_300_000:
            raise ValueError
        cursor = page["next_cursor"]
        if cursor is not None and (not isinstance(cursor, str) or not 1 <= len(cursor) <= 512):
            raise ValueError
        if entries and (not cursor or cursor == previous.get("cursor")):
            raise ValueError
        if not entries and (
            page["has_more"] or (previous.get("cursor") and cursor != previous["cursor"])
        ):
            raise ValueError
        identities, sequence = set(), int(previous.get("last_sequence", 0))
        for entry in entries:
            identity = entry["detection_id"]
            if (
                not isinstance(identity, str)
                or not 1 <= len(identity) <= 512
                or identity in identities
                or entry["schema_version"] not in {"1.0.0", "1.1.0", "1.2.0"}
                or entry["change_type"]
                not in {"detection.created", "detection.backfilled", "detection.handling_updated"}
                or type(entry["revision"]) is not int
                or entry["revision"] < 1
                or (entry["change_type"] != "detection.handling_updated" and entry["revision"] != 1)
                or entry["kind"] not in {"signal", "correlation"}
                or type(entry["sequence"]) is not int
                or entry["sequence"] != sequence + 1
                or not isinstance(entry["payload"], dict)
                or entry["payload"].get("detection_id") != identity
                or len(json_text(entry["payload"]).encode()) > 1_000_000
            ):
                raise ValueError
            stamp = datetime.fromisoformat(entry["committed_at"].replace("Z", "+00:00"))
            if stamp.tzinfo is None or stamp.timestamp() > time.time() + 300:
                raise ValueError
            if entry["change_type"] == "detection.backfilled":
                if (
                    entry["schema_version"] not in {"1.1.0", "1.2.0"}
                    or page["schema_version"] not in {"1.1.0", "1.2.0"}
                    or type(entry.get("source_expires_at")) is not int
                    or entry["source_expires_at"] < 1
                    or type(entry.get("original_commit_time_known")) is not bool
                ):
                    raise ValueError
                if (
                    not isinstance(entry.get("backfill_job_id"), str)
                    or not 1 <= len(entry["backfill_job_id"]) <= 80
                ):
                    raise ValueError
                indexed_at = datetime.fromisoformat(
                    entry["indexed_committed_at"].replace("Z", "+00:00")
                )
                if indexed_at.tzinfo is None or indexed_at.timestamp() > time.time() + 300:
                    raise ValueError
            if "handling" in entry:
                if entry["schema_version"] != "1.2.0" or page["schema_version"] != "1.2.0":
                    raise ValueError
                validate_state(entry["handling"])
            if entry["change_type"] == "detection.handling_updated":
                if (
                    entry["revision"] != entry["handling"]["rev"]
                    or type(entry["source_expires_at"]) is not int
                    or entry["source_expires_at"] < 1
                ):
                    raise ValueError
                original = datetime.fromisoformat(
                    entry["indexed_committed_at"].replace("Z", "+00:00")
                )
                if original.tzinfo is None or original.timestamp() > stamp.timestamp():
                    raise ValueError
            identities.add(identity)
            sequence = entry["sequence"]
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
        raise FleetError("invalid_detection_feed_page", 502) from None


def collect_detections(store, message, agent_factory=Agent):
    if time.time() * 1000 - message["sequence"] > 1_800_000:
        return {"state": "expired", "records": 0}
    detections = Detections(store)
    claim = detections.claim(message)
    if not claim:
        return {"state": "skipped", "records": 0}
    item, token = claim
    previous = detections.checkpoint(item["agent_id"])
    # A gap requires explicit reconciliation; never replace its cursor with the head.
    approved = item.get("detection_reconciliation")
    reconciling = approved and approved["request_id"] != previous.get("reconciled_request_id")
    handoff = item.get("detection_handoff")
    handing_off = handoff and handoff["request_id"] != previous.get("handoff_request_id")
    if os.getenv("DETECTION_POLLING_ENABLED", "true") != "true" and not (
        handing_off or reconciling
    ):
        state = {**previous, "state": "gap" if previous.get("state") == "gap" else "paused"}
        detections.finish(item, token, message["sequence"], state)
        return {"state": state["state"], "records": 0}
    if previous.get("state") == "gap" and not (reconciling or handing_off):
        detections.finish(item, token, message["sequence"], previous)
        return {"state": "gap", "records": 0}
    records, pages, lag = 0, 0, 0
    deadline = time.monotonic() + 40
    agent = agent_factory(item, "", deadline=deadline)
    error = None
    receipts = previous.get("delivery_protocol") == "receipts-v1"
    try:
        if handing_off:
            from .detection_handoff import execute as handoff_execute

            if (
                reconciling
                or item["rev"] != handoff["expected_registration_rev"]
                or (
                    previous.get("generation") != handoff["expected_generation"]
                    and previous.get("handoff_pending_request") != handoff["request_id"]
                )
            ):
                raise FleetError("detection_handoff_checkpoint_conflict", 409)
            prior = previous
            previous = {**previous, "handoff_pending_request": handoff["request_id"]}
            previous = handoff_execute(detections, item, token, prior, agent)
            detections.finish(item, token, message["sequence"], previous)
            return {
                "state": previous["state"],
                "records": 0,
                "handoff_complete": True,
                "requests": agent.requests,
            }
        if reconciling:
            from .detection_reconciliation import execute

            # Do not turn an invalid generation into a retryable authorization
            # merely by persisting a pending marker after the rejection.
            if item["rev"] != approved["expected_registration_rev"] or (
                previous.get("generation") != approved["expected_generation"]
                and previous.get("reconciliation_pending_request") != approved["request_id"]
            ):
                raise FleetError("detection_reconciliation_checkpoint_conflict", 409)
            prior = previous
            previous = {**previous, "reconciliation_pending_request": approved["request_id"]}
            previous = execute(detections, item, token, prior, agent)
            receipts = True
            if approved.get("recovery") or os.getenv("DETECTION_POLLING_ENABLED", "true") != "true":
                detections.finish(item, token, message["sequence"], previous)
                return {
                    "state": previous["state"],
                    "records": 0,
                    "recovery_complete": bool(approved.get("recovery")),
                    "requests": agent.requests,
                }
        # Each feed page supplies a live identity and version check. Negotiate
        # the Core capability once per successful registration revision rather
        # than doubling every unchanged poll's API traffic with another status GET.
        if previous.get("verified_registration_rev") != item["rev"]:
            report = agent.verify()
            if report.get("capabilities", {}).get("detection_feed") not in {
                "1.0.0",
                "1.1.0",
                "1.2.0",
            }:
                raise FleetError("agent_detection_feed_unavailable", 409)
            available = report.get("capabilities", {}).get("detection_consumers") == "1.0.0"
            if receipts and not available:
                raise FleetError("agent_detection_consumers_unavailable", 409)
            receipts = available
        for _ in range(MAX_PAGES):
            if time.monotonic() > deadline - 8:
                break
            consumer_state = None
            if receipts:
                from .consumer_delivery import read_page

                page, consumer_state = read_page(agent, item, previous, PAGE_LIMIT)
            else:
                query = {"limit": str(PAGE_LIMIT)}
                if previous.get("cursor"):
                    query["cursor"] = previous["cursor"]
                code, page = agent.request("GET", "/detections/feed", query=query)
                if code == 410:
                    raise FleetError("detection_retention_gap", 409)
                if code != 200:
                    raise FleetError(f"detection_feed_http_{code}", 502)
            validate_page(page, item, previous)
            previous = detections.persist(item, token, previous, page, consumer_state)
            pages += 1
            records += len(page["items"])
            for entry in page["items"]:
                stamp = datetime.fromisoformat(entry["committed_at"].replace("Z", "+00:00"))
                lag = max(lag, max(0, time.time() - stamp.timestamp()))
            if not page["has_more"]:
                break
    except FleetError as failure:
        error = failure
    detections.finish(item, token, message["sequence"], previous, error)
    return {
        "state": "failed" if error else previous.get("state", "pending"),
        "records": records,
        "pages": pages,
        "delivery_lag_seconds": lag,
        "has_more": bool(previous.get("has_more")),
        "requests": agent.requests,
        "error_code": error.code if error else None,
    }
