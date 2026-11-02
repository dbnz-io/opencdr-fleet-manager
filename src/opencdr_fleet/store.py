"""DynamoDB registry, fenced polling leases and complete, chunked snapshots."""

from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from collections import Counter
from decimal import Decimal

import boto3
from boto3.dynamodb.conditions import Key
from boto3.dynamodb.types import TypeSerializer
from botocore.config import Config
from botocore.exceptions import ClientError

from .models import (
    FleetError,
    cursor_decode,
    cursor_encode,
    json_text,
    now_iso,
    public_registration,
)

CONFIG = Config(connect_timeout=2, read_timeout=4, retries={"max_attempts": 2, "mode": "standard"})


def wire(value):
    safe = json.loads(json_text(value), parse_float=Decimal)
    serializer = TypeSerializer()
    return {key: serializer.serialize(item) for key, item in safe.items()}


def conditional(error: ClientError) -> bool:
    return error.response["Error"]["Code"] == "ConditionalCheckFailedException" or (
        error.response["Error"]["Code"] == "TransactionCanceledException"
        and any(
            item.get("Code") == "ConditionalCheckFailed"
            for item in error.response.get("CancellationReasons", [])
        )
    )


class Store:
    def __init__(self, session=None):
        session = session or boto3.Session()
        self.ddb = session.resource("dynamodb", config=CONFIG)
        self.client = session.client("dynamodb", config=CONFIG)
        self.registry = self.ddb.Table(os.environ["REGISTRY_TABLE"])
        self.status = self.ddb.Table(os.environ["STATUS_TABLE"])
        self.cache = self.ddb.Table(os.environ["CACHE_TABLE"])
        self.ssm = session.client("ssm", config=CONFIG)
        self.sqs = session.client("sqs", config=CONFIG)
        self.prefix = os.environ["CREDENTIAL_PREFIX"].rstrip("/")

    def get_agent(self, name: str) -> dict:
        item = self.registry.get_item(Key={"id": "AGENT#" + name}, ConsistentRead=True).get("Item")
        if not item:
            raise FleetError("agent_not_found", 404)
        return item

    def agents(self, limit=50, cursor=None) -> tuple[list[dict], str | None]:
        args = {
            "IndexName": "agents",
            "KeyConditionExpression": Key("record_type").eq("AGENT"),
            "Limit": limit,
        }
        key = cursor_decode(cursor)
        if key:
            if (
                set(key) != {"record_type", "agent_id", "id"}
                or key["record_type"] != "AGENT"
                or key["id"] != "AGENT#" + str(key["agent_id"])
            ):
                raise FleetError("invalid_cursor")
            args["ExclusiveStartKey"] = key
        result = self.registry.query(**args)
        next_key = result.get("LastEvaluatedKey")
        return result.get("Items", []), cursor_encode(next_key) if next_key else None

    def save_agent(self, value: dict, *, create: bool) -> dict:
        expected = value.pop("expected_rev", None)
        name = value["agent_id"]
        stamp = now_iso()
        item = {**value, "id": "AGENT#" + name, "record_type": "AGENT", "updated_at": stamp}
        if create:
            if expected is not None:
                raise FleetError("expected_rev_not_supported_for_create")
            item.update(rev=1, created_at=stamp)
            identity = f"IDENTITY#{value['account_id']}#{value['region']}#{value['stage']}"
            try:
                self.client.transact_write_items(
                    TransactItems=[
                        {
                            "Put": {
                                "TableName": self.registry.name,
                                "Item": wire(item),
                                "ConditionExpression": "attribute_not_exists(id)",
                            }
                        },
                        {
                            "Put": {
                                "TableName": self.registry.name,
                                "Item": wire({"id": identity, "agent_id": name}),
                                "ConditionExpression": "attribute_not_exists(id)",
                            }
                        },
                    ]
                )
            except ClientError as error:
                if conditional(error):
                    raise FleetError("agent_or_identity_already_registered", 409) from None
                raise
        else:
            current = self.get_agent(name)
            if expected is None or expected != int(current["rev"]):
                raise FleetError("registration_revision_conflict", 409)
            if any(current[field] != value[field] for field in ("account_id", "region", "stage")):
                raise FleetError("deployment_identity_is_immutable", 409)
            item.update(rev=expected + 1, created_at=current["created_at"])
            try:
                # Replacing the registration also invalidates any in-flight poll's fence.
                self.registry.put_item(
                    Item=item,
                    ConditionExpression="rev = :rev",
                    ExpressionAttributeValues={":rev": expected},
                )
            except ClientError as error:
                if conditional(error):
                    raise FleetError("registration_revision_conflict", 409) from None
                raise
        return item

    def credentials(self, registration: dict, *, write=False) -> tuple[str, str | None]:
        base = f"{self.prefix}/{registration['agent_id']}"

        def read(kind):
            try:
                result = self.ssm.get_parameter(Name=f"{base}/{kind}-key", WithDecryption=True)
                key = result["Parameter"]["Value"]
                if result["Parameter"]["Type"] != "SecureString" or not key:
                    raise FleetError("invalid_agent_credential", 502)
                return key
            except ClientError:
                raise FleetError("agent_credential_unavailable", 502) from None

        if write and not registration["allow_writes"]:
            raise FleetError("agent_writes_disabled", 403)
        return read("read"), read("write") if write else None

    def enqueue(self, item: dict, sequence: int | None = None):
        self.sqs.send_message(
            QueueUrl=os.environ["POLL_QUEUE_URL"],
            MessageBody=json_text(
                {
                    "agent_id": item["agent_id"],
                    "rev": int(item["rev"]),
                    "sequence": sequence if sequence is not None else time.time_ns() // 1_000_000,
                }
            ),
        )

    def enqueue_many(self, items: list[dict], sequence: int):
        for offset in range(0, len(items), 10):
            result = self.sqs.send_message_batch(
                QueueUrl=os.environ["POLL_QUEUE_URL"],
                Entries=[
                    {
                        "Id": str(index),
                        "MessageBody": json_text(
                            {
                                "agent_id": item["agent_id"],
                                "rev": int(item["rev"]),
                                "sequence": sequence,
                            }
                        ),
                    }
                    for index, item in enumerate(items[offset : offset + 10])
                ],
            )
            if result.get("Failed"):
                raise FleetError("poll_dispatch_failed", 503)

    def claim(self, name: str, rev: int, sequence: int) -> tuple[dict, str] | None:
        token = uuid.uuid4().hex
        try:
            result = self.registry.update_item(
                Key={"id": "AGENT#" + name},
                ConditionExpression=(
                    "rev = :rev AND enabled = :yes AND "
                    "(attribute_not_exists(lease_until) OR lease_until < :now) AND "
                    "(attribute_not_exists(completed_sequence) OR completed_sequence < :sequence)"
                ),
                UpdateExpression="SET poll_token = :token, lease_until = :until",
                ExpressionAttributeValues={
                    ":rev": rev,
                    ":yes": True,
                    ":now": int(time.time()),
                    ":sequence": sequence,
                    ":token": token,
                    ":until": int(time.time()) + 90,
                },
                ReturnValues="ALL_NEW",
            )
            return result["Attributes"], token
        except ClientError as error:
            if conditional(error):
                return None
            raise

    def finish(self, item: dict, token: str, sequence: int, status: dict):
        try:
            self.client.transact_write_items(
                TransactItems=[
                    {
                        "Update": {
                            "TableName": self.registry.name,
                            "Key": wire({"id": item["id"]}),
                            "ConditionExpression": "rev = :rev AND poll_token = :token",
                            "UpdateExpression": (
                                "SET completed_sequence = :sequence REMOVE lease_until, poll_token"
                            ),
                            "ExpressionAttributeValues": wire(
                                {":rev": item["rev"], ":token": token, ":sequence": sequence}
                            ),
                        }
                    },
                    {"Put": {"TableName": self.status.name, "Item": wire(status)}},
                ]
            )
            return True
        except ClientError as error:
            if conditional(error):
                return False  # registration or lease changed; never publish stale data
            raise

    def get_status(self, name: str) -> dict:
        return self.status.get_item(Key={"agent_id": name}, ConsistentRead=True).get("Item", {})

    def view_status(self, item: dict) -> dict:
        state = self.get_status(item["agent_id"])
        now = int(time.time() * 1000)
        threshold = int(os.environ.get("STALE_AFTER_SECONDS", "180")) * 1000
        same_revision = state.get("registration_rev") == item["rev"]
        return {
            "agent": public_registration(item),
            "observation": state or None,
            "status_stale": not same_revision
            or not item["enabled"]
            or state.get("health") in {"unreachable", "identity_mismatch", "incompatible"}
            or now - int(state.get("status_success_ms", 0)) > threshold,
            "configuration_stale": not same_revision
            or not item["enabled"]
            or state.get("configuration_state") != "ready"
            or now - int(state.get("configuration_success_ms", 0)) > threshold,
        }

    def manifest(self, name: str, generation: str) -> dict:
        if (
            not isinstance(generation, str)
            or len(generation) != 32
            or any(c not in "0123456789abcdef" for c in generation)
        ):
            raise FleetError("invalid_snapshot_generation")
        result = self.cache.get_item(
            Key={"pk": name + "#" + generation, "sk": "MANIFEST"}, ConsistentRead=True
        ).get("Item")
        if not result or int(result["expires_at"]) <= int(time.time()):
            raise FleetError("snapshot_expired_or_missing", 410)
        return result

    def snapshot(self, name: str, documents: dict[str, dict], previous: str | None) -> str:
        encoded = {key: json_text(value) for key, value in documents.items()}
        total = sum(len(value) for value in encoded.values())
        if total > 20_000_000 or len(documents) > 5000:
            raise FleetError("snapshot_capacity_exceeded", 502)
        digest = hashlib.sha256(json_text(encoded).encode()).hexdigest()
        if previous:
            try:
                manifest = self.manifest(name, previous)
                if (
                    manifest["digest"] == digest
                    and int(manifest["expires_at"]) > time.time() + 3600
                ):
                    return previous
            except FleetError as error:
                if error.status != 410:
                    raise
        generation = uuid.uuid4().hex
        pk = name + "#" + generation
        expiry = int(time.time()) + int(os.environ.get("SNAPSHOT_RETENTION_HOURS", "24")) * 3600
        with self.cache.batch_writer() as batch:
            for key, payload in encoded.items():
                chunks = [payload[i : i + 240_000] for i in range(0, len(payload), 240_000)]
                batch.put_item(
                    Item={
                        "pk": pk,
                        "sk": "META#" + key,
                        "resource_key": key,
                        "parts": len(chunks),
                        "sha256": hashlib.sha256(payload.encode()).hexdigest(),
                        "expires_at": expiry,
                    }
                )
                for index, chunk in enumerate(chunks):
                    batch.put_item(
                        Item={
                            "pk": pk,
                            "sk": f"DATA#{key}#{index:04d}",
                            "payload": chunk,
                            "expires_at": expiry,
                        }
                    )
        self.cache.put_item(
            Item={
                "pk": pk,
                "sk": "MANIFEST",
                "generation": generation,
                "digest": digest,
                "resource_count": len(documents),
                "document_bytes": total,
                "counts": dict(Counter(key.split(":")[0] for key in documents)),
                "captured_at": now_iso(),
                "expires_at": expiry,
            }
        )
        return generation

    def configuration(self, name: str, limit: int, cursor=None, kind=None) -> dict:
        if kind is not None and kind not in (
            "rule",
            "list",
            "setting",
            "ir_role",
            "integration",
            "catalog",
        ):
            raise FleetError("invalid_configuration_kind")
        state = self.get_status(name)
        decoded = cursor_decode(cursor)
        generation = decoded.get("generation") if decoded else state.get("snapshot_generation")
        if not generation:
            raise FleetError("configuration_not_yet_cached", 404)
        manifest = self.manifest(name, generation)
        pk, prefix = name + "#" + generation, "META#" + (kind + ":" if kind else "")
        args = {
            "KeyConditionExpression": Key("pk").eq(pk) & Key("sk").begins_with(prefix),
            "Limit": limit,
            "ConsistentRead": True,
        }
        if decoded:
            if (
                set(decoded) != {"generation", "last_sk", "kind", "agent_id"}
                or decoded["agent_id"] != name
                or decoded["kind"] != kind
                or not isinstance(decoded["last_sk"], str)
                or not decoded["last_sk"].startswith(prefix)
            ):
                raise FleetError("invalid_cursor")
            args["ExclusiveStartKey"] = {"pk": pk, "sk": decoded["last_sk"]}
        page = self.cache.query(**args)
        results, total, last = [], 0, None
        for meta in page.get("Items", []):
            pieces = []
            for part in range(int(meta["parts"])):
                chunk = self.cache.get_item(
                    Key={"pk": pk, "sk": f"DATA#{meta['resource_key']}#{part:04d}"},
                    ConsistentRead=True,
                ).get("Item")
                if not chunk:
                    raise FleetError("snapshot_incomplete", 502)
                pieces.append(chunk["payload"])
            payload = "".join(pieces)
            if hashlib.sha256(payload.encode()).hexdigest() != meta["sha256"]:
                raise FleetError("snapshot_checksum_mismatch", 502)
            if results and total + len(payload) > 3_000_000:
                break
            results.append({"resource_key": meta["resource_key"], "document": json.loads(payload)})
            total += len(payload)
            last = meta["sk"]
        more = len(results) < len(page.get("Items", [])) or bool(page.get("LastEvaluatedKey"))
        token = (
            cursor_encode(
                {"generation": generation, "last_sk": last, "kind": kind, "agent_id": name}
            )
            if more and last
            else None
        )
        return {
            "agent_id": name,
            "generation": generation,
            "is_current": generation == state.get("snapshot_generation"),
            "manifest": {k: v for k, v in manifest.items() if k not in ("pk", "sk")},
            "verified_at": state.get("configuration_verified_at")
            if generation == state.get("snapshot_generation")
            else None,
            "items": results,
            "next_token": token,
        }
