"""One shared case store for standalone Core and organization-local Fleet.

Case state, active detection locks, append-only audit and retry receipts share a
transaction. Evidence is content-addressed in a separate retained S3 bucket.
"""

import base64
import hashlib
import json
import time
from datetime import UTC, datetime
from decimal import Decimal

from boto3.dynamodb.types import TypeDeserializer, TypeSerializer
from botocore.exceptions import ClientError

from .case_contract import MAX_ATTACHMENTS, CaseError, agents, changes, identifier, request, text
from .detection_query import canonical


def wire(value):
    value = json.loads(canonical(value), parse_float=Decimal)
    return {k: TypeSerializer().serialize(v) for k, v in value.items()}


def decode(value):
    return {k: TypeDeserializer().deserialize(v) for k, v in value.items()}


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def stamp():
    return datetime.now(UTC).isoformat()


def public(row):
    result = {k: v for k, v in row.items() if k not in {"pk", "sk", "evidence_key"}}
    if "attachments" in result:
        result["attachments"] = [public(a) for a in result["attachments"]]
    return result


class Cases:
    def __init__(
        self,
        client,
        table,
        s3,
        bucket,
        actor,
        allowed,
        resolver,
        grant_rev=None,
        integration_fence=None,
        routing_owner=None,
    ):
        self.client, self.table, self.s3, self.bucket = client, table, s3, bucket
        self.actor, self.allowed, self.resolver = actor, frozenset(allowed), resolver
        self.grant_rev = grant_rev
        self.integration_fence = integration_fence
        self.routing_owner = routing_owner

    def view(self, row):
        from .case_integrations import visible_statuses

        return {**public(row), "external_status": visible_statuses(self, row)}

    def active(self, query):
        if set(query) != {"agent_id", "detection_id", "agent_ids"}:
            raise CaseError("invalid_case_query")
        selected = set(agents(query["agent_ids"].split(",")))
        name, identity = text(query["agent_id"], 128), text(query["detection_id"], 512)
        if not selected <= self.allowed or name not in selected:
            raise CaseError("case_scope_forbidden", 403)
        attachment_id = digest({"agent_id": name, "detection_id": identity})
        lock = self.get("LINK#" + attachment_id, "ACTIVE")
        if not lock:
            raise CaseError("case_not_found", 404)
        row = self.case(lock["case_id"])
        if (
            not set(row["agent_ids"]) <= selected
            or row["status"] == "closed"
            or not any(
                a["attachment_id"] == attachment_id and a["attached"] for a in row["attachments"]
            )
        ):
            raise CaseError("case_not_found", 404)
        return {"case": self.view(row)}

    def check_access(self):
        from .delegation import CURRENT

        if CURRENT.get():
            CURRENT.get().fresh()
        if self.integration_fence:
            name, revision = self.integration_fence
            current = self.get("INTEGRATION", name)
            if (
                not current
                or current["rev"] != revision
                or not current["enabled"]
                or current["principal"] != self.actor
            ):
                raise CaseError("case_connector_access_changed", 403)
        if self.grant_rev is not None:
            current = self.get("ACCESS", self.actor)
            if not current or current["rev"] != self.grant_rev:
                raise CaseError("case_access_changed", 403)

    def get(self, pk, sk):
        row = self.client.get_item(
            TableName=self.table, Key=wire({"pk": pk, "sk": sk}), ConsistentRead=True
        ).get("Item")
        return decode(row) if row else None

    def case(self, case_id):
        identifier(case_id)
        row = self.get("CASE", case_id)
        if not row or not set(row["agent_ids"]) <= self.allowed:
            raise CaseError("case_not_found", 404)
        return row

    def put(self, row, condition="attribute_not_exists(pk)", values=None):
        args = {"TableName": self.table, "Item": wire(row), "ConditionExpression": condition}
        if values:
            args["ExpressionAttributeValues"] = wire(values)
        return {"Put": args}

    def ownership_fences(self, operations, *, completing_claim=False):
        """Fence every owner table touched by an atomic case/Library mutation.

        Only the reviewed migration controller may write OWNERSHIP/STATE. A
        missing row is the pre-migration local owner. A controller must drain
        already-claimed workers before activating a different owner; this check
        alone cannot cancel an external request already in flight.
        """
        coordinates = {(self.table, "STATE")}
        for operation in operations:
            for kind, args in operation.items():
                if kind not in {"Put", "Update", "Delete", "ConditionCheck"}:
                    continue
                row = args.get("Item", args.get("Key", {}))
                if "pk" not in row or "sk" not in row:
                    continue
                pk = row["pk"].get("S", "")
                if pk == "OWNERSHIP":
                    raise CaseError("ownership_state_requires_migration_controller", 403)
                table = args["TableName"]
                coordinates.add((table, "STATE"))
                # Core keeps its execution journal and account-level review
                # authority when case/library authoring moves to Fleet.
                # Fence the affected family even when its row is only a
                # condition in a cross-table mutation (e.g. case tuning).
                if pk in {"CASE", "ACCESS", "INTEGRATION"} or pk.startswith(
                    ("LINK#", "EXTENSION#", "ROUTING")
                ):
                    coordinates.add((table, "cases"))
                if pk in {"ITEM", "RELEASE"} or pk.startswith(
                    ("IDENTITY#", "VERSION#", "TEST#", "COMPILE#", "MAPPING#")
                ):
                    coordinates.add((table, "library"))
        fences = []
        for table, family in sorted(coordinates):
            key = wire({"pk": "OWNERSHIP", "sk": family})
            item = self.client.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
            condition = {"TableName": table, "Key": key}
            if not item:
                condition["ConditionExpression"] = "attribute_not_exists(pk)"
            else:
                row = decode(item)
                allowed = (
                    {"active", "frozen"} if completing_claim and family == "STATE" else {"active"}
                )
                if (
                    row.get("schema") != "opencdr.ownership/1"
                    or row.get("state") not in allowed
                    or not isinstance(row.get("revision"), (int, Decimal))
                    or isinstance(row.get("revision"), bool)
                    or row["revision"] < 1
                    or row["revision"] != int(row["revision"])
                ):
                    raise CaseError("owner_migration_fenced", 409)
                condition.update(
                    ConditionExpression="#state = :active AND revision = :revision",
                    ExpressionAttributeNames={"#state": "state"},
                    ExpressionAttributeValues=wire(
                        {":active": row["state"], ":revision": row["revision"]}
                    ),
                )
            fences.append({"ConditionCheck": condition})
        return fences

    def complete_claim(self, operations, claim_key, attempt_id):
        """Record a claimed effect while frozen; never grant a new effect claim.

        Only worker outcome persistence calls this. Retirement still blocks it:
        a controller must drain/reconcile claims before transferring ownership.
        The permanent claim is checked atomically with every completion write.
        """
        if (
            set(claim_key) != {"pk", "sk"}
            or not claim_key["pk"].startswith("EFFECT#")
            or claim_key["sk"] != "CLAIM"
        ):
            raise CaseError("invalid_completion_claim")
        identifier(attempt_id)
        fence = {
            "ConditionCheck": {
                "TableName": self.table,
                "Key": wire(claim_key),
                "ConditionExpression": "attempt_id = :attempt",
                "ExpressionAttributeValues": wire({":attempt": attempt_id}),
            }
        }
        self._transact([*operations, fence], completing_claim=True)

    def transact(self, operations):
        self._transact(operations, completing_claim=False)

    def _transact(self, operations, *, completing_claim):
        from .delegation import transaction_fences

        actions = [
            *operations,
            *transaction_fences(),
            *self.ownership_fences(operations, completing_claim=completing_claim),
        ]
        if len(actions) > 100:
            raise CaseError("owner_transaction_limit", 413)
        try:
            self.client.transact_write_items(TransactItems=actions)
        except ClientError as error:
            if error.response["Error"]["Code"] == "TransactionCanceledException":
                raise CaseError("case_revision_or_active_link_conflict", 409) from None
            raise

    def receipt(self, case_id, operation, body):
        self.check_access()
        found = self.get("REQUEST#" + case_id, body["request_id"])
        if not found:
            return None
        if (
            found["digest"] != digest({"operation": operation, "body": body})
            or found["actor"] != self.actor
        ):
            raise CaseError("case_request_conflict", 409)
        return {"case": found["result"], "idempotent": True}

    def commit(self, previous, updated, operation, body, detail, extra=()):
        from .delegation import audit_identity

        if audit_identity():
            detail = {**detail, "identity": audit_identity()}
        case_id = updated["case_id"]
        updated = {
            **updated,
            "pk": "CASE",
            "sk": case_id,
            "rev": int(previous["rev"]) + 1 if previous else 1,
            "updated_at": stamp(),
            "updated_by": self.actor,
        }
        if len(canonical(updated).encode()) > 150_000:
            raise CaseError("case_record_limit", 413)
        event = {
            "pk": "AUDIT#" + case_id,
            "sk": f"{updated['rev']:012d}",
            "case_id": case_id,
            "rev": updated["rev"],
            "kind": operation,
            "actor": self.actor,
            "request_id": body["request_id"],
            "reason": body["reason"],
            "at": updated["updated_at"],
            "detail": detail,
        }
        receipt = {
            "pk": "REQUEST#" + case_id,
            "sk": body["request_id"],
            "actor": self.actor,
            "digest": digest({"operation": operation, "body": body}),
            "result": {"case_id": case_id, "rev": updated["rev"]}
            if operation == "external_status"
            else public(updated),
        }
        writes = [
            self.put(updated, "rev = :rev", {":rev": previous["rev"]})
            if previous
            else self.put(updated),
            self.put(event),
            self.put(receipt),
            *extra,
        ]
        if self.grant_rev is not None:
            writes.append(
                {
                    "ConditionCheck": {
                        "TableName": self.table,
                        "Key": wire({"pk": "ACCESS", "sk": self.actor}),
                        "ConditionExpression": "rev = :rev",
                        "ExpressionAttributeValues": wire({":rev": self.grant_rev}),
                    }
                }
            )
        if self.integration_fence:
            name, revision = self.integration_fence
            writes.append(
                {
                    "ConditionCheck": {
                        "TableName": self.table,
                        "Key": wire({"pk": "INTEGRATION", "sk": name}),
                        "ConditionExpression": "rev = :rev",
                        "ExpressionAttributeValues": wire({":rev": revision}),
                    }
                }
            )
        try:
            self.transact(writes)
        except CaseError:
            prior = self.receipt(case_id, operation, body)
            if prior:
                return prior
            raise
        return {"case": public(updated), "idempotent": False}

    def create(self, body):
        request(body, {"title", "description", "severity", "agent_ids"}, create=True)
        scope = agents(body["agent_ids"])
        if not set(scope) <= self.allowed:
            raise CaseError("case_scope_forbidden", 403)
        changes({k: body[k] for k in ("title", "description", "severity")})
        case_id = digest({"actor": self.actor, "request_id": body["request_id"]})[:32]
        prior = self.receipt(case_id, "created", body)
        if prior:
            return prior
        value = {
            "case_id": case_id,
            "schema_version": "1.0.0",
            "agent_ids": scope,
            **{k: body[k] for k in ("title", "description", "severity")},
            "status": "open",
            "assigned_to": None,
            "created_at": stamp(),
            "created_by": self.actor,
            "attachments": [],
        }
        return self.commit(
            None, value, "created", body, {"title": body["title"], "agent_ids": scope}
        )

    def prepare(self, case_id, operation, body, fields):
        request(body, fields)
        previous = self.case(case_id)  # Reauthorize before returning a retry receipt.
        prior = self.receipt(case_id, operation, body)
        if prior:
            return previous, prior
        if previous["rev"] != body["expected_rev"]:
            raise CaseError("case_revision_conflict", 409)
        return previous, None

    def lock(self, attachment, case_id, *, release=False):
        key = {"pk": "LINK#" + attachment["attachment_id"], "sk": "ACTIVE"}
        if release:
            return {
                "Delete": {
                    "TableName": self.table,
                    "Key": wire(key),
                    "ConditionExpression": "case_id = :case",
                    "ExpressionAttributeValues": wire({":case": case_id}),
                }
            }
        return self.put(
            {**key, "case_id": case_id},
            "attribute_not_exists(pk) OR case_id = :case",
            {":case": case_id},
        )

    def update(self, case_id, body):
        previous, prior = self.prepare(case_id, "updated", body, {"changes"})
        if prior:
            return prior
        patch = changes(body["changes"])
        if previous.get("merged_into") and patch.get("status", "closed") != "closed":
            raise CaseError("merged_case_cannot_reopen", 409)
        value = {**previous, **patch}
        extra = []
        if (previous["status"] == "closed") != (value["status"] == "closed"):
            extra = [
                self.lock(a, case_id, release=value["status"] == "closed")
                for a in previous["attachments"]
                if a["attached"]
            ]
        return self.commit(
            previous,
            value,
            "updated",
            body,
            {"before": {k: previous[k] for k in patch}, "after": patch},
            extra,
        )

    def note(self, case_id, body):
        previous, prior = self.prepare(case_id, "note", body, {"text"})
        if prior:
            return prior
        text(body["text"], 4000)
        return self.commit(previous, previous, "note", body, {"text": body["text"]})

    def attach(self, case_id, body):
        previous, prior = self.prepare(case_id, "attached", body, {"agent_id", "detection_id"})
        if prior:
            return prior
        name, identity = text(body["agent_id"], 128), text(body["detection_id"], 512)
        if name not in previous["agent_ids"]:
            raise CaseError("case_scope_forbidden", 403)
        if previous["status"] == "closed":
            raise CaseError("case_closed", 409)
        attachment_id = digest({"agent_id": name, "detection_id": identity})
        old = next(
            (a for a in previous["attachments"] if a["attachment_id"] == attachment_id), None
        )
        if old and old["attached"]:
            raise CaseError("detection_already_attached", 409)
        if old:
            self.evidence(case_id, attachment_id)  # Verify retained bytes before reattachment.
            attachment = {**old, "attached": True, "attached_at": stamp()}
        else:
            if len(previous["attachments"]) >= MAX_ATTACHMENTS:
                raise CaseError("case_attachment_limit", 409)
            resolved = self.resolver(name, identity)
            item, evidence = resolved["item"], resolved["evidence"]
            if (
                item["agent_id"] != name
                or item["detection_id"] != identity
                or evidence.get("detection_id") != identity
            ):
                raise CaseError("case_evidence_identity_mismatch", 502)
            raw = canonical(evidence).encode()
            if len(raw) > 1_000_000:
                raise CaseError("case_evidence_too_large", 413)
            sha = hashlib.sha256(raw).hexdigest()
            key = "cases/" + case_id + "/" + attachment_id + "/" + sha + ".json"
            try:
                self.s3.put_object(
                    Bucket=self.bucket,
                    Key=key,
                    Body=raw,
                    ContentType="application/json",
                    ServerSideEncryption="AES256",
                    IfNoneMatch="*",
                )
            except ClientError as error:
                if error.response["Error"]["Code"] != "PreconditionFailed":
                    raise
                self.read_blob(key, sha)
            attachment = {
                "attachment_id": attachment_id,
                "agent_id": name,
                "detection_id": identity,
                "account_id": item["account_id"],
                "region": item["region"],
                "stage": item["stage"],
                "kind": item["kind"],
                "severity": str(item["summary"].get("severity", "UNKNOWN"))[:32],
                "rule_id": str(item["summary"].get("rule_id", ""))[:128],
                "evidence_sha256": sha,
                "evidence_key": key,
                "captured_at": stamp(),
                "attached_at": stamp(),
                "attached": True,
            }
        attachments = [
            a for a in previous["attachments"] if a["attachment_id"] != attachment_id
        ] + [attachment]
        return self.commit(
            previous,
            {**previous, "attachments": attachments},
            "attached",
            body,
            {
                k: attachment[k]
                for k in ("attachment_id", "agent_id", "detection_id", "evidence_sha256")
            },
            [self.lock(attachment, case_id)],
        )

    def detach(self, case_id, body):
        previous, prior = self.prepare(case_id, "detached", body, {"attachment_id"})
        if prior:
            return prior
        attachment = next(
            (
                a
                for a in previous["attachments"]
                if a["attachment_id"] == body["attachment_id"] and a["attached"]
            ),
            None,
        )
        if not attachment:
            raise CaseError("case_attachment_not_found", 404)
        attachments = [
            {**a, "attached": False, "detached_at": stamp()}
            if a["attachment_id"] == body["attachment_id"]
            else a
            for a in previous["attachments"]
        ]
        extra = (
            [self.lock(attachment, case_id, release=True)] if previous["status"] != "closed" else []
        )
        return self.commit(
            previous,
            {**previous, "attachments": attachments},
            "detached",
            body,
            {"attachment_id": body["attachment_id"]},
            extra,
        )

    def read_blob(self, key, sha):
        try:
            stream = self.s3.get_object(Bucket=self.bucket, Key=key)["Body"]
            try:
                raw = stream.read(1_000_001)
            finally:
                stream.close()
        except ClientError as error:
            if error.response["Error"]["Code"] in {"NoSuchKey", "NoSuchBucket"}:
                raise CaseError("case_evidence_unavailable", 410) from None
            raise
        if len(raw) > 1_000_000 or hashlib.sha256(raw).hexdigest() != sha:
            raise CaseError("case_evidence_integrity_failure", 502)
        return json.loads(raw)

    def evidence(self, case_id, attachment_id):
        case = self.case(case_id)
        attachment = next(
            (a for a in case["attachments"] if a["attachment_id"] == attachment_id), None
        )
        if not attachment:
            raise CaseError("case_attachment_not_found", 404)
        return {
            "case_id": case_id,
            "attachment": public(attachment),
            "evidence": self.read_blob(attachment["evidence_key"], attachment["evidence_sha256"]),
        }

    def history(self, case_id, query):
        self.case(case_id)
        if set(query) - {"after", "limit"}:
            raise CaseError("invalid_case_query")
        limit, after = int(query.get("limit", 20)), int(query.get("after", 0))
        if not 1 <= limit <= 50 or after < 0:
            raise CaseError("invalid_case_query")
        result = self.client.query(
            TableName=self.table,
            ConsistentRead=True,
            KeyConditionExpression="pk = :pk AND sk > :after",
            ExpressionAttributeValues=wire({":pk": "AUDIT#" + case_id, ":after": f"{after:012d}"}),
            Limit=limit,
        )
        rows = [decode(r) for r in result.get("Items", [])]
        return {
            "case_id": case_id,
            "items": [public(r) for r in rows],
            "next_after": str(rows[-1]["rev"]) if result.get("LastEvaluatedKey") else None,
        }

    def listing(self, query):
        if set(query) - {"limit", "cursor", "agent_ids", "status"}:
            raise CaseError("invalid_case_query")
        selected = (
            set(agents(query["agent_ids"].split(",")))
            if query.get("agent_ids")
            else set(self.allowed)
        )
        if not selected <= self.allowed:
            raise CaseError("case_scope_forbidden", 403)
        status = query.get("status")
        if status:
            changes({"status": status})
        limit = int(query.get("limit", 20))
        if not 1 <= limit <= 50:
            raise CaseError("invalid_case_query")
        binding = digest(
            {
                "actor": self.actor,
                "allowed": sorted(self.allowed),
                "selected": sorted(selected),
                "status": status,
                "limit": limit,
            }
        )
        after = ""
        if query.get("cursor"):
            try:
                if len(query["cursor"]) > 1024:
                    raise ValueError
                cursor = json.loads(
                    base64.urlsafe_b64decode(query["cursor"] + "=" * (-len(query["cursor"]) % 4))
                )
                if cursor["scope"] != binding or cursor["expires"] < time.time():
                    raise ValueError
                after = identifier(cursor["after"])
            except (ValueError, KeyError, TypeError):
                raise CaseError("invalid_case_cursor") from None
        result = self.client.query(
            TableName=self.table,
            ConsistentRead=True,
            KeyConditionExpression="pk = :pk" + (" AND sk > :after" if after else ""),
            ExpressionAttributeValues=wire({":pk": "CASE", **({":after": after} if after else {})}),
            Limit=limit,
        )
        rows = [decode(r) for r in result.get("Items", [])]
        visible = [
            r
            for r in rows
            if set(r["agent_ids"]) <= selected and (not status or r["status"] == status)
        ]
        token = None
        if result.get("LastEvaluatedKey"):
            token = (
                base64.urlsafe_b64encode(
                    canonical(
                        {
                            "scope": binding,
                            "expires": int(time.time()) + 3600,
                            "after": rows[-1]["case_id"],
                        }
                    ).encode()
                )
                .decode()
                .rstrip("=")
            )
        # These are page counts, never totals for a partial or cross-account result set.
        return {
            "items": [
                {
                    k: v
                    for k, v in public(r).items()
                    if k not in {"attachments", "description", "external_status"}
                }
                | {"attachment_count": sum(a["attached"] for a in r["attachments"])}
                for r in visible
            ],
            "page_count": len(visible),
            "has_more": bool(token),
            "next_cursor": token,
            "scope_policy": "all_case_accounts_required",
        }
