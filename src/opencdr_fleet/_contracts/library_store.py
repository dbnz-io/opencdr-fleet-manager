"""Immutable authoring versions/artifacts, optimistic heads and retained receipts."""

import json

from botocore.exceptions import ClientError

from .case_contract import CaseError, identifier, text
from .case_store import Cases, decode, digest, stamp, wire
from .detection_query import canonical
from .library_contract import (
    KINDS,
    MAX_RELEASE_ITEMS,
    VERSION,
    LibraryError,
    command,
    document,
    provenance,
    references,
    runtime_id,
)
from .library_quality import LibraryQuality


def view(row):
    return {key: value for key, value in row.items() if key not in {"pk", "sk", "artifact_key"}}


class Library(LibraryQuality, Cases):
    def __init__(self, client, table, s3, bucket, actor, *, evaluator=None, runtime_reader=None):
        super().__init__(client, table, s3, bucket, actor, [], None)
        self.evaluator = evaluator
        self.runtime_reader = runtime_reader

    def required(self, pk, sk):
        row = self.get(pk, sk)
        if not row:
            raise LibraryError("library_not_found", 404)
        return row

    def receipt(self, operation, body):
        row = self.get("REQUEST#" + digest(self.actor), body["request_id"])
        if not row:
            return None
        if row["digest"] != digest({"operation": operation, "body": body}):
            raise LibraryError("library_request_conflict", 409)
        return {**row["result"], "idempotent": True}

    def commit(self, operation, body, result, writes):
        receipt = {
            "pk": "REQUEST#" + digest(self.actor),
            "sk": body["request_id"],
            "digest": digest({"operation": operation, "body": body}),
            "result": result,
        }
        try:
            self.transact([*writes, self.put(receipt)])
        except CaseError:
            prior = self.receipt(operation, body)
            if prior:
                return prior
            raise LibraryError("library_revision_or_identity_conflict", 409) from None
        return {**result, "idempotent": False}

    def event(self, content_id, rev, kind, body, detail):
        from .delegation import audit_identity

        if audit_identity():
            detail = {**detail, "identity": audit_identity()}
        return self.put(
            {
                "pk": "AUDIT#" + content_id,
                "sk": f"{rev:016d}",
                "content_id": content_id,
                "rev": rev,
                "kind": kind,
                "actor": self.actor,
                "at": stamp(),
                "reason": body["reason"],
                "request_id": body["request_id"],
                "detail": detail,
            }
        )

    def create(self, body):
        command(body, {"kind", "runtime_id", "title", "description"})
        if not isinstance(body["kind"], str) or body["kind"] not in KINDS:
            raise LibraryError("invalid_library_kind")
        runtime_id(body["runtime_id"])
        text(body["title"], 200)
        text(body["description"], 2000, empty=True)
        prior = self.receipt("create", body)
        if prior:
            return prior
        content_id = digest({"actor": self.actor, "request_id": body["request_id"]})[:32]
        now = stamp()
        row = {
            "pk": "ITEM",
            "sk": content_id,
            "content_id": content_id,
            "schema_version": VERSION,
            **{k: body[k] for k in ("kind", "runtime_id", "title", "description")},
            "archived": False,
            "rev": 1,
            "latest_version": 0,
            "created_at": now,
            "created_by": self.actor,
            "updated_at": now,
            "updated_by": self.actor,
        }
        return self.commit(
            "create",
            body,
            {"item": view(row)},
            [
                self.put(row),
                self.put(
                    {
                        "pk": "IDENTITY#" + body["kind"],
                        "sk": body["runtime_id"],
                        "content_id": content_id,
                    }
                ),
                self.event(
                    content_id,
                    1,
                    "created",
                    body,
                    {"kind": body["kind"], "runtime_id": body["runtime_id"]},
                ),
            ],
        )

    def item(self, content_id):
        return self.required("ITEM", identifier(content_id))

    def update(self, content_id, body):
        command(body, {"title", "description", "archived"}, revision=True)
        text(body["title"], 200)
        text(body["description"], 2000, empty=True)
        if type(body["archived"]) is not bool:
            raise LibraryError("invalid_library_archived")
        operation = "update:" + identifier(content_id)
        prior = self.receipt(operation, body)
        if prior:
            return prior
        previous = self.item(content_id)
        if previous["rev"] != body["expected_rev"]:
            raise LibraryError("library_revision_conflict", 409)
        row = {
            **previous,
            **{k: body[k] for k in ("title", "description", "archived")},
            "rev": int(previous["rev"]) + 1,
            "updated_at": stamp(),
            "updated_by": self.actor,
        }
        return self.commit(
            operation,
            body,
            {"item": view(row)},
            [
                self.put(row, "rev = :rev", {":rev": previous["rev"]}),
                self.event(
                    content_id,
                    row["rev"],
                    "metadata",
                    body,
                    {k: body[k] for k in ("title", "description", "archived")},
                ),
            ],
        )

    def version(self, content_id, number):
        identifier(content_id)
        if type(number) is not int or not 1 <= number <= 9007199254740991:
            raise LibraryError("invalid_library_version")
        return self.required("VERSION#" + content_id, f"{number:016d}")

    def check_reference(self, ref):
        row = self.version(ref["content_id"], int(ref["version"]))
        if row["artifact_sha256"] != ref["artifact_sha256"]:
            raise LibraryError("library_reference_digest_mismatch", 409)
        return row

    def artifact(self, row):
        try:
            response = self.s3.get_object(Bucket=self.bucket, Key=row["artifact_key"])
            try:
                raw = response["Body"].read(131073)
            finally:
                response["Body"].close()
        except ClientError as error:
            if error.response["Error"]["Code"] in {"NoSuchKey", "404"}:
                raise LibraryError("library_artifact_unavailable", 410) from None
            raise
        if len(raw) > 131072:
            raise LibraryError("library_artifact_integrity_failure", 502)
        try:
            body = json.loads(raw)
        except (ValueError, UnicodeError):
            raise LibraryError("library_artifact_integrity_failure", 502) from None
        if digest(body) != row["artifact_sha256"]:
            raise LibraryError("library_artifact_integrity_failure", 502)
        return body

    def put_artifact(self, key, body):
        try:
            self.s3.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=canonical(body).encode(),
                ContentType="application/json",
                IfNoneMatch="*",
            )
        except ClientError as error:
            if error.response["Error"]["Code"] not in {"PreconditionFailed", "412"}:
                raise
            # An existing object must match; a retry never overwrites it.
            self.artifact({"artifact_key": key, "artifact_sha256": digest(body)})

    def import_version(self, content_id, body):
        from .library_imports import fetch_git

        command(body, {"dependencies", "provenance"}, revision=True)
        operation = "import:" + identifier(content_id)
        prior = self.receipt(operation, body)
        if prior:
            return prior
        head = self.item(content_id)
        if head["rev"] != body["expected_rev"]:
            raise LibraryError("library_revision_conflict", 409)
        origin = provenance(body["provenance"])
        if origin["kind"] != "git-import":
            raise LibraryError("library_verified_import_requires_github")
        payload = fetch_git(body["provenance"])
        origin = {**origin, "verification": "verified_git", "verified_at": stamp()}
        return self.save_version(
            content_id, {**body, "document": payload}, _verified=origin, _request=body
        )

    def import_runtime_version(self, content_id, body):
        command(
            body,
            {"dependencies", "source_deployment", "source_revision", "source_sha256"},
            revision=True,
        )
        operation = "runtime-import:" + identifier(content_id)
        prior = self.receipt(operation, body)
        if prior:
            return prior
        head = self.item(content_id)
        if head["rev"] != body["expected_rev"]:
            raise LibraryError("library_revision_conflict", 409)
        text(body["source_deployment"], 256)
        text(body["source_revision"], 128)
        if self.runtime_reader is None:
            raise LibraryError("library_runtime_import_unavailable", 503)
        source = self.runtime_reader(head, body["source_deployment"], body["source_revision"])
        if digest(source["document"]) != body["source_sha256"]:
            raise LibraryError("library_runtime_source_changed", 409)
        # Keep the unmodified observation with its hash; strip only documented
        # top-level runtime bookkeeping from the new authored document.
        metadata = {
            "rev",
            "expected_rev",
            "rule_version",
            "release_id",
            "release_version",
            "content_fingerprint",
            "timestamp",
            "created_by",
            "updated_by",
            "catalog_generation",
        }
        payload = {k: v for k, v in source["document"].items() if k not in metadata}
        origin = {
            "kind": "runtime-import",
            "source_deployment": body["source_deployment"],
            "observed_at": source["observed_at"],
            "verification": "verified_snapshot",
            "source_revision": body["source_revision"],
            "source_sha256": body["source_sha256"],
            "verified_at": stamp(),
        }
        request = {
            "request_id": body["request_id"],
            "reason": body["reason"],
            "expected_rev": body["expected_rev"],
            "dependencies": body["dependencies"],
            "document": payload,
            "provenance": {"kind": "authored"},
        }
        return self.save_version(
            content_id,
            request,
            _verified=origin,
            _request=body,
            _operation=operation,
            _source=source["document"],
        )

    def save_version(
        self, content_id, body, *, _verified=None, _request=None, _operation=None, _source=None
    ):
        command(body, {"document", "dependencies", "provenance"}, revision=True)
        operation = _operation or ("import:" if _verified else "version:") + identifier(content_id)
        request = body if _request is None else _request
        prior = self.receipt(operation, request)
        if prior:
            return prior
        head = self.item(content_id)
        if head["rev"] != body["expected_rev"]:
            raise LibraryError("library_revision_conflict", 409)
        if head["archived"]:
            raise LibraryError("library_item_archived", 409)
        payload = document(body["document"], head)
        deps = references(body["dependencies"])
        origin = _verified if _verified is not None else provenance(body["provenance"])
        for ref in deps:
            self.check_reference(ref)
        number = int(head["latest_version"]) + 1
        artifact = {
            "schema_version": VERSION,
            "content_id": content_id,
            "version": number,
            "kind": head["kind"],
            "runtime_id": head["runtime_id"],
            "document": payload,
            "dependencies": deps,
            "provenance": origin,
        }
        if _source is not None:
            artifact["source_document"] = _source
        if len(canonical(artifact).encode()) > 131072:
            raise LibraryError("library_artifact_too_large", 413)
        fingerprint = digest(artifact)
        key = f"library/versions/{content_id}/{number:016d}/{fingerprint}.json"
        row = {
            "pk": "VERSION#" + content_id,
            "sk": f"{number:016d}",
            "schema_version": VERSION,
            "content_id": content_id,
            "version": number,
            "kind": head["kind"],
            "runtime_id": head["runtime_id"],
            "document_sha256": digest(payload),
            "artifact_sha256": fingerprint,
            "artifact_key": key,
            "dependencies": deps,
            "provenance": origin,
            "validation_state": "not_run",
            "created_at": stamp(),
            "created_by": self.actor,
        }
        updated = {
            **head,
            "latest_version": number,
            "rev": int(head["rev"]) + 1,
            "updated_at": row["created_at"],
            "updated_by": self.actor,
        }
        self.put_artifact(key, artifact)
        return self.commit(
            operation,
            request,
            {"item": view(updated), "version": view(row)},
            [
                self.put(updated, "rev = :rev", {":rev": head["rev"]}),
                self.put(row),
                self.event(
                    content_id,
                    updated["rev"],
                    "version_saved",
                    body,
                    {
                        "version": number,
                        "artifact_sha256": fingerprint,
                        "document_sha256": row["document_sha256"],
                    },
                ),
            ],
        )

    def listing(self, partition, query, *, numeric=False):
        if set(query) - {"after", "limit"}:
            raise LibraryError("invalid_library_query")
        limit = int(query.get("limit", "20"))
        if not 1 <= limit <= 50:
            raise LibraryError("invalid_library_limit")
        after = query.get("after")
        if after:
            if numeric:
                value = int(after)
                if not 0 <= value <= 9007199254740991:
                    raise LibraryError("invalid_library_cursor")
                after = f"{value:016d}"
            else:
                identifier(after)
        response = self.client.query(
            TableName=self.table,
            ConsistentRead=True,
            KeyConditionExpression="pk = :pk AND sk > :after",
            ExpressionAttributeValues=wire({":pk": partition, ":after": after or "!"}),
            Limit=limit,
        )
        rows = [decode(row) for row in response.get("Items", [])]
        cursor = rows[-1]["sk"] if rows and response.get("LastEvaluatedKey") else None
        if numeric and cursor:
            cursor = str(int(cursor))
        return {"items": [view(row) for row in rows], "next_after": cursor, "page_count": len(rows)}

    def freeze(self, body):
        command(body, {"title", "description", "items"})
        text(body["title"], 200)
        text(body["description"], 2000, empty=True)
        roots = references(body["items"], MAX_RELEASE_ITEMS)
        if not roots:
            raise LibraryError("library_release_empty")
        prior = self.receipt("release", body)
        if prior:
            return prior
        pending = list(roots)
        closure = {}
        identities = {}
        while pending:
            ref = pending.pop()
            content_id = ref["content_id"]
            if content_id in closure:
                if any(closure[content_id][k] != ref[k] for k in ("version", "artifact_sha256")):
                    raise LibraryError("library_dependency_version_conflict", 409)
                continue
            if len(closure) >= MAX_RELEASE_ITEMS:
                raise LibraryError("library_release_dependency_limit", 413)
            row = self.check_reference(ref)
            self.artifact(row)
            identity = (row["kind"], row["runtime_id"])
            if identity in identities and identities[identity] != content_id:
                raise LibraryError("library_runtime_identity_conflict", 409)
            identities[identity] = content_id
            closure[content_id] = {
                **ref,
                "kind": row["kind"],
                "runtime_id": row["runtime_id"],
                "document_sha256": row["document_sha256"],
            }
            pending.extend(row["dependencies"])
        release_id = digest({"actor": self.actor, "request_id": body["request_id"]})[:32]
        manifest = {
            "schema_version": VERSION,
            "release_id": release_id,
            "roots": roots,
            "items": sorted(closure.values(), key=lambda value: value["content_id"]),
            "validation_state": "not_run",
            "deployment_state": "not_requested",
        }
        fingerprint = digest(manifest)
        key = f"library/releases/{release_id}/{fingerprint}.json"
        row = {
            "pk": "RELEASE",
            "sk": release_id,
            "schema_version": VERSION,
            "release_id": release_id,
            "title": body["title"],
            "description": body["description"],
            "state": "frozen",
            "validation_state": "not_run",
            "deployment_state": "not_requested",
            "artifact_sha256": fingerprint,
            "artifact_key": key,
            "item_count": len(closure),
            "created_at": stamp(),
            "created_by": self.actor,
            "request_id": body["request_id"],
            "reason": body["reason"],
        }
        self.put_artifact(key, manifest)
        return self.commit("release", body, {"release": view(row)}, [self.put(row)])
