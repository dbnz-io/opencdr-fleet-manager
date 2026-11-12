"""Bounded owner-local authoring; saved documents are not runtime validation."""

import json
import re
from urllib.parse import urlsplit

from .case_contract import CaseError, identifier, text

VERSION = "1.0.0"
MAX_DOCUMENT_BYTES = 65536
MAX_RELEASE_ITEMS = 25
KINDS = {"signal", "correlation", "list"}


class LibraryError(CaseError):
    pass


def runtime_id(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value):
        raise LibraryError("invalid_library_runtime_id")
    return value


def command(body, fields, *, revision=False):
    required = {"request_id", "reason"} | fields | ({"expected_rev"} if revision else set())
    if not isinstance(body, dict) or set(body) != required:
        raise LibraryError("invalid_library_request")
    identifier(body["request_id"])
    text(body["reason"], 1000)
    if revision and (
        type(body["expected_rev"]) is not int or not 1 <= body["expected_rev"] <= 9007199254740991
    ):
        raise LibraryError("invalid_library_revision")
    try:
        if len(json.dumps(body, allow_nan=False).encode()) > 131072:
            raise LibraryError("library_request_too_large", 413)
    except (ValueError, TypeError, RecursionError):
        raise LibraryError("invalid_library_json") from None


def references(values, maximum=20):
    if not isinstance(values, list) or len(values) > maximum:
        raise LibraryError("invalid_library_references")
    seen = set()
    for value in values:
        if not isinstance(value, dict) or set(value) != {
            "content_id",
            "version",
            "artifact_sha256",
        }:
            raise LibraryError("invalid_library_reference")
        identifier(value["content_id"])
        if type(value["version"]) is not int or not 1 <= value["version"] <= 9007199254740991:
            raise LibraryError("invalid_library_version")
        if not isinstance(value["artifact_sha256"], str) or not re.fullmatch(
            r"[a-f0-9]{64}", value["artifact_sha256"]
        ):
            raise LibraryError("invalid_library_digest")
        if value["content_id"] in seen:
            raise LibraryError("duplicate_library_reference")
        seen.add(value["content_id"])
    return sorted(values, key=lambda value: value["content_id"])


def provenance(value):
    if not isinstance(value, dict) or value.get("kind") not in {
        "authored",
        "git-import",
        "runtime-import",
    }:
        raise LibraryError("invalid_library_provenance")
    fields = {"kind"}
    if value["kind"] == "git-import":
        fields |= {"repository", "commit", "path", "upstream_sha256"}
        url = urlsplit(text(value.get("repository"), 1024))
        if (
            url.scheme != "https"
            or not url.hostname
            or url.username
            or url.password
            or url.query
            or url.fragment
            or url.port not in {None, 443}
            or any(ord(c) < 33 for c in value["repository"])
        ):
            raise LibraryError("invalid_library_repository")
        if not isinstance(value.get("commit"), str) or not re.fullmatch(
            r"(?:[a-f0-9]{40}|[a-f0-9]{64})", value["commit"]
        ):
            raise LibraryError("library_commit_must_be_pinned")
        path = text(value.get("path"), 512)
        if (
            path.startswith("/")
            or "\\" in path
            or any(part in {"", "..", "."} for part in path.split("/"))
            or any(ord(c) < 32 for c in path)
        ):
            raise LibraryError("invalid_library_source_path")
        if not isinstance(value.get("upstream_sha256"), str) or not re.fullmatch(
            r"[a-f0-9]{64}", value["upstream_sha256"]
        ):
            raise LibraryError("invalid_library_digest")
    elif value["kind"] == "runtime-import":
        fields |= {"source_deployment", "observed_at"}
        from datetime import datetime

        text(value.get("source_deployment"), 256)
        observed = datetime.fromisoformat(text(value.get("observed_at"), 64).replace("Z", "+00:00"))
        if observed.tzinfo is None:
            raise LibraryError("invalid_library_observation_time")
    if set(value) != fields:
        raise LibraryError("invalid_library_provenance")
    return {**value, "verification": "caller_declared"}


def document(value, header):
    if not isinstance(value, dict) or not value:
        raise LibraryError("library_document_must_be_object")
    if len(json.dumps(value, allow_nan=False).encode()) > MAX_DOCUMENT_BYTES:
        raise LibraryError("library_document_too_large", 413)

    def bounded(node, depth=0):
        if depth > 20:
            raise LibraryError("library_document_too_deep")
        if isinstance(node, dict):
            for key, child in node.items():
                text(key, 256)
                bounded(child, depth + 1)
        elif isinstance(node, list):
            for child in node:
                bounded(child, depth + 1)

    bounded(value)
    if {
        "rev",
        "expected_rev",
        "rule_version",
        "release_id",
        "release_version",
        "content_fingerprint",
        "case_id",
        "case_ids",
        "assigned_to",
    } & set(value):
        raise LibraryError("library_document_contains_operational_metadata")
    if header["kind"] == "list":
        if value.get("list_id") != header["runtime_id"] or "rule_kind" in value:
            raise LibraryError("library_document_identity_mismatch")
    elif value.get("rule_id") != header["runtime_id"] or value.get("rule_kind") != header["kind"]:
        raise LibraryError("library_document_identity_mismatch")
    return value
