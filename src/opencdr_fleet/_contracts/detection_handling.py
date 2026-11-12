"""Handling metadata is independent of evidence, response outcomes and SIEM state."""

import re
from urllib.parse import urlsplit

STATUSES = {"open", "acknowledged", "resolved", "dismissed"}
DISPOSITIONS = {
    "untriaged",
    "true-positive",
    "benign-expected",
    "false-positive",
    "duplicate",
    "insufficient-context",
}


def initial():
    return {
        "schema_version": "1.0.0",
        "rev": 0,
        "status": "open",
        "disposition": "untriaged",
        "assigned_to": None,
        "note": "",
        "external_refs": [],
        "updated_at": None,
        "updated_by": None,
    }


def validate(body, previous):
    if not isinstance(body, dict) or set(body) != {
        "expected_rev",
        "request_id",
        "reason",
        "changes",
    }:
        raise ValueError("Expected revision, request ID, reason and changes are required")
    if type(body["expected_rev"]) is not int or body["expected_rev"] < 0:
        raise ValueError("Invalid handling revision")
    if not isinstance(body["request_id"], str) or not re.fullmatch(
        r"[a-f0-9]{32}", body["request_id"]
    ):
        raise ValueError("Invalid handling request ID")
    if not isinstance(body["reason"], str) or not 1 <= len(body["reason"].strip()) <= 1000:
        raise ValueError("A review reason is required for every change")
    changes = body["changes"]
    if (
        not isinstance(changes, dict)
        or not changes
        or set(changes) - {"status", "disposition", "assigned_to", "note", "external_refs"}
    ):
        raise ValueError("Unsupported handling changes")
    result = {**previous, **changes}
    if (
        not isinstance(result["status"], str)
        or not isinstance(result["disposition"], str)
        or result["status"] not in STATUSES
        or result["disposition"] not in DISPOSITIONS
    ):
        raise ValueError("Unknown handling status or disposition")
    if result["assigned_to"] is not None and (
        not isinstance(result["assigned_to"], str)
        or not 1 <= len(result["assigned_to"]) <= 256
        or any(ord(c) < 32 for c in result["assigned_to"])
    ):
        raise ValueError("Invalid assignment reference")
    if not isinstance(result["note"], str) or len(result["note"]) > 2000:
        raise ValueError("Handling note exceeds 2000 characters")
    if "external_refs" in changes:
        links = changes["external_refs"]
        if not isinstance(links, list) or len(links) > 5:
            raise ValueError("At most five external references are supported")
        verified, keys = [], set()
        for link in links:
            if not isinstance(link, dict) or set(link) != {
                "integration_id",
                "incident_id",
                "url",
                "status",
            }:
                raise ValueError("Manual references cannot claim verified synchronization")
            if any(
                not isinstance(link[k], str)
                or not 1 <= len(link[k]) <= 128
                or any(ord(c) < 32 for c in link[k])
                for k in ("integration_id", "incident_id", "status")
            ):
                raise ValueError("Invalid external incident identity or status label")
            url = link["url"]
            if not isinstance(url, str) or len(url) > 1024 or any(ord(c) < 33 for c in url):
                raise ValueError("Invalid incident URL")
            parsed = urlsplit(url)
            if (
                parsed.scheme != "https"
                or not parsed.hostname
                or parsed.username
                or parsed.password
            ):
                raise ValueError("Incident URLs require HTTPS without embedded credentials")
            key = (link["integration_id"], link["incident_id"])
            if key in keys:
                raise ValueError("Duplicate incident reference")
            keys.add(key)
            verified.append(
                {**link, "provenance": "manual", "sync_state": "unverified", "last_synced_at": None}
            )
        result["external_refs"] = verified
    return result
