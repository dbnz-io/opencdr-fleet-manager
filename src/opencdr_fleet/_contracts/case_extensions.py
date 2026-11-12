"""Case-owned analyst indicators and retained provider evidence.

These records never enqueue a lookup, authorize payment, or prove a provider was
contacted. Historical imports are explicitly unverified and cannot be promoted
into an execution claim. Actor, scope, case revision and audit share one commit.
"""

import base64
import ipaddress
import json
import re
from urllib.parse import urlsplit, urlunsplit

from .case_contract import CaseError, request, text
from .case_store import decode, digest, public, stamp, wire


def normalize(kind, value):
    text(value, 2048)
    if value != value.strip() or any(ord(c) <= 32 for c in value):
        raise CaseError("invalid_case_indicator")
    if kind == "ip":
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            raise CaseError("invalid_case_indicator") from None
    if kind in {"md5", "sha1", "sha256"}:
        if not re.fullmatch(
            rf"[a-fA-F0-9]{{{ {'md5': 32, 'sha1': 40, 'sha256': 64}[kind] }}}", value
        ):
            raise CaseError("invalid_case_indicator")
        return value.lower()
    if kind == "domain":
        try:
            domain = value.rstrip(".").encode("idna").decode().lower()
        except UnicodeError:
            raise CaseError("invalid_case_indicator") from None
        if len(domain) > 253 or not all(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
            for part in domain.split(".")
        ):
            raise CaseError("invalid_case_indicator")
        return domain
    if kind == "url":
        try:
            parsed = urlsplit(value)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or parsed.username
                or parsed.password
            ):
                raise ValueError()
            port = parsed.port
            host = parsed.hostname.encode("idna").decode().lower()
            if ":" in host:
                host = "[" + host + "]"
            netloc = host + (":" + str(port) if port else "")
            return urlunsplit(
                (parsed.scheme, netloc, parsed.path or "/", parsed.query, parsed.fragment)
            )
        except (ValueError, UnicodeError):
            raise CaseError("invalid_case_indicator") from None
    raise CaseError("unsupported_case_indicator_type")


class Extensions:
    def __init__(self, cases):
        self.cases = cases

    def listing(self, case_id, kind, query):
        if kind not in {"indicators", "provider-results"} or set(query) - {"after"}:
            raise CaseError("invalid_case_extension_query")
        self.cases.check_access()
        self.cases.case(case_id)
        pk = "EXTENSION#" + case_id + "#" + kind
        args = {
            "TableName": self.cases.table,
            "KeyConditionExpression": "pk = :pk",
            "ExpressionAttributeValues": wire({":pk": pk}),
            "ConsistentRead": True,
            "Limit": 20,
        }
        if query.get("after"):
            token = query["after"]
            try:
                if not isinstance(token, str) or len(token) > 2048:
                    raise ValueError()
                cursor = json.loads(base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)))
                if (
                    set(cursor) != {"case_id", "kind", "key"}
                    or cursor["case_id"] != case_id
                    or cursor["kind"] != kind
                    or not re.fullmatch(r"[a-f0-9]{64}", cursor["key"])
                ):
                    raise ValueError()
                args["ExclusiveStartKey"] = wire({"pk": pk, "sk": cursor["key"]})
            except (ValueError, TypeError, KeyError):
                raise CaseError("invalid_case_extension_cursor") from None
        page = self.cases.client.query(**args)
        key = decode(page["LastEvaluatedKey"])["sk"] if page.get("LastEvaluatedKey") else None
        self.cases.check_access()
        return {
            "case_id": case_id,
            "kind": kind,
            "items": [public(decode(x)) for x in page.get("Items", [])],
            "next_after": base64.urlsafe_b64encode(
                json.dumps({"case_id": case_id, "kind": kind, "key": key}).encode()
            )
            .decode()
            .rstrip("=")
            if key
            else None,
            "execution_authorized": False,
        }

    def save(self, case_id, kind, body):
        if kind == "indicators":
            request(body, {"indicator", "relationship", "note", "source"})
            if not isinstance(body["indicator"], dict) or set(body["indicator"]) != {
                "type",
                "value",
            }:
                raise CaseError("invalid_case_indicator")
            indicator = {
                "type": body["indicator"]["type"],
                "value": normalize(body["indicator"]["type"], body["indicator"]["value"]),
            }
            if body["relationship"] not in {"unconfirmed", "relevant", "unrelated"}:
                raise CaseError("invalid_indicator_relationship")
            text(body["note"], 1000)
            source = body["source"]
            if not isinstance(source, dict) or source.get("kind") not in {"analyst", "attachment"}:
                raise CaseError("invalid_indicator_source")
            if set(source) != (
                {"kind"} if source["kind"] == "analyst" else {"kind", "attachment_id"}
            ):
                raise CaseError("invalid_indicator_source")
            key = digest(indicator)
            value = {
                "indicator": indicator,
                "relationship": body["relationship"],
                "note": body["note"],
                "source": source,
                "provenance": "analyst_assertion",
            }
        elif kind == "provider-results":
            request(
                body,
                {"provider", "reference", "source_sha256", "observed_at", "result", "indicator"},
            )
            if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", text(body["provider"], 64)):
                raise CaseError("invalid_provider_reference")
            text(body["reference"], 512)
            if not re.fullmatch(r"[a-f0-9]{64}", text(body["source_sha256"], 64)):
                raise CaseError("invalid_provider_source_hash")
            from datetime import UTC, datetime

            observed = datetime.fromisoformat(text(body["observed_at"], 64).replace("Z", "+00:00"))
            if observed.tzinfo is None or observed > datetime.now(UTC):
                raise CaseError("invalid_provider_result_time")
            indicator = body["indicator"]
            if not isinstance(indicator, dict) or set(indicator) != {"type", "value"}:
                raise CaseError("invalid_case_indicator")
            indicator = {
                "type": indicator["type"],
                "value": normalize(indicator["type"], indicator["value"]),
            }
            if (
                not isinstance(body["result"], dict)
                or len(json.dumps(body["result"], allow_nan=False).encode()) > 16000
            ):
                raise CaseError("provider_result_limit", 413)
            key = digest(
                {
                    "provider": body["provider"],
                    "reference": body["reference"],
                    "source_sha256": body["source_sha256"],
                }
            )
            value = {
                k: body[k]
                for k in ["provider", "reference", "source_sha256", "observed_at", "result"]
            }
            value.update(
                indicator=indicator,
                provenance="historical_import_unverified",
                execution_authorized=False,
                provider_contacted=False,
            )
        else:
            raise CaseError("case_extension_not_found", 404)
        cases = self.cases
        cases.check_access()
        previous = cases.case(case_id)
        retry = cases.receipt(case_id, "extension." + kind, body)
        if retry:
            return retry
        if int(previous["rev"]) != body["expected_rev"]:
            raise CaseError("case_revision_conflict", 409)
        if (
            kind == "indicators"
            and value["source"]["kind"] == "attachment"
            and not any(
                x["attachment_id"] == value["source"]["attachment_id"]
                for x in previous["attachments"]
            )
        ):
            raise CaseError("indicator_attachment_not_found", 404)
        pk = "EXTENSION#" + case_id + "#" + kind
        old = cases.get(pk, key)
        if kind == "provider-results" and old:
            raise CaseError("provider_history_immutable", 409)
        row = {
            "pk": pk,
            "sk": key,
            "extension_id": key,
            "case_id": case_id,
            **value,
            "rev": int(old["rev"]) + 1 if old else 1,
            "updated_by": cases.actor,
            "updated_at": stamp(),
        }
        put = cases.put(row, "rev = :rev", {":rev": old["rev"]}) if old else cases.put(row)
        return cases.commit(
            previous,
            previous,
            "extension." + kind,
            body,
            {
                "extension_id": key,
                "extension_revision": row["rev"],
                "provenance": value["provenance"],
                "execution_authorized": False,
            },
            extra=[put],
        )
