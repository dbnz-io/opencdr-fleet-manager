"""Authenticated connector reports, separate from local case status.

No provider credentials or remote HTTP calls live in this domain. An administrator
binds an immutable AWS principal to an integration, URL origin and account scope.
"""

import re
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

from .case_contract import CaseError, agents, request, text
from .case_store import Cases, digest, public, stamp


def integration_id(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value):
        raise CaseError("invalid_case_integration")
    return value


def origin(value):
    text(value, 1024)
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or any(ord(c) < 33 for c in value)
    ):
        raise CaseError("invalid_incident_url")
    if parsed.port not in {None, 443}:
        raise CaseError("invalid_incident_url")
    return "https://" + parsed.hostname.lower()


class Integrations:
    def __init__(self, client, table, actor, registry):
        self.store = Cases(client, table, None, None, actor, [], None)
        self.actor, self.registry = actor, registry

    def read(self, name):
        row = self.store.get("INTEGRATION", integration_id(name))
        if not row:
            raise CaseError("case_integration_not_found", 404)
        return public(row)

    def update(self, name, body):
        integration_id(name)
        request(body, {"principal", "agent_ids", "enabled", "incident_origin", "max_age_seconds"})
        if not isinstance(body["principal"], str) or not re.fullmatch(
            r"aws(?:-us-gov|-cn)?:[0-9]{12}:(?:AROA|AIDA)[A-Z0-9]{12,64}", body["principal"]
        ):
            raise CaseError("invalid_case_principal")
        scope = agents(body["agent_ids"])
        if (
            type(body["enabled"]) is not bool
            or type(body["max_age_seconds"]) is not int
            or not 60 <= body["max_age_seconds"] <= 604800
        ):
            raise CaseError("invalid_case_integration_policy")
        base = origin(body["incident_origin"])
        if body["incident_origin"] != base:
            raise CaseError("incident_origin_must_be_https_origin")
        key = "INTEGRATION_REQUEST#" + name

        def prior():
            row = self.store.get(key, body["request_id"])
            if row:
                if row["actor"] != self.actor or row["digest"] != digest(body):
                    raise CaseError("case_request_conflict", 409)
                return {"integration": row["result"], "idempotent": True}

        receipt = prior()
        if receipt:
            return receipt
        previous = self.store.get("INTEGRATION", name)
        if int(previous["rev"] if previous else 0) != body["expected_rev"]:
            raise CaseError("case_integration_revision_conflict", 409)
        for agent in scope:
            self.registry(agent)
        updated = {
            "integration_id": name,
            "rev": body["expected_rev"] + 1,
            "principal": body["principal"],
            "agent_ids": scope,
            "enabled": body["enabled"],
            "incident_origin": base,
            "max_age_seconds": body["max_age_seconds"],
            "updated_at": stamp(),
            "updated_by": self.actor,
        }
        row = {"pk": "INTEGRATION", "sk": name, **updated}
        try:
            self.store.transact(
                [
                    self.store.put(row, "rev = :rev", {":rev": previous["rev"]})
                    if previous
                    else self.store.put(row),
                    self.store.put(
                        {
                            "pk": "INTEGRATION_AUDIT#" + name,
                            "sk": f"{updated['rev']:012d}",
                            "before": public(previous) if previous else None,
                            "after": updated,
                            "reason": body["reason"],
                            "actor": self.actor,
                            "request_id": body["request_id"],
                        }
                    ),
                    self.store.put(
                        {
                            "pk": key,
                            "sk": body["request_id"],
                            "actor": self.actor,
                            "digest": digest(body),
                            "result": updated,
                        }
                    ),
                ]
            )
        except CaseError:
            receipt = prior()
            if receipt:
                return receipt
            raise
        return {"integration": updated, "idempotent": False}

    def report(self, case_id, body):
        def ack(result):
            return {
                "case_id": case_id,
                "rev": result["case"]["rev"],
                "idempotent": result["idempotent"],
            }

        if not isinstance(body, dict):
            raise CaseError("invalid_case_request")
        name = integration_id(body.get("integration_id"))
        binding = self.read(name)
        if not binding["enabled"] or binding["principal"] != self.actor:
            raise CaseError("case_connector_forbidden", 403)
        fields = {"integration_id", "incident_id", "sequence", "result"}
        fields |= (
            {"url", "status", "source_updated_at"} if body.get("result") == "ok" else {"error_code"}
        )
        request(body, fields, create=True)
        text(body["incident_id"], 128)
        if type(body["sequence"]) is not int or not 1 <= body["sequence"] <= 9007199254740991:
            raise CaseError("invalid_connector_sequence")
        if body["result"] == "ok":
            text(body["status"], 128)
            if origin(body["url"]) != binding["incident_origin"]:
                raise CaseError("incident_origin_mismatch", 403)
            source_at = datetime.fromisoformat(
                text(body["source_updated_at"], 64).replace("Z", "+00:00")
            )
            if source_at.tzinfo is None or source_at > datetime.now(UTC) + timedelta(minutes=5):
                raise CaseError("invalid_incident_timestamp")
        elif body["result"] != "error" or body["error_code"] not in {
            "unauthorized",
            "unavailable",
            "rate_limited",
            "not_found",
            "invalid_response",
        }:
            raise CaseError("invalid_connector_result")
        cases = Cases(
            self.store.client,
            self.store.table,
            None,
            None,
            self.actor,
            binding["agent_ids"],
            None,
            integration_fence=(name, binding["rev"]),
        )
        for _ in range(3):
            previous = cases.case(case_id)
            prior = cases.receipt(case_id, "external_status", body)
            if prior:
                return ack(prior)
            refs = previous.get("external_status", [])
            match = next(
                (
                    r
                    for r in refs
                    if r["integration_id"] == name and r["incident_id"] == body["incident_id"]
                ),
                None,
            )
            if (
                match
                and body["result"] == "ok"
                and source_at
                < datetime.fromisoformat(match["source_updated_at"].replace("Z", "+00:00"))
            ):
                raise CaseError("connector_source_time_regression", 409)
            if match and match["sequence"] >= body["sequence"]:
                raise CaseError("connector_sequence_conflict", 409)
            if not match and (body["result"] == "error" or len(refs) >= 5):
                raise CaseError("external_reference_missing_or_limit", 409)
            now = stamp()
            updated = {
                **(match or {}),
                "integration_id": name,
                "incident_id": body["incident_id"],
                "sequence": body["sequence"],
                "provenance": "authenticated_connector",
                "reported_by": self.actor,
                "binding_rev": binding["rev"],
                "last_attempt_at": now,
            }
            if body["result"] == "ok":
                updated.update(
                    url=body["url"],
                    status=body["status"],
                    source_updated_at=body["source_updated_at"],
                    last_success_at=now,
                    last_error_code=None,
                    sync_state="current",
                )
            else:
                updated.update(last_error_code=body["error_code"], sync_state="error")
            value = {**previous, "external_status": [r for r in refs if r is not match] + [updated]}
            try:
                return ack(
                    cases.commit(
                        previous,
                        value,
                        "external_status",
                        body,
                        {
                            "integration_id": name,
                            "incident_id": body["incident_id"],
                            "sequence": body["sequence"],
                            "result": body["result"],
                            "reported_status": updated.get("status"),
                            "error_code": updated.get("last_error_code"),
                        },
                    )
                )
            except CaseError as error:
                if error.code != "case_revision_or_active_link_conflict":
                    raise
        raise CaseError("case_revision_conflict", 409)


def visible_statuses(cases, row):
    result = []
    for ref in row.get("external_status", []):
        binding = cases.get("INTEGRATION", ref["integration_id"])
        state = ref["sync_state"]
        if not binding or not binding["enabled"]:
            state = "disabled"
        elif binding["principal"] != ref["reported_by"] or binding["rev"] != ref["binding_rev"]:
            state = "stale"
        elif state != "error" and (
            datetime.now(UTC) - datetime.fromisoformat(ref["last_success_at"])
        ).total_seconds() > int(binding["max_age_seconds"]):
            state = "stale"
        result.append({**ref, "sync_state": state})
    return result


def handle(client, table, actor, tier, registry, method, path, body, query):
    store = Integrations(client, table, actor, registry)
    if query:
        raise CaseError("invalid_case_query")
    match = re.fullmatch(r"/case-integrations/([A-Za-z0-9_-]{1,64})", path)
    if match:
        if tier != "administrator":
            raise CaseError("case_integration_administrator_required", 403)
        if method == "GET":
            return {"integration": store.read(match[1])}
        if method == "PUT":
            return store.update(match[1], body)
    match = re.fullmatch(r"/cases/([a-f0-9]{32})/external-status", path)
    if match and method == "POST":
        if tier != "integration":
            raise CaseError("dedicated_connector_identity_required", 403)
        return store.report(match[1], body)
    raise CaseError("case_route_not_found", 404)
