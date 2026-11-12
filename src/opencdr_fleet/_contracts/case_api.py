"""Shared route contract and explicit principal grants for Fleet-owned cases."""

import re

from .case_contract import CaseError, agents, request
from .case_store import Cases, digest, public, stamp


class Access:
    def __init__(self, client, table, actor, registry):
        self.store = Cases(client, table, None, None, actor, [], None)
        self.actor, self.registry = actor, registry

    def read(self, principal):
        if not isinstance(principal, str) or not re.fullmatch(
            r"aws(?:-us-gov|-cn)?:[0-9]{12}:(?:AROA|AIDA)[A-Z0-9]{12,64}", principal
        ):
            raise CaseError("invalid_case_principal")
        return public(
            self.store.get("ACCESS", principal)
            or {"principal": principal, "rev": 0, "agent_ids": []}
        )

    def update(self, body):
        request(body, {"principal", "agent_ids"})
        previous = self.read(body["principal"])
        scope = agents(body["agent_ids"]) if body["agent_ids"] != [] else []
        fingerprint = digest(body)
        key = "ACCESS_REQUEST#" + body["principal"]

        def retry():
            saved = self.store.get(key, body["request_id"])
            if saved:
                if saved["actor"] != self.actor or saved["digest"] != fingerprint:
                    raise CaseError("case_request_conflict", 409)
                return {"access": saved["result"], "idempotent": True}

        prior = retry()
        if prior:
            return prior
        if previous["rev"] != body["expected_rev"]:
            raise CaseError("case_access_revision_conflict", 409)
        for name in scope:
            self.registry(name)
        value = {
            "principal": body["principal"],
            "agent_ids": scope,
            "rev": int(previous["rev"]) + 1,
            "updated_at": stamp(),
            "updated_by": self.actor,
        }
        row = {"pk": "ACCESS", "sk": body["principal"], **value}
        writes = [
            self.store.put(row, "rev = :rev", {":rev": previous["rev"]})
            if previous["rev"]
            else self.store.put(row),
            self.store.put(
                {
                    "pk": "ACCESS_AUDIT#" + body["principal"],
                    "sk": f"{value['rev']:012d}",
                    "before": previous,
                    "after": value,
                    "reason": body["reason"],
                    "request_id": body["request_id"],
                    "actor": self.actor,
                }
            ),
            self.store.put(
                {
                    "pk": key,
                    "sk": body["request_id"],
                    "digest": fingerprint,
                    "actor": self.actor,
                    "result": value,
                }
            ),
        ]
        try:
            self.store.transact(writes)
        except CaseError:
            prior = retry()
            if prior:
                return prior
            raise
        return {"access": value, "idempotent": False}


def dispatch(cases, method, path, body, query):
    extension = re.fullmatch(
        r"/cases/([a-f0-9]{32})/extensions/(indicators|provider-results)", path
    )
    if extension:
        from .case_extensions import Extensions

        service = Extensions(cases)
        if method == "GET":
            return service.listing(extension[1], extension[2], query)
        if method == "POST" and not query:
            return service.save(extension[1], extension[2], body)
        raise CaseError("method_not_allowed", 405)
    tuning = re.fullmatch(r"/cases/([a-f0-9]{32})/tuning-draft", path)
    if tuning:
        if method != "POST" or query or not getattr(cases, "tuning_library", None):
            raise CaseError("tuning_library_authority_required", 403)
        return cases.tuning_library.draft(tuning[1], body)
    if path == "/cases/routing/preview":
        from .case_routing import preview

        if method != "POST" or query:
            raise CaseError("invalid_routing_preview")
        return preview(cases, body)
    if path == "/cases/active" and method == "GET":
        return cases.active(query)
    if path == "/cases":
        if method == "GET":
            return cases.listing(query)
        if method == "POST" and not query:
            return cases.create(body)
        raise CaseError("invalid_case_request")
    match = re.fullmatch(
        r"/cases/([a-f0-9]{32})(/(notes|detections|detections/detach|history|evidence))?", path
    )
    if not match:
        raise CaseError("case_route_not_found", 404)
    case_id, suffix = match[1], match[3]
    if method == "GET":
        if suffix == "history":
            return cases.history(case_id, query)
        if suffix == "evidence" and set(query) == {"attachment_id"}:
            return cases.evidence(case_id, query["attachment_id"])
        if not suffix and not query:
            return {"case": cases.view(cases.case(case_id))}
    if query:
        raise CaseError("invalid_case_query")
    if method == "PUT" and not suffix:
        return cases.update(case_id, body)
    if method == "POST" and suffix in {"notes", "detections", "detections/detach"}:
        return {"notes": cases.note, "detections": cases.attach, "detections/detach": cases.detach}[
            suffix
        ](case_id, body)
    raise CaseError("method_not_allowed", 405)
