"""Owner-administered issuers and subjects, with revisioned grants and audit."""

import re

from .case_contract import CaseError, agents, request, text
from .case_store import Cases, digest, public, stamp, wire
from .delegation import CURRENT, PERMISSIONS, actor_id


class Identities:
    def __init__(self, client, table, actor, registry):
        self.store = Cases(client, table, None, None, actor, [], None)
        self.actor, self.registry = actor, registry

    def get(self, kind, name):
        return public(self.store.get("IDENTITY_" + kind.upper(), name) or {"rev": 0})

    def update(self, kind, name, body):
        if CURRENT.get():
            raise CaseError("identity_admin_requires_direct_iam", 403)
        if kind == "issuer":
            request(body, {"tenant", "principals", "enabled"})
            if not re.fullmatch(r"[A-Za-z0-9_.:@/-]{1,128}", name):
                raise CaseError("invalid_identity_issuer")
            principals = body["principals"]
            if (
                not isinstance(principals, list)
                or not 1 <= len(principals) <= 10
                or any(
                    not isinstance(p, str)
                    or not re.fullmatch(
                        r"aws(?:-us-gov|-cn)?:[0-9]{12}:(?:AROA|AIDA)[A-Z0-9]{12,64}", p
                    )
                    for p in principals
                )
                or len(set(principals)) != len(principals)
            ):
                raise CaseError("invalid_identity_principal")
            data = {"issuer": name, "tenant": body["tenant"], "principals": sorted(principals)}
        elif kind == "subject":
            request(body, {"issuer", "tenant", "subject", "permissions", "agent_ids", "enabled"})
            for key in ("issuer", "tenant", "subject"):
                if not isinstance(body[key], str) or not re.fullmatch(
                    r"[A-Za-z0-9_.:@/-]{1,128}", body[key]
                ):
                    raise CaseError("invalid_identity_subject")
            if name != actor_id(body["issuer"], body["tenant"], body["subject"]):
                raise CaseError("identity_subject_mismatch")
            issuer = self.get("issuer", body["issuer"])
            if not issuer.get("enabled") or issuer["tenant"] != body["tenant"]:
                raise CaseError("identity_issuer_unavailable", 409)
            permissions = body["permissions"]
            if (
                not isinstance(permissions, list)
                or any(not isinstance(p, str) for p in permissions)
                or not set(permissions) <= PERMISSIONS
                or len(set(permissions)) != len(permissions)
            ):
                raise CaseError("invalid_identity_permissions")
            scope = agents(body["agent_ids"]) if body["agent_ids"] else []
            for agent in scope:
                self.registry(agent)
            data = {k: body[k] for k in ("issuer", "tenant", "subject")}
            data.update(actor=name, permissions=sorted(permissions), agent_ids=scope)
        else:
            raise CaseError("identity_route_not_found", 404)
        text(body["tenant"], 128)
        if type(body["enabled"]) is not bool:
            raise CaseError("invalid_identity_enabled")
        key = "IDENTITY_" + kind.upper()
        previous = self.get(kind, name)
        saved = self.store.get("IDENTITY_REQUEST#" + digest([kind, name]), body["request_id"])
        if saved:
            if saved["actor"] != self.actor or saved["digest"] != digest(body):
                raise CaseError("identity_request_conflict", 409)
            return {"identity": saved["result"], "idempotent": True}
        if previous["rev"] != body["expected_rev"]:
            raise CaseError("identity_revision_conflict", 409)
        # Subject identities and issuer tenant bindings cannot be retargeted.
        if previous["rev"] and any(previous.get(k) != data[k] for k in ("issuer", "tenant")):
            raise CaseError("identity_binding_immutable", 409)
        value = {
            **data,
            "enabled": body["enabled"],
            "rev": int(previous["rev"]) + 1,
            "updated_at": stamp(),
            "updated_by": self.actor,
        }
        row = {"pk": key, "sk": name, **value}
        # Fence queued approval eligibility against any issuer/subject change.
        # ADD is atomic across independent identity updates; no scan or per-reviewer
        # transaction conditions are needed by the approval owner adapter.
        operations = [
            {
                "Update": {
                    "TableName": self.store.table,
                    "Key": wire({"pk": "IDENTITY_AUTHORITY", "sk": "EPOCH"}),
                    "UpdateExpression": "ADD revision :one",
                    "ExpressionAttributeValues": wire({":one": 1}),
                }
            },
            self.store.put(row, "rev = :rev", {":rev": previous["rev"]})
            if previous["rev"]
            else self.store.put(row),
            self.store.put(
                {
                    "pk": "IDENTITY_AUDIT#" + digest([kind, name]),
                    "sk": f"{value['rev']:012d}",
                    "actor": self.actor,
                    "before": previous,
                    "after": value,
                    "reason": body["reason"],
                    "request_id": body["request_id"],
                }
            ),
            self.store.put(
                {
                    "pk": "IDENTITY_REQUEST#" + digest([kind, name]),
                    "sk": body["request_id"],
                    "actor": self.actor,
                    "digest": digest(body),
                    "result": value,
                }
            ),
        ]
        if kind == "issuer":
            # Sticky transport bindings prevent omission of the assertion from
            # falling back to the service role's broader permissions. Removed
            # principals remain bound, but can no longer attest this issuer.
            for principal in data["principals"]:
                operations.append(
                    self.store.put(
                        {"pk": "IDENTITY_TRANSPORT", "sk": principal, "issuer": name},
                        "attribute_not_exists(pk) OR issuer = :issuer",
                        {":issuer": name},
                    )
                )
        self.store.transact(operations)
        return {"identity": value, "idempotent": False}


def dispatch(store, tier, method, path, body, query):
    if tier != "administrator" or CURRENT.get():
        raise CaseError("identity_admin_requires_direct_iam", 403)
    match = re.fullmatch(r"/identity/(issuers|subjects)/([A-Za-z0-9_.:@-]{1,128})", path)
    if not match or query:
        raise CaseError("invalid_identity_route", 400)
    kind, name = {"issuers": "issuer", "subjects": "subject"}[match[1]], match[2]
    if method == "GET":
        return {"identity": store.get(kind, name)}
    if method == "PUT":
        return store.update(kind, name, body)
    raise CaseError("method_not_allowed", 405)
