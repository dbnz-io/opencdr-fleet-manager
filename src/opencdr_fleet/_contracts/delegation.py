"""Bounded human delegation over an already verified AWS_IAM transport.

The SigV4-signed POST body contains the assertion and the complete operation.
Only an owner-registered immutable AWS principal may attest a subject. A fresh,
owner-local subject grant is required; the issuer cannot mint permissions.
This module deliberately does not authorize queued jobs or response execution.
"""

import hashlib
import json
import re
import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass

from boto3.dynamodb.types import TypeDeserializer, TypeSerializer

from .case_contract import CaseError

CURRENT = ContextVar("opencdr_delegated_authority", default=None)
MAX_LIFETIME = 60
PERMISSIONS = frozenset({"read", "triage", "library", "review", "execute"})


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def fingerprint(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def actor_id(issuer, tenant, subject):
    return "human:" + fingerprint([issuer, tenant, subject])


def wire(value):
    serializer = TypeSerializer()
    return {key: serializer.serialize(item) for key, item in value.items()}


def read(client, table, key):
    raw = client.get_item(TableName=table, Key=wire(key), ConsistentRead=True).get("Item")
    decoder = TypeDeserializer()
    return {k: decoder.deserialize(v) for k, v in raw.items()} if raw else None


def fail(code="delegation_forbidden", status=403):
    raise CaseError(code, status)


def operation_permission(method, path):
    """An allowlist prevents an assertion from authorizing an async side effect."""
    if path.startswith("/v1/"):
        path = path[3:]
    if (
        method == "GET"
        and (path == "/groups" or re.fullmatch(r"/groups/[A-Za-z0-9][A-Za-z0-9._-]{0,79}", path))
    ) or (
        method == "POST" and re.fullmatch(r"/groups/[A-Za-z0-9][A-Za-z0-9._-]{0,79}/resolve", path)
    ):
        return "review"
    if re.fullmatch(r"/cases/[a-f0-9]{32}/extensions/(?:indicators|provider-results)", path):
        if method == "GET":
            return "read"
        if method == "POST":
            return "triage"
    if method == "GET" and (
        path == "/configuration/inventory"
        or re.fullmatch(r"/agents/[A-Za-z0-9_-]{1,80}(?:/configuration|/detections/status)?", path)
    ):
        return "read"
    if method == "POST" and re.fullmatch(r"/cases/[a-f0-9]{32}/tuning-draft", path):
        return "library"
    if method == "GET" and path in {"/configuration/ownership", "/configuration/flags"}:
        return "review"
    if method == "POST" and (
        path == "/rollouts/plan"
        or re.fullmatch(
            r"/rollouts/(?:operator|responder|administrator)-[a-f0-9]{32}/(?:prepare|apply|cancel|reconcile/[A-Za-z0-9._-]{1,128})",
            path,
        )
    ):
        return "execute"
    if (
        method == "GET"
        and re.fullmatch(
            r"/rollouts/(?:operator|responder|administrator)-[a-f0-9]{32}(?:/results/[A-Za-z0-9._-]{1,128})?",
            path,
        )
    ) or (
        method == "POST"
        and re.fullmatch(r"/rollouts/(?:operator|responder|administrator)-[a-f0-9]{32}/drift", path)
    ):
        return "review"
    if method == "POST" and re.fullmatch(
        r"/reviews/[a-f0-9]{32}/(?:execute|activate|cancel|drain)", path
    ):
        return "execute"
    if method == "GET" and re.fullmatch(
        r"/reviews/[a-f0-9]{32}/(?:execution|verification|activation)", path
    ):
        return "review"
    if (
        method == "GET" and (path == "/reviews" or re.fullmatch(r"/reviews/[a-f0-9]{32}", path))
    ) or (
        method == "POST"
        and (
            path == "/reviews"
            or re.fullmatch(r"/reviews/[a-f0-9]{32}/(?:decisions|withdrawals)", path)
        )
    ):
        return "review"
    forwarded = re.fullmatch(
        r"/agents/[A-Za-z0-9_-]{1,80}/detections/(handling|outcomes)(/history)?", path
    )
    if forwarded:
        path = "/detections/" + forwarded[1] + (forwarded[2] or "")
    if method == "GET" and (
        path
        in {
            "/status",
            "/detections",
            "/detections/summary",
            "/detections/detail",
            "/detections/handling",
            "/detections/handling/history",
            "/detections/outcomes",
            "/detections/outcomes/history",
            "/cases/active",
            "/case-access",
        }
        or re.fullmatch(r"/cases(?:/[a-f0-9]{32}(?:/(?:history|evidence))?)?", path)
        or re.fullmatch(
            r"/library/(?:items|releases)(?:/[a-f0-9]{32}(?:/(?:versions(?:/[1-9][0-9]*(?:/artifact)?)?|history|artifact|runtime-source|(?:tests|compilations|mappings)(?:/[a-f0-9]{32})?))?)?",
            path,
        )
    ):
        return "library" if path.startswith("/library/") else "read"
    if (
        method == "POST"
        and path in {"/cases", "/cases/routing/preview"}
        or method == "PUT"
        and path == "/detections/handling"
        or method == "PUT"
        and re.fullmatch(r"/cases/[a-f0-9]{32}", path)
        or method == "POST"
        and re.fullmatch(r"/cases/[a-f0-9]{32}/(?:notes|detections(?:/detach)?)", path)
    ):
        return "triage"
    if (
        method == "POST"
        and path in {"/library/items", "/library/releases"}
        or method == "PUT"
        and re.fullmatch(r"/library/items/[a-f0-9]{32}", path)
        or method == "POST"
        and re.fullmatch(
            r"/library/items/[a-f0-9]{32}/(?:versions|imports|runtime-imports|tests)", path
        )
        or method == "POST"
        and re.fullmatch(r"/library/releases/[a-f0-9]{32}/(?:compilations|mappings)", path)
    ):
        return "library"
    fail("delegation_operation_not_supported")


@dataclass(frozen=True)
class Authority:
    client: object
    table: str
    actor: str
    issuer_key: dict
    subject_key: dict
    issuer_revision: int
    subject_revision: int
    expires_at: int
    agents: frozenset
    permissions: frozenset
    transport_principal: str
    claim: dict

    def fresh(self, now=None):
        now = time.time() if now is None else now
        if now >= self.expires_at:
            fail("delegation_expired")
        for key, revision in (
            (self.issuer_key, self.issuer_revision),
            (self.subject_key, self.subject_revision),
        ):
            row = read(self.client, self.table, key)
            if not row or row.get("rev") != revision or row.get("enabled") is not True:
                fail("delegation_revoked")
        return self

    def fences(self):
        self.fresh()
        return [
            {
                "ConditionCheck": {
                    "TableName": self.table,
                    "Key": wire(key),
                    "ConditionExpression": "rev = :rev AND enabled = :enabled",
                    "ExpressionAttributeValues": wire({":rev": revision, ":enabled": True}),
                }
            }
            for key, revision in (
                (self.issuer_key, self.issuer_revision),
                (self.subject_key, self.subject_revision),
            )
        ]


def authorize(client, table, envelope, *, owner, transport_principal, now=None):
    now = int(time.time()) if now is None else now
    if not isinstance(envelope, dict) or set(envelope) != {"identity", "operation"}:
        fail("invalid_delegation", 400)
    claim, operation = envelope["identity"], envelope["operation"]
    if (
        not isinstance(claim, dict)
        or set(claim) != {"issuer", "tenant", "subject", "audience", "issued_at", "expires_at"}
        or not isinstance(operation, dict)
        or set(operation) != {"method", "path", "query", "body"}
    ):
        fail("invalid_delegation", 400)
    for field in ("issuer", "tenant", "subject"):
        if not isinstance(claim[field], str) or not re.fullmatch(
            r"[A-Za-z0-9_.:@/-]{1,128}", claim[field]
        ):
            fail("invalid_delegation", 400)
    if any(type(claim[k]) is not int for k in ("issued_at", "expires_at")):
        fail("invalid_delegation", 400)
    if claim["audience"] != owner:
        fail("delegation_wrong_audience")
    if not (
        0 < claim["expires_at"] - claim["issued_at"] <= MAX_LIFETIME
        and claim["issued_at"] <= now < claim["expires_at"]
    ):
        fail("delegation_expired")
    if not isinstance(operation["query"], dict) or not isinstance(operation["body"], dict):
        fail("invalid_delegation", 400)
    if not all(isinstance(k, str) and isinstance(v, str) for k, v in operation["query"].items()):
        fail("invalid_delegation", 400)
    if not isinstance(operation["method"], str) or not isinstance(operation["path"], str):
        fail("invalid_delegation", 400)
    if operation["method"] == "GET" and operation["body"]:
        fail("invalid_delegation", 400)
    permission = operation_permission(operation["method"], operation["path"])
    issuer_key = {"pk": "IDENTITY_ISSUER", "sk": claim["issuer"]}
    actor = actor_id(claim["issuer"], claim["tenant"], claim["subject"])
    subject_key = {"pk": "IDENTITY_SUBJECT", "sk": actor}
    issuer, subject = read(client, table, issuer_key), read(client, table, subject_key)
    if not issuer or not subject:
        fail()
    if (
        issuer.get("enabled") is not True
        or subject.get("enabled") is not True
        or issuer.get("tenant") != claim["tenant"]
        or transport_principal not in issuer.get("principals", [])
        or subject.get("issuer") != claim["issuer"]
        or subject.get("tenant") != claim["tenant"]
        or subject.get("subject") != claim["subject"]
    ):
        fail()
    permissions = frozenset(subject.get("permissions", []))
    if permission not in permissions or not permissions <= PERMISSIONS:
        fail("delegation_permission_denied")
    allowed = frozenset(subject.get("agent_ids", []))
    if not allowed:
        fail("delegation_account_scope_required")
    return Authority(
        client,
        table,
        actor,
        issuer_key,
        subject_key,
        int(issuer["rev"]),
        int(subject["rev"]),
        claim["expires_at"],
        allowed,
        permissions,
        transport_principal,
        dict(claim),
    )


@contextmanager
def using(authority):
    token = CURRENT.set(authority)
    try:
        yield authority
    finally:
        CURRENT.reset(token)


def transaction_fences():
    authority = CURRENT.get()
    return authority.fences() if authority else []


def delegated_actor():
    authority = CURRENT.get()
    return authority.fresh().actor if authority else None


def scope_operation(authority, operation, *, core_scope=None):
    """Scope list queries at the server; case stores also enforce every case account."""
    path = operation["path"]
    path = path[3:] if path.startswith("/v1/") else path
    query = dict(operation["query"])
    if core_scope is not None and core_scope not in authority.agents:
        fail("delegation_account_scope_denied")
    inventory = re.fullmatch(
        r"/agents/([A-Za-z0-9_-]{1,80})(?:/configuration|/detections/status)?", path
    )
    if inventory and inventory[1] not in authority.agents:
        fail("delegation_account_scope_denied")
    forwarded = re.fullmatch(
        r"/agents/([A-Za-z0-9_-]{1,80})/detections/(?:handling|outcomes)(?:/history)?", path
    )
    if forwarded and forwarded[1] not in authority.agents:
        fail("delegation_account_scope_denied")
    if (
        path in {"/detections", "/detections/summary", "/cases", "/cases/active"}
        and operation["method"] == "GET"
    ):
        selected = (
            set(query["agent_ids"].split(",")) if "agent_ids" in query else set(authority.agents)
        )
        if not selected or not selected <= authority.agents:
            fail("delegation_account_scope_denied")
        query["agent_ids"] = ",".join(sorted(selected))
    if "agent_id" in query and query["agent_id"] not in authority.agents:
        fail("delegation_account_scope_denied")
    if path == "/detections/detail" and core_scope is None and "agent_id" not in query:
        fail("delegation_account_scope_required")
    if path == "/cases" and operation["method"] == "POST":
        selected = operation["body"].get("agent_ids")
        if (
            not isinstance(selected, list)
            or not selected
            or any(not isinstance(v, str) or v not in authority.agents for v in selected)
        ):
            fail("delegation_account_scope_denied")
    return {**operation, "query": query}


def audit_identity():
    authority = CURRENT.get()
    return (
        {
            "actor": authority.actor,
            "transport_principal": authority.transport_principal,
            "issuer": authority.claim["issuer"],
            "tenant": authority.claim["tenant"],
            "subject": authority.claim["subject"],
            "grant_rev": authority.subject_revision,
            "issuer_rev": authority.issuer_revision,
            "expires_at": authority.expires_at,
        }
        if authority
        else None
    )


def require_assertion(client, table, identity, method, path):
    if CURRENT.get() or path in {"/status", "/v1/status", "/delegated", "/v1/delegated"}:
        return
    from .case_contract import iam_principal

    principal = iam_principal(identity)
    if read(client, table, {"pk": "IDENTITY_TRANSPORT", "sk": principal}):
        fail("delegation_assertion_required")
