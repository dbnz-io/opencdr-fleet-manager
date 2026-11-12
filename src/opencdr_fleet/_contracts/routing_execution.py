"""Owner-local, reviewed routing execution for a durable feed adapter.

No public route or automatic trigger is installed here. The owner supplies a
resolver whose immutable provenance distinguishes live records from imports.
All effects are case/evidence writes; this module cannot call external providers.
"""

from botocore.exceptions import ClientError

from .approval_contract import integer, require
from .approval_contract import plan as approval_plan
from .case_contract import MAX_ATTACHMENTS, identifier
from .case_routing import plan, policy
from .case_store import Cases, digest, public, stamp, wire
from .delegation import CURRENT
from .detection_query import canonical


class RoutingAutomation:
    def __init__(self, cases, reviews, load_rule, feed=None):
        require(
            cases.table == reviews.table
            and cases.client is reviews.client
            and cases.routing_owner == reviews.owner
            and cases.actor == reviews.actor,
            "routing_owner_authority_mismatch",
            403,
        )
        self.cases, self.reviews, self.load_rule = cases, reviews, load_rule
        self.feed, self.source_fences = feed, []
        self.partition = "ROUTING#" + reviews.namespace

    def access_fences(self):
        self.cases.check_access()
        if self.cases.grant_rev is None:
            return []
        return [
            {
                "ConditionCheck": {
                    "TableName": self.cases.table,
                    "Key": wire({"pk": "ACCESS", "sk": self.cases.actor}),
                    "ConditionExpression": "rev = :rev",
                    "ExpressionAttributeValues": wire({":rev": self.cases.grant_rev}),
                }
            }
        ]

    def prepare(self, operation):
        require(
            isinstance(operation, dict)
            and set(operation) in ({"kind", "policy"}, {"kind", "policy", "source"})
            and operation["kind"] == "routing.configure",
            "invalid_routing_operation",
        )
        selected = policy(operation["policy"])
        require(set(selected["agent_ids"]) <= self.cases.allowed, "routing_scope_forbidden", 403)
        self.cases.check_access()
        previous = self.reviews.get(self.partition, selected["policy_id"])
        revision = int((previous or {}).get("revision", 0))
        require(selected["revision"] == revision + 1, "routing_policy_revision_conflict", 409)
        # The owner adapter resolves the authored version; unknown rules are never
        # inferred from a similarly named rule or an imported detection summary.
        rule = (
            self.load_rule(selected["rule"], operation["source"])
            if "source" in operation
            else self.load_rule(selected["rule"])
        )
        require(
            isinstance(rule, dict) and rule == selected["rule"], "routing_rule_version_unknown", 409
        )
        content = {
            "kind": "routing.configure",
            "policy": selected,
            **({"source": operation["source"]} if "source" in operation else {}),
        }
        dependencies = {
            "previous_revision": revision,
            "previous_sha256": digest(previous),
            "rule": rule,
        }
        fixed = approval_plan(
            {
                "operation": "configuration.write",
                "content_sha256": digest(content),
                "dependencies_sha256": digest(dependencies),
                "response_required": False,
                "targets": [
                    {
                        "target_id": name,
                        "registration_rev": 0,
                        "snapshot_sha256": digest(
                            {"owner": self.reviews.owner, "rule": rule, "agent_id": name}
                        ),
                        "expected_revisions": {"routing_policy": revision},
                    }
                    for name in selected["agent_ids"]
                ],
            }
        )
        return {"plan": fixed, "material": {"content": content, "dependencies": dependencies}}

    def activate(self, approval_id, body):
        require(
            isinstance(body, dict) and set(body) == {"expected_rev", "request_id", "reason"},
            "invalid_routing_activation",
        )
        integer(body["expected_rev"], 1)
        self.reviews.command(body["request_id"], body["reason"])
        detail = self.reviews.detail_visible(approval_id)
        retained = detail["binding"].get("material", {})
        selected = retained.get("content", {}).get("policy")
        require(isinstance(selected, dict), "routing_review_material_required", 409)
        key = selected["policy_id"]
        fingerprint = digest(
            {"body": body, "actor": self.reviews.actor, "approval_id": approval_id}
        )
        receipt_key = "ROUTING_ACTIVATION#" + self.reviews.namespace
        prior = self.reviews.get(receipt_key, approval_id)
        if prior:
            require(prior["request_sha256"] == fingerprint, "routing_activation_conflict", 409)
            return {"activation": public(prior), "idempotent": True}
        prepared = self.prepare(retained["content"])
        require(prepared["material"] == retained, "routing_dependencies_changed", 409)
        auth = self.reviews.authorize(approval_id, prepared["plan"])
        require(
            auth["approval_revision"] == body["expected_rev"], "approval_revision_conflict", 409
        )
        deadline = int(auth["expires_at"])
        if CURRENT.get():
            deadline = min(deadline, CURRENT.get().expires_at)
        require(self.reviews.clock() + 5 < deadline, "routing_authority_expired", 403)
        active = {
            "pk": self.partition,
            "sk": key,
            "revision": selected["revision"],
            "policy": selected,
            "approval_id": approval_id,
            "approval_rev": body["expected_rev"],
            "plan": prepared["plan"],
            "binding_sha256": auth["binding_sha256"],
            "executor": auth["authority"]["executor"],
            "actor": self.reviews.actor,
            "expires_at": deadline,
            "activated_at": stamp(),
        }
        receipt = {
            "pk": receipt_key,
            "sk": approval_id,
            "policy_id": key,
            "revision": selected["revision"],
            "request_sha256": fingerprint,
            "reason": body["reason"],
            "request_id": body["request_id"],
            "actor": self.reviews.actor,
            "expires_at": deadline,
        }
        subscriptions = self.feed.start(selected["agent_ids"]) if self.feed else None
        if subscriptions is not None:
            active["delivery"] = subscriptions
            receipt["delivery"] = subscriptions
        revision = selected["revision"] - 1
        writes = [
            self.cases.put(active, "revision = :rev", {":rev": revision})
            if revision
            else self.cases.put(active),
            self.cases.put(
                {
                    **active,
                    "pk": self.partition + "#VERSION#" + key,
                    "sk": str(selected["revision"]),
                }
            ),
            self.cases.put(receipt),
            *auth["fences"],
        ]
        Cases.transact(self.cases, [*writes, *self.access_fences()])
        return {"activation": public(receipt), "idempotent": False}

    def authorize(self, active):
        require(active["actor"] == self.reviews.actor, "routing_executor_mismatch", 403)
        auth = self.reviews.authorize(active["approval_id"], active["plan"])
        require(
            auth["approval_revision"] == active["approval_rev"]
            and auth["binding_sha256"] == active["binding_sha256"]
            and auth["authority"]["executor"] == active["executor"],
            "routing_authority_changed",
            403,
        )
        require(
            self.reviews.clock() + 5 < min(active["expires_at"], auth["expires_at"]),
            "routing_authority_expired",
            403,
        )
        self.cases.check_access()
        return [
            *auth["fences"],
            *self.source_fences,
            {
                "ConditionCheck": {
                    "TableName": self.cases.table,
                    "Key": wire({"pk": self.partition, "sk": active["sk"]}),
                    "ConditionExpression": "revision = :rev AND approval_id = :approval",
                    "ExpressionAttributeValues": wire(
                        {":rev": active["revision"], ":approval": active["approval_id"]}
                    ),
                }
            },
        ]

    def process(self, policy_id, agent_id, detection_id):
        """Consume an owner-resolved event. ACK only after this durable outcome.

        Missing trusted provenance yields a retained manual outcome. The adapter
        must preserve original provenance during live-feed replay/catch-up.
        """
        identifier(policy_id)
        active = self.reviews.get(self.partition, policy_id)
        require(active is not None, "routing_policy_not_found", 404)
        self.authorize(active)
        selected = active["policy"]
        require(
            agent_id in self.cases.allowed and agent_id in selected["agent_ids"],
            "routing_scope_forbidden",
            403,
        )
        event = digest(
            {
                "owner": self.reviews.owner,
                "policy_id": policy_id,
                "agent_id": agent_id,
                "detection_id": detection_id,
            }
        )
        # Receipt spans policy revisions: reconfiguration cannot replay an old
        # event into a second case. Explicit reviewed migration is separate work.
        pk = "ROUTING_OUTCOME#" + self.reviews.namespace
        prior = self.reviews.get(pk, event)
        if prior:
            return {"outcome": public(prior), "idempotent": True}
        resolved = self.cases.resolver(agent_id, detection_id)
        item, evidence = resolved["item"], resolved["evidence"]
        require(
            item["agent_id"] == agent_id and item["detection_id"] == detection_id,
            "routing_source_identity_mismatch",
            502,
        )
        first = plan(self.reviews.owner, selected, item, evidence)
        group_key = self.partition + "#GROUP#" + first.get("group_sha256", event)
        group = self.reviews.get(group_key, "ACTIVE") if selected["mode"] == "join" else None
        candidate = self.cases.case(group["case_id"]) if group else None
        decision = plan(self.reviews.owner, selected, item, evidence, candidate)
        provenance = resolved.get("routing_eligibility")
        if (
            not isinstance(provenance, dict)
            or provenance.get("source") != "live"
            or provenance.get("historical") is not False
        ):
            decision = {**decision, "action": "manual", "reason": "live_provenance_required"}
        attachment_id = digest({"agent_id": agent_id, "detection_id": detection_id})
        linked = self.cases.get("LINK#" + attachment_id, "ACTIVE")
        if linked:
            decision = {**decision, "action": "manual", "reason": "already_linked"}
        outcome = {
            "pk": pk,
            "sk": event,
            "policy_id": policy_id,
            "revision": active["revision"],
            "agent_id": agent_id,
            "detection_id": detection_id,
            "action": decision["action"],
            "reason": decision["reason"],
            "at": stamp(),
            "external_effects": False,
        }
        if decision["action"] not in {"create", "join"}:
            Cases.transact(
                self.cases,
                [self.cases.put(outcome), *self.authorize(active), *self.access_fences()],
            )
            return {"outcome": public(outcome), "idempotent": False}
        creating = decision["action"] == "create"
        case_id = decision["case_key"] if creating else candidate["case_id"]
        previous = None if creating else candidate
        require(
            not previous or len(previous["attachments"]) < MAX_ATTACHMENTS,
            "case_attachment_limit",
            409,
        )
        raw = canonical(evidence).encode()
        require(len(raw) <= 1_000_000, "case_evidence_too_large", 413)
        sha = digest(evidence)
        key = "cases/" + case_id + "/" + attachment_id + "/" + sha + ".json"
        try:
            self.cases.s3.put_object(
                Bucket=self.cases.bucket,
                Key=key,
                Body=raw,
                ContentType="application/json",
                ServerSideEncryption="AES256",
                IfNoneMatch="*",
            )
        except ClientError as error:
            if error.response["Error"]["Code"] != "PreconditionFailed":
                raise
            self.cases.read_blob(key, sha)
        attachment = {
            "attachment_id": attachment_id,
            "agent_id": agent_id,
            "detection_id": detection_id,
            **{k: item[k] for k in ["account_id", "region", "stage", "kind"]},
            "severity": str(item["summary"].get("severity", "UNKNOWN"))[:32],
            "rule_id": str(item["summary"].get("rule_id", ""))[:128],
            "evidence_sha256": sha,
            "evidence_key": key,
            "captured_at": stamp(),
            "attached_at": stamp(),
            "attached": True,
        }
        severity = str(item["summary"].get("severity", "unknown")).lower()
        if severity not in {"low", "medium", "high", "critical", "unknown"}:
            severity = "unknown"
        value = previous or {
            "case_id": case_id,
            "schema_version": "1.1.0",
            "agent_ids": [agent_id],
            "title": "Routed detection: " + selected["rule"]["rule_id"],
            "description": "Created by reviewed owner routing policy.",
            "severity": severity,
            "status": "open",
            "assigned_to": None,
            "created_at": stamp(),
            "created_by": self.cases.actor,
            "attachments": [],
            "routing": {
                "owner": self.reviews.owner,
                "group_sha256": decision["group_sha256"],
                "policy_id": policy_id,
                "effective_policy_revision": selected["revision"],
            },
        }
        value = {**value, "attachments": [*value["attachments"], attachment]}
        outcome["case_id"] = case_id
        extras = [
            self.cases.put(outcome),
            self.cases.lock(attachment, case_id),
            *self.authorize(active),
        ]
        if selected["mode"] == "join":
            pointer = {
                "pk": group_key,
                "sk": "ACTIVE",
                "case_id": case_id,
                "revision": int((group or {}).get("revision", 0)) + 1,
            }
            extras.append(
                self.cases.put(pointer, "revision = :rev", {":rev": group["revision"]})
                if group
                else self.cases.put(pointer)
            )
        if creating and candidate:
            extras.append(
                {
                    "ConditionCheck": {
                        "TableName": self.cases.table,
                        "Key": wire({"pk": "CASE", "sk": candidate["case_id"]}),
                        "ConditionExpression": "rev = :rev",
                        "ExpressionAttributeValues": wire({":rev": candidate["rev"]}),
                    }
                }
            )
        result = self.cases.commit(
            previous,
            value,
            "routed",
            {"request_id": event[:32], "reason": "Reviewed routing policy " + policy_id},
            {"outcome": public(outcome)},
            extras,
        )
        return {"outcome": public(outcome), "idempotent": result["idempotent"]}
