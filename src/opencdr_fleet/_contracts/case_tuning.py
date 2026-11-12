"""Case-linked disabled authoring drafts; never promote or invoke an external provider."""

from .approval_contract import integer, require
from .case_store import digest, stamp, wire
from .delegation import CURRENT
from .library_contract import command, references
from .library_store import Library


class TuningLibrary(Library):
    def __init__(self, cases, table, bucket, canonical_rule):
        super().__init__(cases.client, table, cases.s3, bucket, cases.actor)
        self.cases, self.canonical_rule = cases, canonical_rule
        self.extra = []

    def commit(self, operation, body, result, writes):
        self.cases.check_access()
        return super().commit(
            operation,
            body,
            {**result, "case": self.case_result, "runtime_changed": False, "draft_enabled": False},
            [*writes, *self.extra],
        )

    def draft(self, case_id, body):
        command(body, {"case_rev", "attachment_id", "source", "document"}, revision=True)
        integer(body["case_rev"], 1)
        references([body["source"]], maximum=1)
        identity = CURRENT.get()
        require(
            not identity or {"triage", "library"} <= set(identity.permissions),
            "tuning_case_and_library_permissions_required",
            403,
        )
        self.cases.check_access()
        case = self.cases.case(case_id)
        operation = "case-draft:" + case_id
        prior = self.receipt(operation, body)
        if prior:
            return prior
        require(case["rev"] == body["case_rev"], "case_revision_conflict", 409)
        captured = self.cases.evidence(case_id, body["attachment_id"])
        source = self.check_reference(body["source"])
        artifact = self.artifact(source)
        require(
            source["kind"] in {"signal", "correlation"}
            and captured["evidence"].get("rule_id") == source["runtime_id"]
            and captured["evidence"].get("content_fingerprint")
            == digest(self.canonical_rule(artifact["document"])),
            "tuning_evidence_rule_version_unknown",
            409,
        )
        require(isinstance(body["document"], dict), "invalid_tuning_document")
        document = {**body["document"], "enabled": False, "notify": False}
        at = stamp()
        self.case_result = {"case_id": case_id, "rev": int(case["rev"]) + 1}
        self.extra = [
            self.cases.put(
                {
                    **case,
                    "rev": self.case_result["rev"],
                    "updated_at": at,
                    "updated_by": self.actor,
                },
                "rev = :rev",
                {":rev": case["rev"]},
            ),
            self.cases.put(
                {
                    "pk": "AUDIT#" + case_id,
                    "sk": f"{self.case_result['rev']:012d}",
                    "case_id": case_id,
                    "rev": self.case_result["rev"],
                    "kind": "tuning_draft",
                    "actor": self.actor,
                    "request_id": body["request_id"],
                    "reason": body["reason"],
                    "at": at,
                    "detail": {
                        "source": body["source"],
                        "content_id": source["content_id"],
                        "enabled": False,
                        "runtime_changed": False,
                    },
                }
            ),
        ]
        if self.cases.grant_rev is not None:
            self.extra.append(
                {
                    "ConditionCheck": {
                        "TableName": self.cases.table,
                        "Key": wire({"pk": "ACCESS", "sk": self.actor}),
                        "ConditionExpression": "rev = :rev",
                        "ExpressionAttributeValues": wire({":rev": self.cases.grant_rev}),
                    }
                }
            )
        origin = {
            "kind": "case-tuning",
            "verification": "verified_case_snapshot",
            "owner": self.cases.routing_owner,
            "case_id": case_id,
            "case_rev": case["rev"],
            "attachment_id": body["attachment_id"],
            "evidence_sha256": captured["attachment"]["evidence_sha256"],
            "source": body["source"],
        }
        return self.save_version(
            source["content_id"],
            {
                "request_id": body["request_id"],
                "reason": body["reason"],
                "expected_rev": body["expected_rev"],
                "document": document,
                "dependencies": artifact["dependencies"],
                "provenance": {"kind": "authored"},
            },
            _verified=origin,
            _request=body,
            _operation=operation,
            _source=artifact["document"],
        )
