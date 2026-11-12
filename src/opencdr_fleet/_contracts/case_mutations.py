"""Reviewed merge/duplicate decisions retain both case histories and evidence."""

from .approval_contract import integer, plan, require
from .case_contract import MAX_ATTACHMENTS, identifier
from .case_store import digest, stamp
from .detection_query import canonical


class CaseMutations:
    def __init__(self, routing):
        self.engine, self.cases, self.reviews = (
            routing.engine,
            routing.engine.cases,
            routing.reviews,
        )

    def prepare(self, operation):
        value = self.compile(operation, self.reviews.actor)
        return {k: value[k] for k in ["plan", "material"]}

    def compile(self, operation, actor):
        require(
            isinstance(operation, dict)
            and set(operation)
            == {"kind", "source_case_id", "target_case_id", "source_rev", "target_rev"}
            and operation["kind"] in {"case.merge", "case.duplicate"},
            "invalid_case_merge",
        )
        require(actor == self.cases.actor, "case_merge_actor_mismatch", 403)
        for key in ["source_case_id", "target_case_id"]:
            identifier(operation[key])
        for key in ["source_rev", "target_rev"]:
            integer(operation[key], 1)
        require(operation["source_case_id"] != operation["target_case_id"], "case_merge_same_case")
        self.cases.check_access()
        source, target = [
            self.cases.case(operation[k]) for k in ["source_case_id", "target_case_id"]
        ]
        require(
            source["rev"] == operation["source_rev"] and target["rev"] == operation["target_rev"],
            "case_merge_revision_conflict",
            409,
        )
        require(
            source["status"] != "closed"
            and target["status"] != "closed"
            and not source.get("merged_into")
            and not target.get("merged_into"),
            "case_merge_closed_or_merged",
            409,
        )
        require(set(source["agent_ids"]) == set(target["agent_ids"]), "case_merge_cross_scope", 403)
        merging = operation["kind"] == "case.merge"
        moved = [a for a in source["attachments"] if a["attached"]]
        existing = {a["attachment_id"] for a in target["attachments"]}
        require(
            not merging or not (existing & {a["attachment_id"] for a in moved}),
            "case_merge_attachment_conflict",
            409,
        )
        require(
            not merging or len(target["attachments"]) + len(moved) <= MAX_ATTACHMENTS,
            "case_attachment_limit",
            409,
        )
        require(len(moved) <= 70, "case_merge_transaction_limit", 413)
        # Verify retained immutable bytes. No lookup, provider call or response replay.
        for attachment in moved:
            self.cases.evidence(source["case_id"], attachment["attachment_id"])
        before = {"source": source, "target": target}
        at = stamp()
        changed_source = {
            **source,
            "status": "closed",
            "merged_into" if merging else "duplicate_of": target["case_id"],
            "attachments": [
                {**a, "attached": False, "merged_into": target["case_id"]}
                if merging and a["attached"]
                else a
                for a in source["attachments"]
            ],
        }
        links = list(target.get("related_cases", []))
        require(len(links) < 100, "case_relation_limit", 413)
        changed_target = {
            **target,
            "related_cases": [
                *links,
                {
                    "case_id": source["case_id"],
                    "kind": operation["kind"],
                    "source_rev": source["rev"],
                },
            ],
            "attachments": [
                *target["attachments"],
                *[{**a, "origin_case_id": source["case_id"]} for a in moved],
            ]
            if merging
            else target["attachments"],
        }
        writes, stored = [], {}
        for previous, updated in [(source, changed_source), (target, changed_target)]:
            updated = {
                **updated,
                "rev": int(previous["rev"]) + 1,
                "schema_version": "1.1.0",
                "updated_at": at,
                "updated_by": actor,
            }
            require(len(canonical(updated).encode()) <= 150000, "case_record_limit", 413)
            writes += [
                self.cases.put(updated, "rev = :rev", {":rev": previous["rev"]}),
                self.cases.put(
                    {
                        "pk": "AUDIT#" + updated["case_id"],
                        "sk": f"{updated['rev']:012d}",
                        "case_id": updated["case_id"],
                        "rev": updated["rev"],
                        "kind": operation["kind"],
                        "actor": actor,
                        "at": at,
                        "request_id": digest({"operation": operation, "before": before})[:32],
                        "reason": "Owner-reviewed case relation; execution receipt retains approver and request",
                        "detail": {
                            "operation": operation,
                            "before_sha256": digest(previous),
                            "history_preserved": True,
                        },
                    }
                ),
            ]
            stored[updated["case_id"]] = digest(updated)
        for attachment in moved:
            if merging:
                writes.append(
                    self.cases.put(
                        {
                            "pk": "LINK#" + attachment["attachment_id"],
                            "sk": "ACTIVE",
                            "case_id": target["case_id"],
                        },
                        "case_id = :source",
                        {":source": source["case_id"]},
                    )
                )
            else:
                writes.append(self.cases.lock(attachment, source["case_id"], release=True))
        fixed = plan(
            {
                "operation": "configuration.write",
                "content_sha256": digest(operation),
                "dependencies_sha256": digest(before),
                "response_required": False,
                "targets": [
                    {
                        "target_id": name,
                        "registration_rev": 0,
                        "snapshot_sha256": digest(before),
                        "expected_revisions": {
                            "source_case": int(source["rev"]),
                            "target_case": int(target["rev"]),
                        },
                    }
                    for name in sorted(source["agent_ids"])
                ],
            }
        )
        return {
            "plan": fixed,
            "material": {"content": operation, "dependencies": before},
            "writes": writes,
            "fences": self.engine.access_fences(),
            "result": {
                "kind": "case_merge",
                "cases_sha256": stored,
                "history_preserved": True,
                "external_effects": False,
                "runtime_activation": "not_applicable",
            },
        }

    def verify(self, execution):
        require(
            execution and execution.get("kind") == "case_merge",
            "case_merge_execution_not_found",
            404,
        )
        self.cases.check_access()
        matches = {
            identity: digest(self.cases.case(identity)) == sha
            for identity, sha in execution["cases_sha256"].items()
        }
        self.cases.check_access()
        return {
            "stored_matches": all(matches.values()),
            "cases": matches,
            "runtime_activation": "not_applicable",
            "external_effects": False,
        }
