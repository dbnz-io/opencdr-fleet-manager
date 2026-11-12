"""Owner review adapter for version-pinned routing configuration.

Activation records authority but does not install a feed trigger or infer live
provenance. Feed integration must supply a separate trusted owner resolver.
"""

import hashlib
import json

from .approval_contract import require
from .case_store import Cases, public
from .delegation import CURRENT
from .library_contract import references
from .library_store import Library
from .routing_execution import RoutingAutomation


class OwnerRouting:
    def __init__(
        self,
        reviews,
        scopes,
        s3,
        case_bucket,
        library_table,
        library_bucket,
        canonical_rule,
        grant_rev=None,
        feed=None,
    ):
        if CURRENT.get():
            require("triage" in CURRENT.get().permissions, "routing_case_authority_required", 403)
        self.reviews = reviews
        self.library = Library(reviews.client, library_table, s3, library_bucket, reviews.actor)
        cases = Cases(
            reviews.client,
            reviews.table,
            s3,
            case_bucket,
            reviews.actor,
            scopes,
            None,
            grant_rev=grant_rev,
            routing_owner=reviews.owner,
        )
        self.canonical_rule = canonical_rule
        self.engine = RoutingAutomation(cases, reviews, self.load_rule, feed=feed)

    def load_rule(self, expected, source):
        references([source], maximum=1)
        row = self.library.check_reference(source)
        artifact = self.library.artifact(row)
        require(
            row["kind"] in {"signal", "correlation"}
            and artifact["kind"] == row["kind"]
            and artifact["runtime_id"] == row["runtime_id"],
            "routing_rule_source_mismatch",
            409,
        )
        fingerprint = hashlib.sha256(
            json.dumps(
                self.canonical_rule(artifact["document"]),
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            ).encode()
        ).hexdigest()
        actual = {"kind": row["kind"], "rule_id": row["runtime_id"], "content_sha256": fingerprint}
        require(actual == expected, "routing_rule_fingerprint_mismatch", 409)
        return actual

    def prepare(self, operation):
        require(
            isinstance(operation, dict) and set(operation) == {"kind", "policy", "source"},
            "routing_library_source_required",
        )
        return self.engine.prepare(operation)

    def activate(self, approval_id, body):
        detail = self.reviews.detail_visible(approval_id)
        content = detail["binding"].get("material", {}).get("content", {})
        require(
            "source" in content and content.get("kind") == "routing.configure",
            "routing_library_source_required",
        )
        result = self.engine.activate(approval_id, body)
        return {
            **result,
            "worker_connected": bool(result["activation"].get("delivery")),
            "detail": "Bounded owner feed drain; wake-ups use the owner API or customer runner."
            if result["activation"].get("delivery")
            else "Owner configuration retained; durable feed integration is not installed.",
        }

    def activation(self, approval_id):
        self.reviews.detail_visible(approval_id)
        row = self.reviews.get("ROUTING_ACTIVATION#" + self.reviews.namespace, approval_id)
        self.reviews.authority.fences()
        self.engine.cases.check_access()
        return {
            "activation": public(row) if row else None,
            "authority_expired": row["expires_at"] <= self.reviews.clock() if row else None,
            "worker_connected": bool(row and row.get("delivery") and self.engine.feed),
        }

    def drain(self, approval_id, body):
        from .routing_delivery import drain

        self.reviews.detail_visible(approval_id)
        return drain(self.engine, approval_id, body)
