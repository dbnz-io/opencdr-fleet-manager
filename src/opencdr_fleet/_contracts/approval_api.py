"""Authenticated owner review registry; execution uses separate mutation guards."""

import re

from .approval_authority import ApprovalGrants, FencedReviews, OwnerAuthority
from .approval_contract import require
from .approval_store import public
from .case_contract import iam_principal
from .delegation import CURRENT, delegated_actor


def is_review_route(path):
    return path in {"/review-policy", "/reviews"} or path.startswith(
        ("/review-grants/", "/reviews/")
    )


def exact(body, fields):
    require(isinstance(body, dict) and set(body) == set(fields), "invalid_review_request")


class ReviewAPI:
    def __init__(self, client, table, owner, identity, tier, registry, *, prepare=None):
        require(
            tier in {"observer", "triage", "operator", "responder", "administrator"},
            "review_iam_required",
            403,
        )
        self.tier, self.registry, self.prepare = tier, registry, prepare
        self.principal = delegated_actor() or iam_principal(identity)
        self.reviews = FencedReviews(
            client, table, owner, self.principal, OwnerAuthority(client, table, owner)
        )
        self.grants = ApprovalGrants(
            client,
            table,
            owner,
            self.principal,
            lambda actor: self.direct_admin() and actor == self.principal,
        )

    def direct_admin(self):
        return self.tier == "administrator" and CURRENT.get() is None

    def dispatch(self, method, path, body, query):
        require(is_review_route(path), "review_route_not_found", 404)
        require(isinstance(query, dict), "invalid_review_query")
        if method == "GET":
            require(not body, "invalid_review_request")
        else:
            require(not query, "invalid_review_query")
            require(
                self.tier in {"operator", "responder", "administrator"},
                "review_write_access_required",
                403,
            )
        if path.startswith("/review-grants/"):
            require(self.direct_admin(), "approval_grant_admin_required", 403)
            from .approval_contract import actor

            subject = actor(path.removeprefix("/review-grants/"))
            require(not query, "invalid_review_query")
            if method == "GET":
                return {
                    "grant": public(
                        self.grants.get(self.grants.partition, subject) or {"revision": 0}
                    )
                }
            require(method == "PUT", "method_not_allowed", 405)
            exact(body, {"grant", "expected_rev", "request_id", "reason"})
            require(isinstance(body["grant"], dict), "invalid_approval_grant")
            targets = body["grant"].get("target_ids")
            require(isinstance(targets, list) and len(targets) <= 100, "invalid_approval_targets")
            for target in targets:
                self.registry(target)
            return self.grants.configure(
                subject,
                body["grant"],
                expected_rev=body["expected_rev"],
                request_id=body["request_id"],
                reason=body["reason"],
            )
        if path == "/review-policy":
            require(self.direct_admin(), "review_policy_admin_requires_direct_iam", 403)
            require(not query, "invalid_review_query")
            if method == "GET":
                row = self.reviews.get("REVIEW_POLICY", self.reviews.owner)
                return {"policy": public(row) if row else {"rev": 0}}
            require(method == "PUT", "method_not_allowed", 405)
            exact(body, {"policy", "expected_rev", "request_id", "reason"})
            return {
                "policy": self.reviews.configure(
                    body["policy"],
                    expected_rev=body["expected_rev"],
                    request_id=body["request_id"],
                    reason=body["reason"],
                )
            }
        if path == "/reviews":
            if method == "GET":
                return self.reviews.list_visible(query)
            require(method == "POST", "method_not_allowed", 405)
            exact(body, {"operation", "expires_at", "request_id", "reason"})
            require(self.prepare is not None, "review_operation_adapter_unavailable", 503)
            # The owner adapter resolves revisions, dependencies and response effects.
            # Never accept client-supplied plan digests or response classification.
            prepared = self.prepare(body["operation"])
            material = None
            if isinstance(prepared, dict) and set(prepared) == {"plan", "material"}:
                fixed, material = prepared["plan"], prepared["material"]
            else:
                fixed = prepared
            if fixed["response_required"]:
                require(
                    self.tier in {"responder", "administrator"},
                    "review_response_access_required",
                    403,
                )
            return {
                "review": self.reviews.propose(
                    fixed,
                    material=material,
                    expires_at=body["expires_at"],
                    request_id=body["request_id"],
                    reason=body["reason"],
                )
            }
        match = re.fullmatch(r"/reviews/([a-f0-9]{32})(?:/(decisions|withdrawals))?", path)
        require(match is not None, "review_route_not_found", 404)
        identity, action = match.groups()
        if method == "GET" and action is None:
            require(not query, "invalid_review_query")
            return self.reviews.detail_visible(identity)
        require(method == "POST" and action is not None, "method_not_allowed", 405)
        fields = {"expected_rev", "request_id", "reason"}
        if action == "decisions":
            exact(body, fields | {"mode", "approve"})
            _, fixed = self.reviews.review(identity)
            if fixed["plan"]["response_required"]:
                require(
                    self.tier in {"responder", "administrator"},
                    "review_response_access_required",
                    403,
                )
            return {"review": self.reviews.decide(identity, **body)}
        exact(body, fields)
        return {"review": self.reviews.withdraw(identity, **body)}
