"""Fleet routing policy configuration uses both review and case scope grants."""

import os

from ._contracts.approval_contract import require
from ._contracts.case_api import Access
from ._contracts.delegation import CURRENT
from ._contracts.routing_api import OwnerRouting
from ._evaluator.rule_release import canonical


def service(store, reviews):
    from .routing_feed import RoutingFeed

    if CURRENT.get():
        scopes, revision = sorted(CURRENT.get().agents), None
    else:
        grant = Access(reviews.client, reviews.table, reviews.actor, store.get_agent).read(
            reviews.actor
        )
        scopes, revision = grant["agent_ids"], grant["rev"]
    require(bool(scopes), "routing_case_authority_required", 403)
    return OwnerRouting(
        reviews,
        scopes,
        store.s3,
        os.environ["CASE_EVIDENCE_BUCKET"],
        os.environ["LIBRARY_TABLE_NAME"],
        os.environ["LIBRARY_BUCKET"],
        canonical,
        grant_rev=revision,
        feed=RoutingFeed(store) if os.getenv("DETECTION_TABLE") else None,
    )
