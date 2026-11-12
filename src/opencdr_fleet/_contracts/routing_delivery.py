"""Bounded owner feed drain; durable outcomes precede an atomic checkpoint/receipt.

The API or customer runner supplies wake-ups. It cannot supply detection bodies,
provenance, target scope or a cursor. Retention/recovery gaps require a new review.
"""

from .approval_contract import integer, require
from .case_store import Cases, digest, public


def drain(engine, approval_id, body):
    require(
        isinstance(body, dict)
        and set(body) == {"expected_rev", "request_id", "reason", "agent_id"},
        "invalid_routing_drain",
    )
    integer(body["expected_rev"], 1)
    engine.reviews.command(body["request_id"], body["reason"])
    receipt = engine.reviews.get("ROUTING_ACTIVATION#" + engine.reviews.namespace, approval_id)
    require(receipt is not None, "routing_activation_required", 409)
    active = engine.reviews.get(engine.partition, receipt["policy_id"])
    require(
        active
        and active["approval_id"] == approval_id
        and active["approval_rev"] == body["expected_rev"],
        "routing_activation_superseded",
        409,
    )
    engine.authorize(active)
    require(
        engine.feed is not None and body["agent_id"] in active.get("delivery", {}),
        "routing_subscription_unavailable",
        409,
    )
    name = body["agent_id"]
    start = active["delivery"][name]
    partition = "ROUTING_DELIVERY#" + engine.reviews.namespace + "#" + approval_id
    request_pk = partition + "#REQUEST"
    fingerprint = digest({"actor": engine.reviews.actor, "body": body})
    prior = engine.reviews.get(request_pk, body["request_id"])
    if prior:
        require(prior["request_sha256"] == fingerprint, "routing_drain_request_conflict", 409)
        return {"delivery": public(prior), "idempotent": True, "worker_connected": True}
    previous = engine.reviews.get(partition, name)
    position = previous["position"] if previous else start
    page = engine.feed.read(name, position, limit=20)
    original_resolver = engine.cases.resolver
    engine.source_fences = page["fences"]
    counts = {"create": 0, "join": 0, "manual": 0, "skip": 0, "metadata": 0}
    try:
        for entry in page["items"]:
            engine.authorize(active)
            if entry["change_type"] not in {"detection.created", "detection.backfilled"}:
                counts["metadata"] += 1
                continue
            resolved = engine.feed.resolve(name, entry)

            def resolver(agent_id, detection_id, value=resolved):
                require(
                    agent_id == name and detection_id == value["item"]["detection_id"],
                    "routing_feed_identity_mismatch",
                    502,
                )
                return value

            engine.cases.resolver = resolver
            result = engine.process(active["sk"], name, entry["detection_id"])
            counts[result["outcome"]["action"]] += 1
        row = {
            "pk": partition,
            "sk": name,
            "rev": int((previous or {}).get("rev", 0)) + 1,
            "position": page["position"],
            "approval_id": approval_id,
        }
        result = {
            "pk": request_pk,
            "sk": body["request_id"],
            "request_sha256": fingerprint,
            "approval_id": approval_id,
            "policy_id": active["sk"],
            "request_id": body["request_id"],
            "agent_id": name,
            "counts": counts,
            "consumed": len(page["items"]),
            "has_more": page["has_more"],
            "checkpoint_rev": row["rev"],
            "external_effects": False,
            "reason": body["reason"],
            "actor": engine.reviews.actor,
        }
        Cases.transact(
            engine.cases,
            [
                engine.cases.put(row, "rev = :rev", {":rev": previous["rev"]})
                if previous
                else engine.cases.put(row),
                engine.cases.put(result),
                *engine.authorize(active),
                *engine.access_fences(),
            ],
        )
        return {"delivery": public(result), "idempotent": False, "worker_connected": True}
    finally:
        engine.cases.resolver = original_resolver
        engine.source_fences = []
