"""Owner-local routing preview. No persistence, case creation, lookup or notification."""

from datetime import datetime

from .approval_contract import checksum, integer, require, text
from .case_contract import agents, identifier
from .case_store import digest
from .detection_query import canonical

GROUP_FIELDS = frozenset(
    {
        "severity",
        "source",
        "integration_id",
        "activity_name",
        "actor.user_name",
        "actor.arn",
        "network.source_ip",
        "runtime_entity",
    }
)


def policy(value):
    require(
        isinstance(value, dict)
        and set(value)
        == {
            "policy_id",
            "revision",
            "enabled",
            "mode",
            "agent_ids",
            "rule",
            "group_by",
            "window_seconds",
            "closed_case",
        },
        "invalid_routing_policy",
    )
    identifier(value["policy_id"])
    integer(value["revision"], 1)
    require(type(value["enabled"]) is bool, "invalid_routing_policy")
    require(
        isinstance(value["mode"], str) and value["mode"] in {"manual", "create", "join"},
        "invalid_routing_mode",
    )
    require(
        isinstance(value["closed_case"], str)
        and value["closed_case"] in {"manual", "skip", "new_case"},
        "invalid_closed_case_policy",
    )
    scopes = agents(value["agent_ids"])
    rule = value["rule"]
    require(
        isinstance(rule, dict) and set(rule) == {"kind", "rule_id", "content_sha256"},
        "invalid_routing_rule",
    )
    require(
        isinstance(rule["kind"], str) and rule["kind"] in {"signal", "correlation"},
        "invalid_routing_rule",
    )
    text(rule["rule_id"], 128)
    checksum(rule["content_sha256"])
    group = value["group_by"]
    require(
        isinstance(group, list)
        and len(group) <= 4
        and all(isinstance(x, str) and x in GROUP_FIELDS for x in group)
        and len(set(group)) == len(group),
        "invalid_routing_group_fields",
    )
    integer(value["window_seconds"], 60, 86400)
    result = {**value, "agent_ids": sorted(scopes), "group_by": sorted(group)}
    require(len(canonical(result).encode()) <= 16000, "routing_policy_too_large", 413)
    return result


def plan(owner, draft, item, evidence, candidate=None):
    """Only trusted owner-resolved detection/case records may reach this function."""
    selected = policy(draft)
    text(owner)
    require(item["agent_id"] in selected["agent_ids"], "routing_scope_forbidden", 403)
    require(
        evidence.get("detection_id") == item["detection_id"],
        "routing_evidence_identity_mismatch",
        502,
    )
    source = {
        k: item[k] for k in ["agent_id", "account_id", "region", "stage", "detection_id", "kind"]
    }
    result = {
        "preview_only": True,
        "effective_policy_revision": None,
        "proposed_policy_revision": selected["revision"],
        "policy_sha256": digest(selected),
        "owner": owner,
        "source": source,
        "evidence_sha256": digest(evidence),
        "action": "manual",
        "side_effects": False,
    }

    def finish(reason, action="manual", **extra):
        value = {**result, "action": action, "reason": reason, **extra}
        return {**value, "preview_sha256": digest(value)}

    if not selected["enabled"]:
        return finish("policy_disabled", "skip")
    if selected["mode"] == "manual":
        return finish("manual_policy")
    summary = item.get("summary", {})
    fingerprint = summary.get("content_fingerprint")
    if fingerprint is None:
        return finish("rule_version_unknown")
    if (
        item["kind"] != selected["rule"]["kind"]
        or summary.get("rule_id") != selected["rule"]["rule_id"]
        or fingerprint != selected["rule"]["content_sha256"]
    ):
        return finish("rule_version_not_matched", "skip")
    try:
        raw_time = (
            item.get("occurred_at") or evidence.get("event_time") or evidence.get("timestamp")
        )
        if not isinstance(raw_time, str):
            return finish("event_time_unknown")
        stamp = datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            return finish("event_time_unknown")
        seconds = int(stamp.timestamp())
        if seconds < 0:
            return finish("event_time_unknown")
    except (KeyError, ValueError, TypeError, OverflowError, OSError):
        return finish("event_time_unknown")
    group = {}
    for field in selected["group_by"]:
        value = summary
        for part in field.split("."):
            value = value.get(part) if isinstance(value, dict) else None
        if not isinstance(value, str) or not value or len(value) > 256:
            return finish("group_value_unknown")
        group[field] = value
    # Account, deployment and source-agent boundaries are mandatory, even when
    # users choose the same grouping values. Arrival time never changes a bucket.
    binding = {
        "owner": owner,
        "policy_sha256": result["policy_sha256"],
        "agent_id": source["agent_id"],
        "account_id": source["account_id"],
        "region": source["region"],
        "stage": source["stage"],
        "rule": selected["rule"],
        "window_start": seconds // selected["window_seconds"] * selected["window_seconds"],
        "window_seconds": selected["window_seconds"],
        "values": group,
    }
    group_sha = digest(binding)
    result.update(group_sha256=group_sha, grouping=binding)
    if selected["mode"] == "create":
        return finish(
            "create_per_detection",
            "create",
            case_key=digest({"owner": owner, "policy": result["policy_sha256"], "source": source})[
                :32
            ],
        )
    if candidate is None:
        return finish("new_group", "create", case_key=group_sha[:32])
    if set(candidate.get("agent_ids", [])) != {item["agent_id"]}:
        return finish("candidate_cross_account_scope")
    if (
        candidate.get("routing", {}).get("group_sha256") != group_sha
        or candidate.get("routing", {}).get("owner") != owner
    ):
        return finish("candidate_group_unverified")
    current = {"case_id": candidate["case_id"], "expected_rev": int(candidate["rev"])}
    if candidate["status"] == "closed":
        mode = selected["closed_case"]
        if mode == "new_case":
            return finish(
                "closed_group_new_case",
                "create",
                prior_case=current,
                case_key=digest({"group_sha256": group_sha, "closed_case": current})[:32],
            )
        return finish(
            "closed_group_" + mode, "skip" if mode == "skip" else "manual", prior_case=current
        )
    if candidate["status"] not in {"open", "investigating", "contained"}:
        return finish("candidate_status_unknown")
    return finish("verified_open_group", "join", target_case=current)


def preview(cases, body):
    require(
        isinstance(body, dict)
        and set(body)
        in (
            {"policy", "agent_id", "detection_id"},
            {"policy", "agent_id", "detection_id", "case_id"},
        ),
        "invalid_routing_preview",
    )
    selected = policy(body["policy"])
    require(
        set(selected["agent_ids"]) <= cases.allowed
        and body["agent_id"] in cases.allowed
        and body["agent_id"] in selected["agent_ids"],
        "routing_scope_forbidden",
        403,
    )
    text(body["detection_id"], 512)
    require(bool(cases.routing_owner), "routing_owner_unavailable", 503)
    cases.check_access()
    resolved = cases.resolver(body["agent_id"], body["detection_id"])
    require(
        resolved["item"]["agent_id"] == body["agent_id"]
        and resolved["item"]["detection_id"] == body["detection_id"],
        "routing_source_identity_mismatch",
        502,
    )
    candidate = cases.case(body["case_id"]) if body.get("case_id") else None
    value = plan(cases.routing_owner, selected, resolved["item"], resolved["evidence"], candidate)
    cases.check_access()
    return {"preview": value}
