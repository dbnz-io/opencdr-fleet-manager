"""Observe agents, without imposing desired configuration or copying telemetry."""

from __future__ import annotations

import re
import time
from decimal import Decimal

from .agent import Agent, resource_path
from .models import FleetError, json_text, now_iso

SECRET_FIELD = re.compile(
    r"secret|password|token|credential|auth|headers|api.?key|access.?key|private.?key|(^|_)url$",
    re.I,
)


def redact(value):
    if isinstance(value, dict):
        return {
            key: "***REDACTED***" if SECRET_FIELD.search(key) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def collect(agent: Agent, registration: dict) -> dict[str, dict]:
    documents = {}

    def add(key, document):
        if key in documents:
            raise FleetError("duplicate_resource_during_collection", 502)
        documents[key] = document
        if len(documents) > 5000:
            raise FleetError("snapshot_capacity_exceeded", 502)

    for rule in agent.pages("/rules", {"page_size": "200"}):
        if rule.get("rule_kind") not in ("signal", "correlation") or not rule.get("rule_id"):
            raise FleetError("invalid_rule_record", 502)
        add(f"rule:{rule['rule_kind']}:{rule['rule_id']}", rule)
    for metadata in agent.pages("/lists", {"page_size": "200"}):
        name = metadata.get("list_id")
        if not isinstance(name, str):
            raise FleetError("invalid_list_record", 502)
        document = agent.get(resource_path("lists", name))
        if document.get("rev") != metadata.get("rev"):
            raise FleetError("configuration_changed_during_collection", 409)
        add("list:" + name, document)
    for name in registration["settings_ids"]:
        status, document = agent.request("GET", resource_path("settings", name))
        if status == 404:
            continue  # the profile is known absent in this complete collection
        if status != 200 or not isinstance(document, dict):
            raise FleetError(f"settings_http_{status}", 502)
        add("setting:" + name, redact(document))
    for role in agent.pages("/ir-roles", {"page_size": "200"}):
        account = role.get("aws_account_id")
        if not isinstance(account, str) or not re.fullmatch(r"\d{12}", account):
            raise FleetError("invalid_responder_record", 502)
        add("ir_role:" + account, role)
    add("catalog:integrations", redact(agent.get("/integrations")))
    for name in registration["integration_ids"]:
        code, binding = agent.request("GET", resource_path("integrations", name))
        if code == 404:
            continue
        if code != 200 or not isinstance(binding, dict):
            raise FleetError(f"integration_http_{code}", 502)
        add("integration:" + name, redact(binding))
    return documents


def poll(store, message: dict, agent_factory=Agent) -> str:
    name, rev, sequence = message["agent_id"], message["rev"], message["sequence"]
    # Age-out exceeds three queue receives so storage failures can reach the DLQ.
    # Sequence/revision fences suppress work already superseded by newer polls.
    if int(time.time() * 1000) - sequence > 1_800_000:
        return "expired"
    claimed = store.claim(name, rev, sequence)
    if not claimed:
        return "skipped"
    item, token = claimed
    state = store.get_status(name)
    state.update(
        agent_id=name,
        registration_rev=rev,
        poll_sequence=sequence,
        last_attempt_at=now_iso(),
        health="unreachable",
        configuration_state="failed",
    )
    agent = None
    try:
        read_key, _ = store.credentials(item)
        agent = agent_factory(item, read_key, deadline=time.monotonic() + 40)
        report = agent.verify()
        if len(json_text(report)) > 64_000:
            raise FleetError("agent_status_too_large", 502)
        state.update(
            report=redact(report),
            status_success_ms=int(time.time() * 1000),
            status_verified_at=now_iso(),
            health="degraded",
        )
        runtime = (
            agent.get("/rules/runtime-status")
            if report.get("capabilities", {}).get("runtime_rule_verification")
            else {"supported": False}
        )
        if len(json_text(runtime)) > 64_000:
            raise FleetError("agent_runtime_status_too_large", 502)
        state.update(runtime=runtime, runtime_verified_at=now_iso())
        documents = collect(agent, item)
        if runtime.get("supported") is not False:
            after = agent.get("/rules/runtime-status")
            if runtime.get("generation") != after.get("generation"):
                raise FleetError("configuration_changed_during_collection", 409)
            state["runtime"] = after
        generation = store.snapshot(name, documents, state.get("snapshot_generation"))
        state.update(
            snapshot_generation=generation,
            configuration_state="ready",
            health="healthy",
            configuration_verified_at=now_iso(),
            configuration_success_ms=int(time.time() * 1000),
            configuration_coverage={
                "rules": "all",
                "lists": "all_active",
                "responder_roles": "all",
                "settings_ids": item["settings_ids"],
                "integration_ids": item["integration_ids"],
                "profile_and_binding_enumeration": "registered_ids_only",
            },
        )
        state.pop("error_code", None)
    except FleetError as error:
        state["error_code"] = error.code
        if error.code == "agent_identity_mismatch":
            state["health"] = "identity_mismatch"
        elif error.code == "unsupported_core_contract":
            state["health"] = "incompatible"
    if agent is not None:
        state["poll_request_count"] = agent.requests
        estimate = max(
            agent.requests * 1440 * 31, int(state.get("estimated_monthly_poll_requests", 0))
        )
        state["estimated_monthly_poll_requests"] = estimate
        quota = (state.get("report", {}).get("management_api") or {}).get("monthly_quota")
        state["quota_warning"] = (
            "agent_quota_not_reported"
            if not isinstance(quota, (int, Decimal))
            else "agent_quota_insufficient"
            if quota < estimate
            else None
        )
    return "published" if store.finish(item, token, sequence, state) else "superseded"
