"""Observe agents, without imposing desired configuration or copying telemetry."""

from __future__ import annotations

import re
import time
from decimal import Decimal

from .agent import Agent, resource_path
from .models import FleetError, json_text, now_iso
from .polling_policy import intervals, monthly_requests

SECRET_FIELD = re.compile(
    r"secret|password|token|credential|auth|headers|api.?key|access.?key|private.?key|(^|_)url$",
    re.I,
)


def redact(value):
    if isinstance(value, dict):

        def descriptor(key, item):
            return (key == "response_authority" and isinstance(item, bool)) or (
                key == "auth_mode"
                and isinstance(item, str)
                and item
                in {
                    "iam",
                    "legacy",
                    "legacy-api-key",
                    "observer",
                    "operator",
                    "responder",
                    "administrator",
                }
            )

        return {
            key: "***REDACTED***"
            if SECRET_FIELD.search(key) and not descriptor(key, item)
            else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def collect(agent: Agent, registration: dict, *, inventory=False) -> dict[str, dict]:
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
    settings = (
        agent.pages("/configuration/inventory", {"kind": "settings", "page_size": "100"})
        if inventory
        else [{"resource_id": name} for name in registration["settings_ids"]]
    )
    for metadata in settings:
        name = metadata.get("resource_id")
        status, document = agent.request("GET", resource_path("settings", name))
        if status == 404 and not inventory:
            continue
        if status != 200 or not isinstance(document, dict):
            raise FleetError(f"settings_http_{status}", 502)
        if inventory and document.get("rev") != metadata.get("rev"):
            raise FleetError("configuration_changed_during_collection", 409)
        add("setting:" + name, redact(document))
    for role in agent.pages("/ir-roles", {"page_size": "200"}):
        account = role.get("aws_account_id")
        if not isinstance(account, str) or not re.fullmatch(r"\d{12}", account):
            raise FleetError("invalid_responder_record", 502)
        add("ir_role:" + account, role)
    add("catalog:integrations", redact(agent.get("/integrations")))
    bindings = (
        agent.pages("/configuration/inventory", {"kind": "integrations", "page_size": "100"})
        if inventory
        else [{"resource_id": name} for name in registration["integration_ids"]]
    )
    for metadata in bindings:
        name = metadata.get("resource_id")
        code, binding = agent.request("GET", resource_path("integrations", name))
        if code == 404 and not inventory:
            continue
        if code != 200 or not isinstance(binding, dict):
            raise FleetError(f"integration_http_{code}", 502)
        if inventory and binding.get("rev") != metadata.get("rev"):
            raise FleetError("configuration_changed_during_collection", 409)
        add("integration:" + name, redact(binding))
    return documents


def poll(store, message: dict, agent_factory=Agent) -> str:
    _, refresh_seconds, _ = intervals()
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
    reuse = False
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
        revision = report.get("configuration", {})
        core_generation = revision.get("generation") if revision.get("supported") else None
        if core_generation is None:
            state.pop("core_configuration_generation", None)
        if revision.get("writing"):
            raise FleetError("configuration_write_in_progress", 409)
        inventory = report.get("capabilities", {}).get("configuration_inventory") == "1.0.0"
        enumeration = "all_saved" if inventory else "registered_ids_only"
        reuse = (
            state.get("configuration_coverage", {}).get(
                "profile_and_binding_enumeration", "registered_ids_only"
            )
            == enumeration
            and core_generation is not None
            and core_generation == state.get("core_configuration_generation")
            and state.get("snapshot_registration_rev") == rev
            and state.get("snapshot_generation")
            and int(state.get("full_poll_request_count", 0)) > 1
            and time.time() * 1000 - int(state.get("full_snapshot_ms", 0)) < refresh_seconds * 1000
        )
        if reuse:
            try:
                manifest = store.manifest(name, state["snapshot_generation"])
                reuse = int(manifest["expires_at"]) > time.time() + 3600
            except FleetError:
                reuse = False
        if reuse:
            state.update(
                configuration_state="ready",
                health="healthy",
                configuration_verified_at=now_iso(),
                configuration_success_ms=int(time.time() * 1000),
            )
        else:
            runtime = (
                agent.get("/rules/runtime-status")
                if report.get("capabilities", {}).get("runtime_rule_verification")
                else {"supported": False}
            )
            if len(json_text(runtime)) > 64_000:
                raise FleetError("agent_runtime_status_too_large", 502)
            state.update(runtime=runtime, runtime_verified_at=now_iso())
            documents = collect(agent, item, inventory=inventory)
            if runtime.get("supported") is not False:
                after = agent.get("/rules/runtime-status")
                if runtime.get("generation") != after.get("generation"):
                    raise FleetError("configuration_changed_during_collection", 409)
                state["runtime"] = after
            if core_generation is not None:
                after_report = agent.verify()
                after_revision = after_report.get("configuration", {})
                if (
                    after_revision.get("writing")
                    or after_revision.get("generation") != core_generation
                ):
                    raise FleetError("configuration_changed_during_collection", 409)
                state["core_configuration_generation"] = core_generation
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
                    "settings_ids": sorted(
                        k.removeprefix("setting:") for k in documents if k.startswith("setting:")
                    ),
                    "integration_ids": sorted(
                        k.removeprefix("integration:")
                        for k in documents
                        if k.startswith("integration:")
                    ),
                    "profile_and_binding_enumeration": enumeration,
                    "unknown_revisions": sorted(
                        k
                        for k, value in documents.items()
                        if k.startswith(("setting:", "integration:")) and value.get("rev") is None
                    ),
                },
            )
            state["full_snapshot_ms"] = int(time.time() * 1000)
            state["snapshot_registration_rev"] = rev
            state["full_poll_request_count"] = agent.requests
        state.pop("error_code", None)
    except FleetError as error:
        state["configuration_state"] = "failed"
        state["health"] = "degraded" if state.get("status_verified_at") else "unreachable"
        state["error_code"] = error.code
        if error.code == "agent_identity_mismatch":
            state["health"] = "identity_mismatch"
        elif error.code == "unsupported_core_contract":
            state["health"] = "incompatible"
    if agent is not None:
        state["poll_request_count"] = agent.requests
        full_count = state.get("full_poll_request_count")
        # A failed health check is not a measurement of a full collection.
        # Keep the last successful measurement through failures and cache hits.
        estimate = None
        if full_count is not None:
            estimate = monthly_requests(
                int(full_count),
                generation_supported=state.get("core_configuration_generation") is not None,
            )
        state["estimated_monthly_poll_requests"] = estimate
        quota = (state.get("report", {}).get("management_api") or {}).get("monthly_quota")
        state["quota_warning"] = (
            None
            if (state.get("report", {}).get("management_api") or {}).get("quota_applies") is False
            else "poll_cost_not_measured"
            if estimate is None
            else "agent_quota_not_reported"
            if not isinstance(quota, (int, Decimal))
            else "agent_quota_insufficient"
            if quota < estimate
            else None
        )
    return "published" if store.finish(item, token, sequence, state) else "superseded"
