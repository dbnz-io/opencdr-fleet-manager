"""Versioned organization-local fleet API; authorization is AWS_IAM on every route."""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor

from . import __version__
from .agent import Agent, route
from .models import FleetError, agent_id, json_text, page_size, public_registration, registration
from .polling_policy import intervals, stale_after_seconds

LOG = logging.getLogger(__name__)


def forward(agent, method, path, query, body):
    try:
        report = agent.verify()  # Never authorize a write from cached health.
    except FleetError as error:
        return {
            "status_code": error.status,
            "error_code": error.code,
            "attempted": False,
            "outcome": "not_sent",
        }
    if method == "GET" and path == "/status" and not query:
        return {"status_code": 200, "body": report, "attempted": True}
    try:
        code, result = agent.request(method, path, query=query, body=body)
        return {"status_code": code, "body": result, "attempted": True}
    except FleetError as error:
        return {
            "status_code": error.status,
            "error_code": error.code,
            "attempted": True,
            "outcome": "unknown" if method != "GET" else "failed",
        }


def forward_many(
    store, names: list, method: str, path: str, query=None, body=None, agent_factory=Agent
) -> list[dict]:
    if (
        not isinstance(names, list)
        or not 1 <= len(names) <= 8
        or any(not isinstance(name, str) for name in names)
        or len(set(names)) != len(names)
    ):
        raise FleetError("select_1_to_8_unique_agents")
    route(method, path)
    from .reviewed_rollouts import enforced

    if (
        enforced()
        and method != "GET"
        and path not in {"/rules/validate", "/rules/evaluate", "/rule-releases/plan"}
    ):
        raise FleetError("reviewed_rollout_required", 428)
    prepared, results = [], {}
    deadline = time.monotonic() + 20
    for name in names:
        agent_id(name)
        try:
            record = store.get_agent(name)
            if not record["enabled"]:
                raise FleetError("agent_disabled", 409)
            access = os.getenv("FLEET_MANAGEMENT_ACCESS", "administrator")
            ranks = {"observer": 0, "operator": 1, "responder": 2, "administrator": 3}
            if method != "GET" and ranks.get(
                record.get("write_access", "operator"), 99
            ) > ranks.get(access, 0):
                raise FleetError("fleet_response_authority_required", 403)
            if method != "GET" and access == "observer":
                raise FleetError("fleet_read_only", 403)
            read_key, write_key = store.credentials(record, write=method != "GET")
            prepared.append((record, agent_factory(record, read_key, write_key, deadline=deadline)))
        except FleetError as error:
            results[name] = {
                "agent_id": name,
                "error_code": error.code,
                "status_code": error.status,
                "attempted": False,
            }

    def call(pair):
        record, agent = pair
        try:
            result = forward(agent, method, path, query, body)
            return record, {"agent_id": record["agent_id"], "attempted": True, **result}
        except FleetError as error:
            return record, {
                "agent_id": record["agent_id"],
                "status_code": error.status,
                "error_code": error.code,
                "outcome": "unknown" if method != "GET" else "failed",
            }

    with ThreadPoolExecutor(max_workers=8) as pool:
        for record, result in pool.map(call, prepared):
            if method != "GET" and 200 <= result["status_code"] < 300:
                try:
                    store.enqueue(record)
                    result["refresh_queued"] = True
                except Exception:
                    # Never misreport an accepted non-idempotent write as a failed write.
                    result["refresh_queued"] = False
            results[record["agent_id"]] = result
    ordered, budget = [], 3_500_000
    for name in names:
        result = results[name]
        size = len(json_text(result))
        if size > budget and "body" in result:
            result["body_bytes"] = len(json_text(result.pop("body")))
            result["body_omitted"] = True
            result["detail"] = "aggregate_response_limit_use_single_agent_requests"
        budget -= len(json_text(result))
        LOG.info(
            json_text(
                {
                    "operation": "agent_forward",
                    "agent_id": name,
                    "method": method,
                    "core_path": path,
                    "status_code": result["status_code"],
                    "attempted": result.get("attempted"),
                    "outcome": result.get("outcome"),
                }
            )
        )
        ordered.append(result)
    return ordered


def body(event):
    try:
        raw = event.get("body") or "{}"
        if event.get("isBase64Encoded"):
            raw = base64.b64decode(raw, validate=True).decode()
        if len(raw.encode()) > 2_000_000:
            raise FleetError("request_too_large", 413)
        return json.loads(raw)
    except (ValueError, UnicodeError, TypeError):
        raise FleetError("invalid_json") from None


def dispatch(event, store):
    method, path = event.get("httpMethod", ""), event.get("path", "")
    query = event.get("queryStringParameters") or {}
    params = event.get("pathParameters") or {}
    subscription = re.fullmatch(
        r"/v1/agents/([A-Za-z0-9_-]{1,80})/delivery/([A-Za-z0-9_-]{1,64})(?:/(read|ack))?", path
    )
    if subscription:
        from .subscriber_delivery import handle as delivery

        if query:
            raise FleetError("invalid_delivery_query")
        return delivery(
            store,
            method,
            subscription[1],
            subscription[2],
            subscription[3],
            body(event),
            event.get("requestContext", {}).get("identity", {}),
        )
    if path in {"/v1/review-policy", "/v1/reviews"} or path.startswith(
        ("/v1/review-grants/", "/v1/reviews/")
    ):
        from .approvals import handle

        return handle(
            store,
            method,
            path[3:],
            body(event) if method in {"POST", "PUT"} else {},
            query,
            (event.get("requestContext") or {}).get("identity") or {},
        )
    if path == "/v1/configuration/flags" and method == "GET" and not query:
        from ._contracts.configuration_flags import catalog

        return 200, {
            **catalog(),
            "deployment": {
                "account_id": os.environ["SECURITY_ACCOUNT_ID"],
                "home_region": os.getenv("AWS_REGION", os.getenv("AWS_DEFAULT_REGION")),
                "stage": os.environ["FLEET_STAGE"],
            },
        }
    if path == "/v1/groups" or path.startswith("/v1/groups/"):
        from ._contracts.approval_api import ReviewAPI
        from .groups import Groups
        from .reviewed_rollouts import owner

        service = ReviewAPI(
            store.client,
            os.environ["CASE_TABLE_NAME"],
            owner(),
            (event.get("requestContext") or {}).get("identity") or {},
            os.getenv("FLEET_MANAGEMENT_ACCESS", "administrator"),
            store.get_agent,
        )
        groups = Groups(store, service.reviews)

        def group_result(value):
            return {
                **value,
                "deployment": {
                    "account_id": os.environ["SECURITY_ACCOUNT_ID"],
                    "home_region": os.getenv("AWS_REGION", os.getenv("AWS_DEFAULT_REGION")),
                    "stage": os.environ["FLEET_STAGE"],
                },
            }

        if path == "/v1/groups" and method == "GET":
            return 200, group_result(groups.listing(query))
        parts = path.split("/")
        if len(parts) == 4 and method == "GET" and not query:
            return 200, group_result(groups.read(parts[3]))
        if len(parts) == 5 and parts[4] == "resolve" and method == "POST" and not query:
            request = body(event)
            if not isinstance(request, dict) or set(request) != {"expected_rev"}:
                raise FleetError("invalid_group_resolution")
            return 200, group_result(groups.resolve(parts[3], request["expected_rev"]))
        raise FleetError("use_reviewed_group_configuration", 428)
    if path.startswith("/v1/library/"):
        from .library import handle

        return handle(
            store,
            method,
            path[3:],
            body(event) if method in {"POST", "PUT"} else {},
            query,
            (event.get("requestContext") or {}).get("identity") or {},
        )
    if path in {"/v1/cases", "/v1/case-access"} or path.startswith(
        ("/v1/cases/", "/v1/case-integrations/")
    ):
        from .cases import handle

        return handle(
            store,
            method,
            path[3:],
            body(event) if method in {"POST", "PUT"} else {},
            query,
            (event.get("requestContext") or {}).get("identity") or {},
        )
    match = re.fullmatch(r"/v1/agents/([^/]+)/detections/outcomes(/history)?", path)
    if match:
        from .response_outcomes import handle

        return handle(store, agent_id(match[1]), method, bool(match[2]), query)
    match = re.fullmatch(r"/v1/agents/([^/]+)/detections/handling(/history)?", path)
    if match:
        from .detection_handling import handle

        return handle(
            store,
            agent_id(match[1]),
            method,
            bool(match[2]),
            query,
            body(event) if method == "PUT" else None,
        )
    if path.startswith("/v1/agents/") and path.endswith("/detections/recover"):
        if os.getenv("FLEET_MANAGEMENT_ACCESS", "administrator") != "administrator":
            raise FleetError("detection_recovery_requires_administrator", 403)
        from .detection_reconciliation import request
        from .detection_recovery import context

        parts = path.split("/")
        if len(parts) != 6:
            raise FleetError("route_not_found", 404)
        name = agent_id(parts[3])
        if method == "GET":
            return 200, context(store, name)
        if method == "POST":
            return 202, request(
                store,
                name,
                body(event),
                (event.get("requestContext") or {}).get("identity", {}).get("userArn"),
                recovery=True,
            )
        raise FleetError("method_not_allowed", 405)
    if path.startswith("/v1/agents/") and path.endswith("/detections/handoff"):
        if os.getenv("FLEET_MANAGEMENT_ACCESS", "administrator") != "administrator":
            raise FleetError("detection_handoff_requires_administrator", 403)
        from .detection_handoff import context
        from .detection_handoff import request as handoff_request

        parts = path.split("/")
        if len(parts) != 6:
            raise FleetError("route_not_found", 404)
        name = agent_id(parts[3])
        if method == "GET":
            return 200, context(store, name)
        if method == "POST":
            return 202, handoff_request(
                store,
                name,
                body(event),
                (event.get("requestContext") or {}).get("identity", {}).get("userArn"),
            )
        raise FleetError("method_not_allowed", 405)
    if (
        path.startswith("/v1/agents/")
        and path.endswith("/detections/reconcile")
        and method == "POST"
    ):
        if os.getenv("FLEET_MANAGEMENT_ACCESS", "administrator") != "administrator":
            raise FleetError("detection_reconciliation_requires_administrator", 403)
        from .detection_reconciliation import request

        parts = path.split("/")
        if len(parts) != 6:
            raise FleetError("route_not_found", 404)
        return 202, request(
            store,
            agent_id(parts[3]),
            body(event),
            (event.get("requestContext") or {}).get("identity", {}).get("userArn"),
        )
    if (
        path in {"/v1/detections", "/v1/detections/detail", "/v1/detections/summary"}
        and method == "GET"
    ):
        from .detection_queries import handle

        return handle(path, query, store)
    if path.startswith("/v1/rollouts"):
        from ._contracts.case_contract import iam_principal
        from ._contracts.delegation import delegated_actor
        from .reviewed_rollouts import ReviewedRollouts
        from .rollouts import Rollouts

        principal = delegated_actor() or iam_principal(
            (event.get("requestContext") or {}).get("identity") or {}
        )

        def job_result(value):
            return {
                **(value or {}),
                "deployment": {
                    "account_id": os.environ["SECURITY_ACCOUNT_ID"],
                    "home_region": os.getenv("AWS_REGION", os.getenv("AWS_DEFAULT_REGION")),
                    "stage": os.environ["FLEET_STAGE"],
                },
            }

        rollouts = Rollouts(store, authenticated_actor=principal)
        if path == "/v1/rollouts/plan" and method == "POST":
            return 201, job_result(rollouts.plan(body(event)))
        parts = path.strip("/").split("/")
        if len(parts) >= 3:
            rollout_id = parts[2]
            if len(parts) == 3 and method == "GET":
                return 200, job_result(rollouts.status(rollout_id))
            if len(parts) == 4 and parts[3] == "prepare" and method == "POST":
                return 200, job_result(ReviewedRollouts(rollouts).prepare(rollout_id, body(event)))
            if len(parts) == 4 and parts[3] == "cancel" and method == "POST":
                return 200, job_result(
                    rollouts.cancel(rollout_id, body(event), authenticated_actor=principal)
                )
            if len(parts) == 5 and parts[3] == "reconcile" and method == "POST":
                if body(event):
                    raise FleetError("invalid_rollout_reconciliation")
                return 200, job_result(
                    ReviewedRollouts(rollouts).reconcile(rollout_id, agent_id(parts[4]))
                )
            if len(parts) == 4 and parts[3] == "apply" and method == "POST":
                return 202, job_result(rollouts.enqueue(rollout_id, body(event)))
            if len(parts) == 4 and parts[3] == "drift" and method == "POST":
                return 200, job_result(rollouts.drift(rollout_id, body(event)))
            if len(parts) == 5 and parts[3] == "results" and method == "GET":
                rollouts.status(rollout_id)  # Scope-check before exposing a retained result.
                return 200, job_result(rollouts.blob(rollout_id, "RESULT#" + agent_id(parts[4])))
        raise FleetError("route_not_found", 404)
    if method == "GET" and path == "/v1/status":
        from .detections import installed, policy

        poll_seconds, refresh_seconds, _ = intervals()
        return 200, {
            "product": "OpenCDR Fleet Manager",
            "version": __version__,
            "fleet_contract_version": "1.0.0",
            "poll_interval_seconds": poll_seconds,
            "full_refresh_interval_seconds": refresh_seconds,
            "detection_poll_interval_seconds": policy()[0],
            "stale_after_seconds": stale_after_seconds(),
            "polling_scope": ["health", "configuration"],
            "mode": "observed-state-and-explicit-forwarding",
            "capabilities": {
                "iam_management": True,
                "configuration_flags": "1.0.0",
                "case_extensions": "1.0.0" if os.getenv("CASE_TABLE_NAME") else False,
                "case_merge": "1.0.0" if os.getenv("CASE_TABLE_NAME") else False,
                "case_tuning": "1.0.0"
                if os.getenv("CASE_TABLE_NAME")
                and os.getenv("LIBRARY_TABLE_NAME")
                and os.getenv("LIBRARY_BUCKET")
                else False,
                "routing_delivery": "1.0.0"
                if os.getenv("CASE_TABLE_NAME") and installed()
                else False,
                "subscriber_delivery": "1.0.0" if os.getenv("CASE_TABLE_NAME") else False,
                "routing_scheduler": False,
                "revision_polling": True,
                "durable_rollouts": True,
                "reviewed_rollouts": "1.0.0"
                if os.getenv("FLEET_REVIEW_ENFORCEMENT") == "true"
                else False,
                "detection_delivery": installed(),
                "trusted_identity": "1.0.0" if os.getenv("CASE_TABLE_NAME") else False,
                "case_external_status": "1.0.0" if os.getenv("CASE_TABLE_NAME") else False,
                "active_case_lookup": "1.0.0" if os.getenv("CASE_TABLE_NAME") else False,
                "library_quality": "1.0.0"
                if os.getenv("LIBRARY_TABLE_NAME") and os.getenv("LIBRARY_BUCKET")
                else None,
                "content_library": "1.0.0"
                if os.getenv("LIBRARY_TABLE_NAME") and os.getenv("LIBRARY_BUCKET")
                else False,
                "library_release_snapshots": "1.0.0"
                if os.getenv("LIBRARY_TABLE_NAME") and os.getenv("LIBRARY_BUCKET")
                else False,
                "operational_cases": "1.0.0"
                if os.getenv("CASE_TABLE_NAME") and os.getenv("CASE_EVIDENCE_BUCKET")
                else False,
                "response_outcome_reads": "1.0.0",
                "detection_handling": "1.0.0" if installed() else False,
                "detection_reconciliation": "1.0.0" if installed() else False,
                "detection_feed_recovery": "1.0.0" if installed() else False,
                "detection_consumer_handoff": "1.0.0" if installed() else False,
                "central_detection_queries": "1.0.0" if installed() else False,
            },
            "deployment": {
                "account_id": os.environ["SECURITY_ACCOUNT_ID"],
                "home_region": os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION")),
                "stage": os.environ["FLEET_STAGE"],
            },
        }
    if path in ("/v1/agents", "/v1/statuses") and method == "GET":
        items, token = store.agents(page_size(query.get("limit")), query.get("next_token"))
        return 200, {"items": [store.view_status(item) for item in items], "next_token": token}
    if path == "/v1/agents" and method == "POST":
        item = store.save_agent(registration(body(event)), create=True)
        queued = False
        if item["enabled"]:
            try:
                store.enqueue(item)
                queued = True
            except Exception:
                LOG.warning("initial_poll_enqueue_failed")
        return 201, {"agent": public_registration(item), "refresh_queued": queued}
    if path in ("/v1/fleet/read", "/v1/fleet/invoke") and method == "POST":
        request = body(event)
        if not isinstance(request, dict) or set(request) - {
            "agent_ids",
            "method",
            "path",
            "query",
            "body",
        }:
            raise FleetError("invalid_forward_request")
        verb = request.get("method", "GET")
        if path.endswith("/read") and verb != "GET":
            raise FleetError("read_endpoint_requires_get", 403)
        results = forward_many(
            store,
            request.get("agent_ids"),
            verb,
            request.get("path"),
            request.get("query"),
            request.get("body"),
        )
        return 207, {"results": results, "atomic": False}
    if path.startswith("/v1/agents/"):
        name = agent_id(params.get("agent_id", ""))
        record = store.get_agent(name)
        root = f"/v1/agents/{name}"
        if path == root and method == "GET":
            return 200, store.view_status(record)
        if path == root and method == "PUT":
            item = store.save_agent(registration(body(event), name), create=False)
            # Scheduled polling will pick up an enabled new revision within one tick.
            return 200, {"agent": public_registration(item)}
        if path == root + "/refresh" and method == "POST":
            if not record["enabled"]:
                raise FleetError("agent_disabled", 409)
            store.enqueue(record)
            return 202, {"agent_id": name, "status": "queued"}
        if path == root + "/configuration" and method == "GET":
            result = store.configuration(
                name, page_size(query.get("limit")), query.get("next_token"), query.get("kind")
            )
            result["configuration_stale"] = store.view_status(record)["configuration_stale"]
            return 200, result
        if path == root + "/detections/status" and method == "GET":
            from .detections import Detections

            return 200, Detections(store).status(record)
        if path.startswith(root + "/api/"):
            core_path = "/" + params.get("proxy", "")
            result = forward_many(
                store,
                [name],
                method,
                core_path,
                event.get("multiValueQueryStringParameters") or query,
                body(event) if event.get("body") else None,
            )[0]
            return result["status_code"], result
    raise FleetError("route_not_found", 404)


def response(code, payload):
    encoded = json_text(payload)
    if len(encoded) > 4_000_000:
        code, encoded = 413, json_text({"error_code": "fleet_response_too_large"})
    return {
        "statusCode": code,
        "headers": {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
        "body": encoded,
    }
