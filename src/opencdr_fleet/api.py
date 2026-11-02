"""Versioned organization-local fleet API; authorization is AWS_IAM on every route."""

from __future__ import annotations

import base64
import json
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor

from . import __version__
from .agent import Agent, route
from .models import FleetError, agent_id, json_text, page_size, public_registration, registration

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
    prepared, results = [], {}
    deadline = time.monotonic() + 20
    for name in names:
        agent_id(name)
        try:
            record = store.get_agent(name)
            if not record["enabled"]:
                raise FleetError("agent_disabled", 409)
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
    if method == "GET" and path == "/v1/status":
        return 200, {
            "product": "OpenCDR Fleet Manager",
            "version": __version__,
            "fleet_contract_version": "1.0.0",
            "poll_interval_seconds": 60,
            "mode": "observed-state-and-explicit-forwarding",
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
