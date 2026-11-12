"""Lambda entry points. Logs contain identifiers and error codes, never API payloads."""

from __future__ import annotations

import json
import logging
import os
import re
import time

from ._contracts.case_contract import CaseError
from .api import dispatch, response
from .models import FleetError, agent_id
from .polling import poll
from .store import Store

LOG = logging.getLogger(__name__)
LOG.setLevel(logging.INFO)


def check_account(context):
    expected = os.environ["SECURITY_ACCOUNT_ID"]
    if context.invoked_function_arn.split(":")[4] != expected:
        raise FleetError("wrong_security_account", 503)


def api(event, context):
    try:
        check_account(context)
        if not (event.get("requestContext", {}).get("identity", {}).get("userArn")):
            raise FleetError("iam_identity_required", 403)
        store = Store()
        access = os.getenv("FLEET_MANAGEMENT_ACCESS")
        if access:
            prefix = "/management/" + access
            path = event.get("path", "")
            if not path.startswith(prefix + "/v1/"):
                raise FleetError("invalid_management_entrypoint", 403)
            path = path[len(prefix) :]
            if os.getenv("CASE_TABLE_NAME") and access in {
                "observer",
                "triage",
                "operator",
                "responder",
                "administrator",
            }:
                from ._contracts.delegation import require_assertion

                try:
                    require_assertion(
                        store.client,
                        os.environ["CASE_TABLE_NAME"],
                        event.get("requestContext", {}).get("identity", {}),
                        event.get("httpMethod"),
                        path,
                    )
                except CaseError as error:
                    return response(error.status, {"code": error.code})
            if path == "/v1/delegated" or path.startswith("/v1/identity/"):
                from .identity import handle

                return handle(event, context, api, store=store)
            if access == "integration" and not (
                (event.get("httpMethod") == "GET" and path == "/v1/status")
                or (
                    event.get("httpMethod") == "POST"
                    and re.fullmatch(r"/v1/cases/[a-f0-9]{32}/external-status", path)
                )
            ):
                raise FleetError("connector_report_only", 403)
            if (
                access == "triage"
                and event.get("httpMethod") != "GET"
                and not (
                    (
                        event.get("httpMethod") == "PUT"
                        and re.fullmatch(
                            r"/v1/agents/[A-Za-z0-9_-]{1,80}/detections/handling", path
                        )
                    )
                    or (
                        event.get("httpMethod") in {"PUT", "POST"}
                        and (path == "/v1/cases" or path.startswith("/v1/cases/"))
                    )
                )
            ):
                raise FleetError("fleet_triage_only", 403)
            if (
                access == "observer"
                and event.get("httpMethod") != "GET"
                and path != "/v1/fleet/read"
                and not re.fullmatch(
                    r"/v1/agents/[A-Za-z0-9_-]{1,80}/delivery/[A-Za-z0-9_-]{1,64}(?:/(read|ack))?",
                    path,
                )
            ):
                raise FleetError("fleet_read_only", 403)
            if (
                path == "/v1/agents"
                and event.get("httpMethod") == "POST"
                and access != "administrator"
            ):
                raise FleetError("registration_requires_administrator", 403)
            parts = path.split("/")
            params = dict(event.get("pathParameters") or {})
            if len(parts) > 3 and parts[2] == "agents":
                params["agent_id"] = parts[3]
                if len(parts) > 5 and parts[4] == "api":
                    params["proxy"] = "/".join(parts[5:])
                if (
                    len(parts) == 4
                    and event.get("httpMethod") == "PUT"
                    and access != "administrator"
                ):
                    raise FleetError("registration_requires_administrator", 403)
            event = {**event, "path": path, "pathParameters": params}
        if not access and os.getenv("CASE_TABLE_NAME"):
            from ._contracts.delegation import require_assertion

            try:
                require_assertion(
                    store.client,
                    os.environ["CASE_TABLE_NAME"],
                    event.get("requestContext", {}).get("identity", {}),
                    event.get("httpMethod"),
                    event.get("path", ""),
                )
            except CaseError as error:
                return response(error.status, {"code": error.code})
            if event.get("path") == "/v1/delegated" or event.get("path", "").startswith(
                "/v1/identity/"
            ):
                from .identity import handle

                return handle(event, context, api, store=store)
        code, payload = dispatch(event, store)
        LOG.info(
            json.dumps(
                {
                    "operation": "api",
                    "request_id": context.aws_request_id,
                    "method": event.get("httpMethod"),
                    "status_code": code,
                    "caller": event["requestContext"]["identity"]["userArn"],
                    "route": event.get("resource"),
                }
            )
        )
        return response(code, payload)
    except (FleetError, CaseError) as error:
        return response(
            error.status, {"error_code": error.code, "request_id": context.aws_request_id}
        )
    except Exception:
        LOG.error("api_internal_error request_id=%s", context.aws_request_id)
        return response(500, {"error_code": "internal_error", "request_id": context.aws_request_id})


def schedule(event, context):
    check_account(context)
    store, cursor, count = Store(), None, 0
    sequence = int(time.time() // 60) * 60_000
    while True:
        items, cursor = store.agents(50, cursor)
        enabled = [item for item in items if item["enabled"]]
        store.enqueue_many(enabled, sequence)
        count += len(enabled)
        if not cursor:
            break
    LOG.info("polls_queued=%d", count)
    return {"queued": count}


def worker(event, context):
    check_account(context)
    store, failures = Store(), []
    for record in event.get("Records", []):
        try:
            message = json.loads(record["body"])
            agent_id(message["agent_id"])
            for field in ("rev", "sequence"):
                if (
                    isinstance(message[field], bool)
                    or not isinstance(message[field], int)
                    or message[field] < 1
                ):
                    raise FleetError("invalid_poll_message")
            if message["sequence"] > time.time() * 1000 + 60_000:
                raise FleetError("invalid_poll_message")
            result = poll(store, message)
            LOG.info("agent_id=%s poll=%s", message["agent_id"], result)
        except Exception:
            LOG.error("poll_worker_failure message_id=%s", record["messageId"])
            failures.append({"itemIdentifier": record["messageId"]})
    return {"batchItemFailures": failures}


def rollout_worker(event, context):
    from .rollouts import Rollouts

    check_account(context)
    rollouts, failures = Rollouts(Store()), []
    for record in event.get("Records", []):
        try:
            message = json.loads(record["body"])
            rollouts.execute(message["rollout_id"], agent_id(message["agent_id"]))
        except Exception:
            LOG.error("rollout_worker_failure message_id=%s", record["messageId"])
            failures.append({"itemIdentifier": record["messageId"]})
    return {"batchItemFailures": failures}


def detection_schedule(event, context):
    from .detections import policy

    check_account(context)
    if os.getenv("DETECTION_POLLING_ENABLED", "true") != "true":
        return {"queued": 0}
    interval, _ = policy()
    store, cursor, count = Store(), None, 0
    sequence = int(time.time() // interval) * interval * 1000
    while True:
        items, cursor = store.agents(50, cursor)
        enabled = [item for item in items if item["enabled"] and item.get("auth_mode") == "iam"]
        store.enqueue_many(enabled, sequence, queue_url=os.environ["DETECTION_QUEUE_URL"])
        count += len(enabled)
        if not cursor:
            break
    LOG.info("detection_polls_queued=%d", count)
    return {"queued": count}


def detection_worker(event, context):
    from .detections import collect_detections

    check_account(context)
    store, failures = Store(), []
    for record in event.get("Records", []):
        try:
            message = json.loads(record["body"])
            agent_id(message["agent_id"])
            if any(
                type(message[key]) is not int or message[key] < 1 for key in ("rev", "sequence")
            ):
                raise FleetError("invalid_detection_poll_message")
            if message["sequence"] > time.time() * 1000 + 60_000:
                raise FleetError("invalid_detection_poll_message")
            result = collect_detections(store, message)
            emit_detection_metrics(result)
            LOG.info("agent_id=%s detection_collection=%s", message["agent_id"], json.dumps(result))
        except Exception:
            LOG.error("detection_worker_failure message_id=%s", record["messageId"])
            failures.append({"itemIdentifier": record["messageId"]})
    return {"batchItemFailures": failures}


def emit_detection_metrics(result):
    # Only worker-generated counts/codes; never a response body, cursor or evidence.
    metrics = {
        "DetectionRecordsCollected": result.get("records", 0),
        "DetectionDeliveryLagSeconds": result.get("delivery_lag_seconds", 0),
        "DetectionBacklog": int(result.get("has_more", False)),
        "DetectionCollectionFailures": int(bool(result.get("error_code"))),
        "DetectionRetentionGaps": int(
            result.get("state") == "gap" or result.get("error_code") == "detection_retention_gap"
        ),
    }
    print(
        json.dumps(
            {
                "_aws": {
                    "Timestamp": int(time.time() * 1000),
                    "CloudWatchMetrics": [
                        {
                            "Namespace": "OpenCDR/Fleet",
                            "Dimensions": [["Stage"]],
                            "Metrics": [
                                {
                                    "Name": key,
                                    "Unit": "Seconds" if key.endswith("Seconds") else "Count",
                                }
                                for key in metrics
                            ],
                        }
                    ],
                },
                "Stage": os.environ["FLEET_STAGE"],
                **metrics,
            }
        )
    )
