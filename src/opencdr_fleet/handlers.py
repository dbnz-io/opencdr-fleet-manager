"""Lambda entry points. Logs contain identifiers and error codes, never API payloads."""

from __future__ import annotations

import json
import logging
import os
import time

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
        code, payload = dispatch(event, Store())
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
    except FleetError as error:
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
