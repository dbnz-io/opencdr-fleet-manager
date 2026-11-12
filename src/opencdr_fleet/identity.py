"""Trusted human delegation; grants live with the Fleet management owner."""

import json
import os

from ._contracts.case_contract import CaseError, iam_principal
from ._contracts.delegation import CURRENT, authorize, scope_operation, using
from ._contracts.identity_store import Identities, dispatch
from .api import body, response
from .store import Store


def handle(event, context, callback, *, store=None):
    try:
        configured = os.getenv("FLEET_MANAGEMENT_ACCESS")
        access = configured or "administrator"
        prefix = "/management/" + configured if configured else ""
        path = event.get("path", "")[len(prefix) :]
        method = event.get("httpMethod")
        table = os.getenv("CASE_TABLE_NAME")
        if not table:
            raise CaseError("identity_capability_unavailable", 503)
        store = store if store is not None else Store()
        caller = iam_principal(event.get("requestContext", {}).get("identity", {}))
        payload, query = body(event), event.get("queryStringParameters") or {}
        owner = {
            "account_id": os.environ["SECURITY_ACCOUNT_ID"],
            "home_region": os.getenv("AWS_REGION", os.getenv("AWS_DEFAULT_REGION")),
            "stage": os.environ["FLEET_STAGE"],
        }
        if path == "/v1/delegated":
            if (
                method != "POST"
                or query
                or CURRENT.get()
                or access not in {"observer", "triage", "operator", "responder", "administrator"}
            ):
                raise CaseError("delegation_entrypoint_forbidden", 403)
            authority = authorize(
                store.client, table, payload, owner=owner, transport_principal=caller
            )
            op = scope_operation(authority, payload["operation"])
            if not op["path"].startswith("/v1/"):
                raise CaseError("delegation_entrypoint_forbidden", 403)
            translated = {
                **event,
                "httpMethod": op["method"],
                "path": prefix + op["path"],
                "queryStringParameters": op["query"],
                "pathParameters": {},
                "isBase64Encoded": False,
                "body": json.dumps(op["body"]),
            }
            with using(authority):
                result = callback(translated, context)
                if op["method"] == "GET":
                    authority.fresh()
                return result
        value = dispatch(
            Identities(store.client, table, caller, store.get_agent),
            access,
            method,
            path[3:],
            payload,
            query,
        )
        return response(200, {**value, "deployment": owner})
    except CaseError as error:
        return response(error.status, {"code": error.code})
    except (ValueError, TypeError):
        return response(400, {"code": "invalid_identity_request"})
