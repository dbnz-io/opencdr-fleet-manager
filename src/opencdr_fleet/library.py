"""Customer-wide Fleet library. Never forwards authoring to a member Core."""

import os

from ._contracts.case_contract import CaseError, principal
from ._contracts.library_api import dispatch
from ._contracts.library_store import Library
from ._evaluator import library_evaluator


def handle(store, method, path, body, query, identity):
    owner = {
        "account_id": os.environ["SECURITY_ACCOUNT_ID"],
        "home_region": os.getenv("AWS_REGION", os.getenv("AWS_DEFAULT_REGION")),
        "stage": os.environ["FLEET_STAGE"],
    }
    if not os.getenv("LIBRARY_TABLE_NAME") or not os.getenv("LIBRARY_BUCKET"):
        return 503, {"code": "capability_unavailable", "deployment": owner}
    try:
        tier = os.getenv("FLEET_MANAGEMENT_ACCESS", "administrator")
        if tier not in {"observer", "triage", "operator", "responder", "administrator"} or (
            method != "GET" and tier not in {"operator", "responder", "administrator"}
        ):
            return 403, {"code": "library_iam_access_required", "deployment": owner}
        library = Library(
            store.client,
            os.environ["LIBRARY_TABLE_NAME"],
            store.s3,
            os.environ["LIBRARY_BUCKET"],
            principal(identity),
            evaluator=library_evaluator,
            runtime_reader=lambda head, source, revision: runtime_source(
                store, head, source, revision
            ),
        )
        return 200, {**dispatch(library, method, path, body, query), "deployment": owner}
    except CaseError as error:
        return error.status, {"code": error.code, "deployment": owner}
    except (ValueError, TypeError, OverflowError, RecursionError):
        return 400, {"code": "invalid_library_request", "deployment": owner}


def runtime_source(store, head, source_deployment, source_revision):
    import hashlib
    import json
    import time

    from ._contracts.delegation import CURRENT
    from ._contracts.library_contract import LibraryError

    authority = CURRENT.get()
    if authority and source_deployment not in authority.agents:
        raise LibraryError("library_runtime_source_forbidden", 403)
    item = store.get_agent(source_deployment)
    view = store.view_status(item)
    state = view["observation"] or {}
    if view["configuration_stale"] or state.get("snapshot_registration_rev") != item["rev"]:
        raise LibraryError("library_runtime_snapshot_stale", 409)
    if state.get("snapshot_generation") != source_revision:
        raise LibraryError("library_runtime_source_changed", 409)
    store.manifest(source_deployment, source_revision)
    resource = (
        "list:" + head["runtime_id"]
        if head["kind"] == "list"
        else "rule:" + head["kind"] + ":" + head["runtime_id"]
    )
    pk = source_deployment + "#" + source_revision
    meta = store.cache.get_item(Key={"pk": pk, "sk": "META#" + resource}, ConsistentRead=True).get(
        "Item"
    )
    if not meta or int(meta["expires_at"]) <= int(time.time()):
        raise LibraryError("library_runtime_source_missing", 410)
    if int(meta["parts"]) != 1:
        raise LibraryError("library_source_too_large", 413)
    row = store.cache.get_item(
        Key={"pk": pk, "sk": "DATA#" + resource + "#0000"}, ConsistentRead=True
    ).get("Item")
    if not row or hashlib.sha256(row["payload"].encode()).hexdigest() != meta["sha256"]:
        raise LibraryError("library_runtime_source_integrity", 502)
    document = json.loads(row["payload"])
    # Recheck the registration and generation after reading cached bytes.
    if (
        store.get_agent(source_deployment)["rev"] != item["rev"]
        or store.get_status(source_deployment).get("snapshot_generation") != source_revision
    ):
        raise LibraryError("library_runtime_source_changed", 409)
    return {"document": document, "observed_at": state["configuration_verified_at"]}
