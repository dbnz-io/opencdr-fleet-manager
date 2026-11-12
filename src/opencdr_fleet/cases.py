"""Organization-local operational cases; no Core HTTP requests or caller-chosen grants."""

import os

from ._contracts.case_api import Access, dispatch
from ._contracts.case_contract import CaseError, principal
from ._contracts.case_store import Cases
from ._contracts.delegation import CURRENT
from .detection_queries import handle as detection_detail


def installed():
    return bool(os.getenv("CASE_TABLE_NAME") and os.getenv("CASE_EVIDENCE_BUCKET"))


def handle(store, method, path, body, query, identity):
    owner = {
        "account_id": os.environ["SECURITY_ACCOUNT_ID"],
        "home_region": os.getenv("AWS_REGION", os.getenv("AWS_DEFAULT_REGION")),
        "stage": os.environ["FLEET_STAGE"],
    }
    if not installed():
        return 503, {"code": "capability_unavailable", "deployment": owner}
    try:
        tier = os.getenv("FLEET_MANAGEMENT_ACCESS", "administrator")
        actor = principal(identity)
        if path.startswith("/case-integrations/") or path.endswith("/external-status"):
            from ._contracts.case_integrations import handle as integration

            result = integration(
                store.client,
                os.environ["CASE_TABLE_NAME"],
                actor,
                tier,
                store.get_agent,
                method,
                path,
                body,
                query,
            )
            return 200, {**result, "deployment": owner}
        if tier not in {"observer", "triage", "operator", "responder", "administrator"} or (
            method != "GET" and tier == "observer"
        ):
            raise CaseError("case_iam_triage_required", 403)
        actor = principal(identity)
        table, bucket = os.environ["CASE_TABLE_NAME"], os.environ["CASE_EVIDENCE_BUCKET"]
        access = Access(store.client, table, actor, store.get_agent)
        delegated = CURRENT.get()
        if path == "/case-access":
            if delegated:
                if method != "GET" or query:
                    raise CaseError("case_access_administrator_required", 403)
                return 200, {
                    "deployment": owner,
                    "access": {
                        "principal": actor,
                        "agent_ids": sorted(delegated.agents),
                        "rev": delegated.subject_revision,
                    },
                }
            if method == "GET" and not set(query) - {"principal"}:
                target = query.get("principal", actor)
                if target != actor and tier != "administrator":
                    raise CaseError("case_access_administrator_required", 403)
                result = {"access": access.read(target)}
            elif method == "PUT" and not query:
                if tier != "administrator":
                    raise CaseError("case_access_administrator_required", 403)
                result = access.update(body)
            else:
                raise CaseError("method_not_allowed", 405)
        else:
            grant = (
                {"agent_ids": sorted(delegated.agents), "rev": None}
                if delegated
                else access.read(actor)
            )
            if not grant["agent_ids"]:
                raise CaseError("case_account_grant_required", 403)

            def resolve(name, detection_id):
                registered = store.get_agent(name)
                code, value = detection_detail(
                    "/v1/detections/detail", {"agent_id": name, "detection_id": detection_id}, store
                )
                if code != 200:
                    raise CaseError("case_source_unavailable", code)
                if any(
                    value["item"][key] != registered[key]
                    for key in ("account_id", "region", "stage")
                ):
                    raise CaseError("case_evidence_identity_mismatch", 502)
                return value

            cases = Cases(
                store.client,
                table,
                store.s3,
                bucket,
                actor,
                grant["agent_ids"],
                resolve,
                grant_rev=grant["rev"],
                routing_owner=":".join(owner[k] for k in ("account_id", "home_region", "stage")),
            )
            if tier in {"operator", "responder", "administrator"} and os.getenv(
                "LIBRARY_TABLE_NAME"
            ):
                from ._contracts.case_tuning import TuningLibrary
                from ._evaluator.rule_release import canonical

                cases.tuning_library = TuningLibrary(
                    cases, os.environ["LIBRARY_TABLE_NAME"], os.environ["LIBRARY_BUCKET"], canonical
                )
            result = dispatch(cases, method, path, body, query)
        return 200, {**result, "deployment": owner}
    except CaseError as error:
        return error.status, {"code": error.code, "deployment": owner}
    except (ValueError, TypeError, OverflowError):
        return 400, {"code": "invalid_case_request", "deployment": owner}
