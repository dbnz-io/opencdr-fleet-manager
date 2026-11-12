"""Fleet-owned reviews; never trust forwarded actor or plan fields."""

import os
import re

import boto3
from botocore.config import Config

from ._contracts.approval_api import ReviewAPI
from ._contracts.case_contract import CaseError


def handle(store, method, path, body, query, identity, *, prepare=None):
    owner = {
        "account_id": os.environ["SECURITY_ACCOUNT_ID"],
        "home_region": os.getenv("AWS_REGION", os.getenv("AWS_DEFAULT_REGION")),
        "stage": os.environ["FLEET_STAGE"],
    }
    try:
        if not os.getenv("CASE_TABLE_NAME"):
            return 503, {"code": "review_capability_unavailable", "deployment": owner}
        scope = ":".join(owner[k] for k in ("account_id", "home_region", "stage"))
        from ._contracts.case_contract import iam_principal
        from ._contracts.delegation import delegated_actor
        from .reviewed_rollouts import ReviewedRollouts
        from .rollouts import Rollouts

        principal = delegated_actor() or iam_principal(identity)
        service = ReviewAPI(
            boto3.client(
                "dynamodb",
                config=Config(connect_timeout=2, read_timeout=3, retries={"total_max_attempts": 1}),
            ),
            os.environ["CASE_TABLE_NAME"],
            scope,
            identity,
            os.getenv("FLEET_MANAGEMENT_ACCESS", "administrator"),
            store.get_agent,
            prepare=prepare or (lambda operation: trusted_prepare(operation)),
        )

        def case_compiler():
            from ._contracts.case_mutations import CaseMutations
            from .routing_owner import service as routing_service

            return CaseMutations(routing_service(store, service.reviews))

        def compile_selected(operation, actor):
            if isinstance(operation, dict) and operation.get("kind") in {
                "case.merge",
                "case.duplicate",
            }:
                return case_compiler().compile(operation, actor)
            return Groups(store, service.reviews).compile(operation, actor)

        def trusted_prepare(operation):
            if isinstance(operation, dict) and operation.get("kind") in {
                "case.merge",
                "case.duplicate",
            }:
                return case_compiler().prepare(operation)
            if isinstance(operation, dict) and operation.get("kind") == "routing.configure":
                from .routing_owner import service as routing_service

                return routing_service(store, service.reviews).prepare(operation)
            if isinstance(operation, dict) and operation.get("kind") == "group.configure":
                from .groups import Groups

                return Groups(store, service.reviews).prepare(operation)
            return ReviewedRollouts(Rollouts(store, authenticated_actor=principal)).proposal(
                operation
            )

        activation = re.fullmatch(r"/reviews/([a-f0-9]{32})/(activate|activation|drain)", path)
        if activation:
            from ._contracts.approval_contract import require
            from .reviewed_rollouts import enforced
            from .routing_owner import service as routing_service

            require(not query, "invalid_routing_activation")
            routing = routing_service(store, service.reviews)
            if method == "GET" and activation[2] == "activation":
                result = routing.activation(activation[1])
            else:
                require(
                    method == "POST" and activation[2] in {"activate", "drain"},
                    "method_not_allowed",
                    405,
                )
                require(
                    enforced() and service.tier in {"operator", "responder", "administrator"},
                    "routing_activation_forbidden",
                    403,
                )
                result = (routing.drain if activation[2] == "drain" else routing.activate)(
                    activation[1], body
                )
            return 200, {**result, "deployment": owner}

        match = re.fullmatch(r"/reviews/([a-f0-9]{32})/(execute|execution|verification)", path)
        if match:
            from ._contracts.approval_contract import require
            from ._contracts.case_store import digest
            from ._contracts.mutation_execution import Mutations
            from .groups import Groups
            from .reviewed_rollouts import enforced

            require(not query, "invalid_review_execution")
            groups = Groups(store, service.reviews)
            runner = Mutations(service.reviews, compile_selected)
            if method == "GET" and match[2] == "execution":
                result = runner.read(match[1])
            elif method == "GET" and match[2] == "verification":
                execution = runner.read(match[1])["execution"]
                if execution and execution.get("kind") == "case_merge":
                    return 200, {**case_compiler().verify(execution), "deployment": owner}
                require(
                    execution and execution.get("kind") == "fleet_group",
                    "group_execution_not_found",
                    404,
                )
                current = groups.get(execution["group_id"])
                service.reviews.authority.fences()
                result = {
                    "stored_matches": digest(current) == execution["group_sha256"],
                    "runtime_activation": "not_applicable",
                }
            else:
                require(method == "POST" and match[2] == "execute", "method_not_allowed", 405)
                require(enforced(), "reviewed_execution_not_enabled", 503)
                require(
                    service.tier in {"operator", "responder", "administrator"},
                    "review_write_access_required",
                    403,
                )
                result = runner.execute(match[1], body)
            return 200, {**result, "deployment": owner}
        return 200, {**service.dispatch(method, path, body, query), "deployment": owner}
    except CaseError as error:
        return error.status, {"code": error.code, "deployment": owner}
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        return 400, {"code": "invalid_review_request", "deployment": owner}
