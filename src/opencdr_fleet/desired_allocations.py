"""Verified desired compilation references; allocation does not dispatch a rollout."""

import os

from ._contracts.approval_contract import require
from ._contracts.case_contract import identifier
from ._contracts.case_store import digest
from ._contracts.library_store import Library
from ._evaluator import library_evaluator


def resolve(store, principal, desired):
    require(
        isinstance(desired, dict)
        and set(desired) == {"release_id", "compilation_id", "artifact_sha256"},
        "invalid_desired_compilation",
    )
    identifier(desired["release_id"])
    identifier(desired["compilation_id"])
    library = Library(
        store.client,
        os.environ["LIBRARY_TABLE_NAME"],
        store.s3,
        os.environ["LIBRARY_BUCKET"],
        principal,
        evaluator=library_evaluator,
    )
    row = library.required("COMPILE#" + desired["release_id"], desired["compilation_id"])
    require(
        row["artifact_sha256"] == desired["artifact_sha256"],
        "desired_compilation_digest_mismatch",
        409,
    )
    artifact = library.artifact(row)
    require(
        artifact.get("valid") is True and artifact.get("release_id") == desired["release_id"],
        "desired_compilation_invalid",
        409,
    )
    source = library.required("RELEASE", desired["release_id"])
    require(
        artifact["source_artifact_sha256"] == source["artifact_sha256"],
        "desired_release_changed",
        409,
    )
    library.artifact(source)
    require(
        artifact.get("evaluator", {}).get("sha256") == library.native().provenance()["sha256"],
        "desired_compilation_evaluator_changed",
        409,
    )
    return {
        "desired": desired,
        "source_artifact_sha256": source["artifact_sha256"],
        "resource_sha256": resource_digest(artifact),
        "rule_manifest_sha256": digest(artifact["rule_manifest"]),
        "has_lists": bool(artifact["lists"]),
        "compiled_content_sha256": digest(
            {"lists": artifact["lists"], "rule_manifest": artifact["rule_manifest"]}
        ),
        "dependency_order": ["lists", "rules"],
        "deployment_state": "not_requested",
    }


def resource_digest(artifact):
    resources = [
        {"resource": "list", "id": row["list_id"], "document": row} for row in artifact["lists"]
    ] + [
        {"resource": "rule", "id": row["rule_id"], "rule_kind": row["rule_kind"], "document": row}
        for row in (artifact.get("rule_manifest") or {}).get("rules", [])
    ]
    return digest(
        sorted(resources, key=lambda row: (row["resource"], row.get("rule_kind", ""), row["id"]))
    )


def check_target(allocation, binding):
    """Target revisions may differ; desired resource bytes may not."""
    fixed = binding["plan"]
    content = binding.get("material", {}).get("content")
    require(
        isinstance(content, dict) and digest(content) == fixed["content_sha256"],
        "allocation_core_material_unverified",
        409,
    )
    desired = allocation["compilation"]
    if fixed["operation"] == "release.apply":
        require(
            not desired["has_lists"] and digest(content) == desired["rule_manifest_sha256"],
            "allocation_release_mismatch",
            409,
        )
        return
    require(
        fixed["operation"] == "package.apply" and content.get("kind") == "package.apply",
        "allocation_requires_atomic_package",
        409,
    )
    changes = content.get("changes")
    require(isinstance(changes, list) and bool(changes), "allocation_package_mismatch", 409)
    resources = []
    for change in changes:
        require(
            isinstance(change, dict)
            and change.get("action") == "put"
            and change.get("resource") in {"rule", "list"},
            "allocation_package_mismatch",
            409,
        )
        resources.append({k: v for k, v in change.items() if k not in {"action", "expected_rev"}})
    actual = digest(
        sorted(resources, key=lambda row: (row["resource"], row.get("rule_kind", ""), row["id"]))
    )
    require(actual == desired["resource_sha256"], "allocation_package_mismatch", 409)
