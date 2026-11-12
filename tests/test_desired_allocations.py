import os
import time

import pytest
from test_groups import group_http as group_http_fixture
from test_groups import reviewed as reviewed_fixture
from test_groups import rollout as rollout_fixture
from test_reviewed_rollouts import A, B, cmd

from opencdr_fleet._contracts.library_store import Library
from opencdr_fleet._evaluator import library_evaluator

rollout, reviewed, group_http = rollout_fixture, reviewed_fixture, group_http_fixture


@pytest.fixture
def desired(group_http, monkeypatch):
    call, manager, _, names = group_http
    monkeypatch.setenv("LIBRARY_TABLE_NAME", os.environ["CASE_TABLE_NAME"])
    monkeypatch.setenv("LIBRARY_BUCKET", "allocation-fixture")
    manager.store.s3.create_bucket(Bucket="allocation-fixture")
    library = Library(
        manager.store.client,
        os.environ["CASE_TABLE_NAME"],
        manager.store.s3,
        "allocation-fixture",
        A,
        evaluator=library_evaluator,
    )
    head = library.create(
        cmd(700, kind="signal", runtime_id="fixture", title="Fixture", description="")
    )["item"]
    row = library.save_version(
        head["content_id"],
        cmd(
            701,
            expected_rev=1,
            document={
                "rule_id": "fixture",
                "rule_kind": "signal",
                "description": "Fixture",
                "enabled": False,
                "notify": False,
                "severity": "HIGH",
                "response_module": "",
                "conditions": [{"field": "activity_name", "op": "equals", "value": "Fixture"}],
            },
            dependencies=[],
            provenance={"kind": "authored"},
        ),
    )["version"]
    release = library.freeze(
        cmd(
            702,
            title="Fixture",
            description="",
            items=[{k: row[k] for k in ["content_id", "version", "artifact_sha256"]}],
        )
    )["release"]
    record = library.compile_release(
        release["release_id"], cmd(703, artifact_sha256=release["artifact_sha256"])
    )["record"]
    assert record["valid"]
    reference = {k: record[k] for k in ["release_id", "compilation_id", "artifact_sha256"]}
    operation = {
        "kind": "group.configure",
        "group_id": "desired-canary",
        "expected_rev": 0,
        "group": {
            "kind": "allocation",
            "title": "Canary desired package",
            "enabled": True,
            "agent_ids": names[:2],
            "desired": reference,
        },
    }
    return call, library, operation


def test_allocation_is_verified_reviewed_and_does_not_dispatch(desired):
    call, _, operation = desired
    status, value = call(
        "POST", "/reviews", cmd(710, operation=operation, expires_at=int(time.time()) + 1000)
    )
    assert status == 200, value
    identity = value["review"]["approval_id"]
    assert (
        call(
            "POST",
            "/reviews/" + identity + "/decisions",
            cmd(711, expected_rev=1, approve=True, mode="peer"),
            actor=B,
        )[0]
        == 200
    )
    assert call("POST", "/reviews/" + identity + "/execute", cmd(712, expected_rev=2))[0] == 200
    status, value = call("GET", "/v1/groups/desired-canary")
    assert status == 200 and value["group"]["kind"] == "allocation"
    assert value["group"]["desired"] == operation["group"]["desired"]
    assert (
        call("POST", "/v1/groups/desired-canary/resolve", {"expected_rev": 1})[1][
            "dispatch_allowed"
        ]
        is False
    )


def test_changed_compilation_bytes_cannot_be_allocated(desired):
    call, library, operation = desired
    desired = operation["group"]["desired"]
    row = library.required("COMPILE#" + desired["release_id"], desired["compilation_id"])
    library.s3.put_object(Bucket=library.bucket, Key=row["artifact_key"], Body=b"{}")
    status, value = call(
        "POST", "/reviews", cmd(720, operation=operation, expires_at=int(time.time()) + 1000)
    )
    assert status == 502 and value["code"] == "library_artifact_integrity_failure", value


def test_allocation_frozen_scope_and_exact_target_content(
    desired, group_http, reviewed, monkeypatch
):
    from copy import deepcopy

    from opencdr_fleet._contracts.case_contract import CaseError
    from opencdr_fleet._contracts.case_store import digest
    from opencdr_fleet.desired_allocations import check_target

    test_allocation_is_verified_reviewed_and_does_not_dispatch(desired)
    call, library, operation = desired
    manager, helper, core, _, names, _ = reviewed
    targets = [{"agent_id": name, "approval_id": "1" * 32, "expected_rev": 2} for name in names[:2]]
    result = helper.plan(
        cmd(740, targets=targets, allocation={"group_id": "desired-canary", "expected_rev": 1})
    )
    identity = result["rollout_id"]
    meta = manager.get(identity)
    allocation = meta["allocation"]
    compiled = library.artifact(
        library.required(
            "COMPILE#" + operation["group"]["desired"]["release_id"],
            operation["group"]["desired"]["compilation_id"],
        )
    )
    manifest = compiled["rule_manifest"]
    binding = {
        "plan": {"operation": "release.apply", "content_sha256": digest(manifest)},
        "material": {"content": manifest},
    }
    check_target(allocation, binding)
    altered = deepcopy(binding)
    altered["material"]["content"]["rules"][0]["enabled"] = True
    altered["plan"]["content_sha256"] = digest(altered["material"]["content"])
    with pytest.raises(CaseError, match="allocation_release_mismatch"):
        check_target(allocation, altered)
    with pytest.raises(CaseError, match="allocation_scope_or_revision_changed"):
        helper.plan(
            cmd(
                741,
                targets=targets[:1],
                allocation={"group_id": "desired-canary", "expected_rev": 1},
            )
        )
    with pytest.raises(CaseError, match="allocation_core_material_unverified"):
        helper.prepare(identity, {})
    assert not core.sent
    # A later membership update cannot expand the already frozen job.
    manager.store.cache.update_item(
        Key={"pk": "FLEET_GROUP#" + helper.reviews().namespace, "sk": "desired-canary"},
        UpdateExpression="SET rev=:rev, agent_ids=:names",
        ExpressionAttributeValues={":rev": 2, ":names": names},
    )
    assert manager.get(identity)["agent_ids"] == sorted(names[:2])
