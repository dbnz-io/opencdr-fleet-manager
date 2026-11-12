"""Fleet owner routing needs independent case access as well as review authority."""

import hashlib
import json
import os
import time

from test_groups import group_http as group_http_fixture
from test_groups import reviewed as reviewed_fixture
from test_groups import rollout as rollout_fixture
from test_reviewed_rollouts import A, B, cmd

from opencdr_fleet._contracts.case_api import Access
from opencdr_fleet._contracts.library_store import Library
from opencdr_fleet._evaluator.rule_release import canonical

rollout, reviewed, group_http = rollout_fixture, reviewed_fixture, group_http_fixture


def test_fleet_routing_is_case_scoped_and_retains_owner_receipt(group_http, monkeypatch):
    call, manager, service, names = group_http
    store = manager.store
    monkeypatch.setenv("LIBRARY_TABLE_NAME", os.environ["CASE_TABLE_NAME"])
    monkeypatch.setenv("LIBRARY_BUCKET", "routing-owner-fixture")
    monkeypatch.setenv("CASE_EVIDENCE_BUCKET", "routing-owner-fixture")
    store.s3.create_bucket(Bucket="routing-owner-fixture")
    library = Library(
        store.client, os.environ["CASE_TABLE_NAME"], store.s3, "routing-owner-fixture", A
    )
    item = library.create(
        cmd(700, kind="signal", runtime_id="r1", title="Routing fixture", description="")
    )["item"]
    document = {"rule_id": "r1", "rule_kind": "signal", "conditions": []}
    row = library.save_version(
        item["content_id"],
        cmd(
            701, expected_rev=1, document=document, dependencies=[], provenance={"kind": "authored"}
        ),
    )["version"]
    fingerprint = hashlib.sha256(
        json.dumps(canonical(document), sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()
    operation = {
        "kind": "routing.configure",
        "source": {k: row[k] for k in ["content_id", "version", "artifact_sha256"]},
        "policy": {
            "policy_id": "c" * 32,
            "revision": 1,
            "enabled": True,
            "mode": "join",
            "agent_ids": names[:2],
            "rule": {"kind": "signal", "rule_id": "r1", "content_sha256": fingerprint},
            "group_by": ["severity"],
            "window_seconds": 300,
            "closed_case": "new_case",
        },
    }
    body = cmd(702, operation=operation, expires_at=int(time.time()) + 1000)
    status, value = call("POST", "/reviews", body)
    assert status == 403 and value["code"] == "routing_case_authority_required", value
    access = Access(store.client, os.environ["CASE_TABLE_NAME"], A, store.get_agent)
    access.update(cmd(703, expected_rev=0, principal=A, agent_ids=names[:2]))
    status, value = call("POST", "/reviews", body)
    assert status == 200, value
    identity = value["review"]["approval_id"]
    assert (
        call(
            "POST",
            "/reviews/" + identity + "/decisions",
            cmd(704, expected_rev=1, mode="peer", approve=True),
            actor=B,
        )[0]
        == 200
    )
    status, value = call("POST", "/reviews/" + identity + "/activate", cmd(705, expected_rev=2))
    assert status == 200 and value["worker_connected"] is False, value
    assert (
        call("GET", "/reviews/" + identity + "/activation")[1]["activation"]["policy_id"]
        == "c" * 32
    )
    access.update(cmd(706, expected_rev=1, principal=A, agent_ids=[]))
    assert call("GET", "/reviews/" + identity + "/activation")[0] == 403
