"""Reviewed owner groups stay independent of immutable distribution selections."""

import json
import time

import pytest
from test_reviewed_rollouts import A, B, cmd
from test_reviewed_rollouts import reviewed as reviewed_fixture
from test_reviewed_rollouts import rollout as rollout_fixture

from opencdr_fleet import api, approvals
from opencdr_fleet.groups import Groups
from opencdr_fleet.models import FleetError

reviewed, rollout = reviewed_fixture, rollout_fixture


@pytest.fixture
def group_http(reviewed, monkeypatch):
    manager, _, _, service, names, _ = reviewed
    for n, principal in enumerate([A, B], 100):
        service().dispatch(
            "PUT",
            "/review-grants/" + principal,
            cmd(
                n,
                expected_rev=1,
                grant={
                    "enabled": True,
                    "expires_at": int(time.time()) + 3600,
                    "permissions": ["approve", "mutate", "policy_admin"],
                    "operations": ["package.apply", "configuration.write"],
                    "target_ids": names,
                },
            ),
            {},
        )
    service().dispatch(
        "PUT",
        "/review-policy",
        cmd(
            102,
            expected_rev=1,
            policy={
                "reviewers": [B],
                "allow_self_if_sole": False,
                "emergency_actors": [],
                "max_lifetime_seconds": 3600,
                "operations": ["configuration.write", "package.apply"],
            },
        ),
        {},
    )

    def call(method, path, body=None, actor=A):
        identity = {
            "userArn": "arn:aws:sts::123456789012:assumed-role/test/session",
            "caller": actor.split(":")[-1] + ":session",
        }
        if path.startswith("/v1/groups"):
            return api.dispatch(
                {
                    "httpMethod": method,
                    "path": path,
                    "requestContext": {"identity": identity},
                    "body": json.dumps(body or {}),
                },
                manager.store,
            )
        return approvals.handle(manager.store, method, path, body or {}, {}, identity)

    return call, manager, service, names


def configure(group_http, names=None, rev=0, number=110):
    call, _, _, all_names = group_http
    names = names or all_names[:2]
    operation = {
        "kind": "group.configure",
        "group_id": "canary",
        "expected_rev": rev,
        "group": {"title": "Canary ring", "kind": "ring", "enabled": True, "agent_ids": names},
    }
    code, value = call(
        "POST", "/reviews", cmd(number, operation=operation, expires_at=int(time.time()) + 1000)
    )
    assert code == 200, value
    approval = value["review"]["approval_id"]
    code, value = call(
        "POST",
        "/reviews/" + approval + "/decisions",
        cmd(number + 1, expected_rev=1, mode="peer", approve=True),
        actor=B,
    )
    assert code == 200, value
    code, value = call("POST", "/reviews/" + approval + "/execute", cmd(number + 2, expected_rev=2))
    assert code == 200, value
    return approval, value


def test_reviewed_group_supports_100_members_and_retains_versions(group_http):
    call, manager, service, names = group_http
    identity, result = configure(group_http, names)
    assert result["execution"]["group_rev"] == 1
    code, selected = call("POST", "/v1/groups/canary/resolve", {"expected_rev": 1})
    assert code == 200 and len(selected["targets"]) == 100 and selected["dispatch_allowed"] is False
    first_snapshot = selected["selection_sha256"]
    configure(group_http, names[:2], rev=1, number=120)
    code, selected = call("POST", "/v1/groups/canary/resolve", {"expected_rev": 2})
    assert (
        code == 200
        and len(selected["targets"]) == 2
        and selected["selection_sha256"] != first_snapshot
    )
    assert call("GET", "/reviews/" + identity + "/verification")[1]["stored_matches"] is False
    groups = Groups(manager.store, service().reviews)
    assert manager.store.cache.get_item(
        Key={"pk": groups.partition + "#VERSION#canary", "sk": "000000000001"}
    )["Item"]["agent_ids"] == sorted(names)


def test_direct_membership_write_and_stale_resolution_denied(group_http):
    call, _, _, _ = group_http
    configure(group_http)
    with pytest.raises(FleetError, match="reviewed_group"):
        call("PUT", "/v1/groups/canary", {"agent_ids": ["account-a"]})
    with pytest.raises(Exception, match="group_disabled_or_changed"):
        call("POST", "/v1/groups/canary/resolve", {"expected_rev": 2})


def test_group_edit_does_not_expand_existing_rollout(group_http):
    call, manager, _, names = group_http
    configure(group_http, names[:2])
    selected = call("POST", "/v1/groups/canary/resolve", {"expected_rev": 1})[1]
    planned = manager.plan(
        cmd(
            200,
            targets=[
                {"agent_id": t["agent_id"], "approval_id": "1" * 32, "expected_rev": 2}
                for t in selected["targets"]
            ],
        )
    )
    configure(group_http, names[:4], rev=1, number=210)
    assert manager.get(planned["rollout_id"])["agent_ids"] == sorted(names[:2])


def test_removed_members_still_require_editor_authority(group_http):
    call, _, service, names = group_http
    configure(group_http, names[:2])
    service().dispatch(
        "PUT",
        "/review-grants/" + A,
        cmd(
            220,
            expected_rev=2,
            grant={
                "enabled": True,
                "expires_at": int(time.time()) + 3600,
                "permissions": ["approve", "mutate", "policy_admin"],
                "operations": ["configuration.write"],
                "target_ids": [names[0]],
            },
        ),
        {},
    )
    code, _ = call("GET", "/reviews")
    assert code == 200
    operation = {
        "kind": "group.configure",
        "group_id": "canary",
        "expected_rev": 1,
        "group": {"title": "Narrow", "kind": "ring", "enabled": True, "agent_ids": [names[0]]},
    }
    code, result = call(
        "POST", "/reviews", cmd(221, operation=operation, expires_at=int(time.time()) + 1000)
    )
    assert code == 403, result


def test_group_listing_rechecks_one_authority_epoch(group_http, monkeypatch):
    _, manager, service, _ = group_http
    configure(group_http)
    groups = Groups(manager.store, service().reviews)
    original = groups.visible

    def revoke_after_visible(row, **kwargs):
        allowed = original(row, **kwargs)
        service().dispatch(
            "PUT",
            "/review-grants/" + A,
            cmd(
                250,
                expected_rev=2,
                grant={
                    "enabled": False,
                    "expires_at": int(time.time()) + 1000,
                    "permissions": ["mutate"],
                    "operations": ["configuration.write"],
                    "target_ids": row["agent_ids"],
                },
            ),
            {},
        )
        return allowed

    monkeypatch.setattr(groups, "visible", revoke_after_visible)
    with pytest.raises(Exception, match="authority_changed"):
        groups.listing({})
