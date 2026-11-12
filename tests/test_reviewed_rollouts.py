"""Use real owner approval/transaction stores with a bounded Core transport fixture."""

import time
from copy import deepcopy

import pytest
from test_rollouts import rollout as rollout_fixture

from opencdr_fleet._contracts.approval_api import ReviewAPI
from opencdr_fleet.models import FleetError
from opencdr_fleet.reviewed_rollouts import ReviewedRollouts, owner
from opencdr_fleet.rollouts import digest

rollout = rollout_fixture
A = "aws:123456789012:AROAABCDEFGHIJKLMNOP"
B = "aws:123456789012:AROAQRSTUVWXYZABCDEF"


def cmd(n, **fields):
    return {"request_id": f"{n:032x}", "reason": "Exact fixture approval", **fields}


class Core:
    def __init__(self, manager):
        self.manager = manager
        self.expires = int(time.time()) + 2400
        self.sent = []
        self.reads = []
        self.receipts = {}
        self.lose = False
        self.offline = False

    def binding(self, name):
        registration = self.manager.store.get_agent(name)
        scope = ":".join(registration[k] for k in ["account_id", "region", "stage"])
        return {
            "owner": scope,
            "plan": {
                "operation": "configuration.write",
                "content_sha256": "f" * 64,
                "dependencies_sha256": "e" * 64,
                "response_required": False,
                "targets": [
                    {
                        "target_id": scope,
                        "registration_rev": 0,
                        "snapshot_sha256": "d" * 64,
                        "expected_revisions": {"settings": 1},
                    }
                ],
            },
        }

    def agent(self, record, *args, **kwargs):
        parent = self
        name = record["agent_id"]

        class Agent:
            def verify(self):
                return {
                    "capabilities": {"reviewed_rule_releases": True, "reviewed_mutations": "1.0.0"}
                }

            def request(self, method, path, body=None, **kwargs):
                if method == "GET":
                    parent.reads.append((name, path))
                    if parent.offline:
                        raise FleetError("offline", 503)
                    if path.endswith("/execution"):
                        return 200, {"execution": parent.receipts.get(name)}
                    if path.endswith("/verification"):
                        return 200, {"stored_matches": True, "runtime_activation": "not_verified"}
                    binding = parent.binding(name)
                    return 200, {
                        "review": {
                            "approval_id": "1" * 32,
                            "state": "approved",
                            "rev": 2,
                            "expires_at": parent.expires,
                            "binding_sha256": digest(binding),
                        },
                        "binding": binding,
                    }
                assert method == "POST" and path.endswith("/execute")
                parent.sent.append((name, deepcopy(body)))
                parent.receipts[name] = {
                    "request_id": body["request_id"],
                    "binding_sha256": digest(parent.binding(name)),
                    "state": "succeeded",
                }
                if parent.lose:
                    raise FleetError("lost_ack", 502)
                return 200, {"execution": parent.receipts[name]}

        return Agent()


@pytest.fixture
def reviewed(rollout, monkeypatch):
    manager, _, legacy = rollout
    monkeypatch.setenv("FLEET_REVIEW_ENFORCEMENT", "true")
    monkeypatch.setenv("CASE_TABLE_NAME", "owner-reviews")
    manager.store.client.create_table(
        TableName="owner-reviews",
        BillingMode="PAY_PER_REQUEST",
        AttributeDefinitions=[{"AttributeName": k, "AttributeType": "S"} for k in ["pk", "sk"]],
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
    )
    monkeypatch.setenv(
        "ROLLOUT_QUEUE_URL", manager.store.sqs.create_queue(QueueName="reviewed")["QueueUrl"]
    )
    manager.actor = A
    core = Core(manager)
    manager.agent_factory = core.agent
    helper = ReviewedRollouts(manager)

    def service(principal=A):
        identity = {
            "userArn": "arn:aws:sts::123456789012:assumed-role/test/session",
            "caller": principal.split(":")[-1] + ":session",
        }
        return ReviewAPI(
            manager.store.client,
            "owner-reviews",
            owner(),
            identity,
            "administrator",
            manager.store.get_agent,
            prepare=helper.proposal,
        )

    names = ["account-a"] + [f"account-{i:03d}" for i in range(1, 100)]
    original = manager.store.get_agent("account-a")
    for i, name in enumerate(names[1:], 1):
        manager.store.registry.put_item(
            Item={
                **original,
                "id": "AGENT#" + name,
                "agent_id": name,
                "account_id": f"{i + 1000:012d}",
            }
        )
    grant = {
        "enabled": True,
        "expires_at": int(time.time()) + 3600,
        "permissions": ["mutate", "approve", "policy_admin"],
        "operations": ["package.apply"],
        "target_ids": names,
    }
    for i, principal in enumerate([A, B], 1):
        service().dispatch(
            "PUT", "/review-grants/" + principal, cmd(i, expected_rev=0, grant=grant), {}
        )
    service().dispatch(
        "PUT",
        "/review-policy",
        cmd(
            3,
            expected_rev=0,
            policy={
                "reviewers": [B],
                "allow_self_if_sole": False,
                "emergency_actors": [],
                "max_lifetime_seconds": 3600,
                "operations": ["package.apply"],
            },
        ),
        {},
    )
    return manager, helper, core, service, names, legacy


def planned(reviewed, names=None):
    manager, helper, _, _, all_names, _ = reviewed
    names = names or all_names[:1]
    result = manager.plan(
        cmd(
            10,
            targets=[
                {"agent_id": name, "approval_id": "1" * 32, "expected_rev": 2} for name in names
            ],
        )
    )
    while result["state"] == "planning":
        result = helper.prepare(result["rollout_id"], {})
    return result


def authorized(reviewed, names=None):
    manager, helper, core, service, _, _ = reviewed
    result = planned(reviewed, names)
    approval = service().dispatch(
        "POST",
        "/reviews",
        cmd(
            20,
            operation={"kind": "rollout.execute", "rollout_id": result["rollout_id"]},
            expires_at=int(time.time()) + 1200,
        ),
        {},
    )["review"]
    service(B).dispatch(
        "POST",
        "/reviews/" + approval["approval_id"] + "/decisions",
        cmd(21, expected_rev=1, approve=True, mode="peer"),
        {},
    )
    body = cmd(22, approval_id=approval["approval_id"], expected_rev=2)
    manager.enqueue(result["rollout_id"], body)
    return result, approval, body


def test_100_targets_prepare_in_bounded_pages_and_worker_preserves_scope(reviewed):
    manager, helper, core, _, names, _ = reviewed
    first = manager.plan(
        cmd(
            10,
            targets=[
                {"agent_id": name, "approval_id": "1" * 32, "expected_rev": 2} for name in names
            ],
        )
    )
    assert first["target_count"] == 100 and first["prepared_targets"] == 0 and not core.reads
    second = helper.prepare(first["rollout_id"], {})
    assert second["prepared_targets"] == 8 and len(core.reads) == 8
    result, _, _ = authorized(reviewed, names)
    # Newly registered membership is not pulled into this frozen plan.
    manager.store.registry.put_item(
        Item={**manager.store.get_agent("account-a"), "id": "AGENT#later", "agent_id": "later"}
    )
    for name in names:
        assert manager.execute(result["rollout_id"], name) == "succeeded"
    assert len(core.sent) == 100 and {name for name, _ in core.sent} == set(names)
    assert manager.execute(result["rollout_id"], names[0]) == "already_claimed"
    assert manager.status(result["rollout_id"])["complete"]


def test_unknown_outcome_is_read_only_reconciled_not_replayed(reviewed):
    manager, helper, core, _, _, _ = reviewed
    result, _, _ = authorized(reviewed)
    identity = result["rollout_id"]
    core.lose = True
    assert manager.execute(identity, "account-a") == "unknown"
    assert manager.execute(identity, "account-a") == "already_claimed"
    reconciled = helper.reconcile(identity, "account-a")
    assert reconciled["state"] == "succeeded" and not reconciled["retry_allowed"]
    assert reconciled["verification"]["runtime_activation"] == "not_verified"
    assert len(core.sent) == 1


def test_revocation_and_expired_queued_authority_prevent_dispatch(reviewed):
    manager, helper, core, service, _, _ = reviewed
    result, approval, _ = authorized(reviewed)
    service(B).dispatch(
        "POST", "/reviews/" + approval["approval_id"] + "/withdrawals", cmd(23, expected_rev=2), {}
    )
    assert manager.execute(result["rollout_id"], "account-a") == "blocked"
    target = manager.get(result["rollout_id"], "TARGET#account-a")
    assert target["error_code"] == "approval_not_approved" and not target["dispatch_attempted"]
    assert core.sent == []


def test_cancellation_is_fenced_and_never_undoes_sent_targets(reviewed):
    manager, _, core, _, names, _ = reviewed
    result, _, _ = authorized(reviewed, names[:2])
    identity = result["rollout_id"]
    assert manager.execute(identity, names[0]) == "succeeded"
    manager.cancel(identity, cmd(30, review_digest=result["review_digest"]), authenticated_actor=A)
    assert manager.execute(identity, names[1]) == "cancelled"
    assert len(core.sent) == 1
    status = manager.status(identity)
    assert {t["state"] for t in status["targets"]} == {"succeeded", "cancelled"}


def test_registration_changes_and_legacy_queue_cannot_bypass_review(reviewed):
    manager, helper, core, _, _, legacy = reviewed
    result, _, _ = authorized(reviewed)
    manager.store.registry.update_item(
        Key={"id": "AGENT#account-a"},
        UpdateExpression="SET rev = :rev",
        ExpressionAttributeValues={":rev": 2},
    )
    assert manager.execute(result["rollout_id"], "account-a") == "blocked"
    assert (
        "registration_changed"
        in manager.get(result["rollout_id"], "TARGET#account-a")["error_code"]
    )
    assert not core.sent
    with pytest.raises(FleetError, match="legacy_rollout_requires_new_review"):
        manager.execute(legacy["rollout_id"], "account-a")


def test_offline_read_before_claim_is_retryable_and_no_unknown_write_replayed(reviewed):
    manager, _, core, _, _, _ = reviewed
    result, _, _ = authorized(reviewed)
    core.offline = True
    with pytest.raises(FleetError, match="offline"):
        manager.execute(result["rollout_id"], "account-a")
    assert (
        manager.get(result["rollout_id"], "TARGET#account-a")["state"] == "planned"
        and not core.sent
    )
    core.offline = False
    assert manager.execute(result["rollout_id"], "account-a") == "succeeded"


def test_expired_queued_lifetime_is_durable_blocked_not_dispatched(reviewed):
    manager, _, core, _, _, _ = reviewed
    result, _, _ = authorized(reviewed)
    manager.table.update_item(
        Key={"pk": result["rollout_id"], "sk": "META"},
        UpdateExpression="SET #auth.expires_at = :expired",
        ExpressionAttributeNames={"#auth": "authorization"},
        ExpressionAttributeValues={":expired": int(time.time()) - 1},
    )
    assert manager.execute(result["rollout_id"], "account-a") == "blocked"
    target = manager.get(result["rollout_id"], "TARGET#account-a")
    assert target["error_code"] == "queued_authority_expired" and not target["dispatch_attempted"]
    assert not core.sent


def test_absent_receipt_after_uncertain_dispatch_never_proves_safe_retry(reviewed):
    manager, helper, core, _, _, _ = reviewed
    result, _, _ = authorized(reviewed)
    identity = result["rollout_id"]
    core.lose = True
    assert manager.execute(identity, "account-a") == "unknown"
    core.receipts.clear()
    observed = helper.reconcile(identity, "account-a")
    assert observed["state"] == "unknown" and observed["retry_allowed"] is False
    assert manager.execute(identity, "account-a") == "already_claimed" and len(core.sent) == 1


def test_report_only_drift_is_bounded_and_never_resends(reviewed):
    manager, helper, core, _, names, _ = reviewed
    result = planned(reviewed, names[:10])
    before = len(core.sent)
    first = manager.drift(result["rollout_id"], {})
    assert first["report_only"] and first["observed_targets"] == 8 and first["next_after"]
    second = manager.drift(result["rollout_id"], {"after": first["next_after"]})
    assert second["observed_targets"] == 2 and second["next_after"] is None
    assert len(core.sent) == before
