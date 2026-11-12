import time
from unittest.mock import Mock

import pytest

from opencdr_fleet.models import FleetError
from opencdr_fleet.rollouts import Rollouts


@pytest.fixture
def rollout(store, agent_record, monkeypatch):
    monkeypatch.setenv("ROLLOUT_TABLE", "rollouts")
    monkeypatch.setenv("ROLLOUT_QUEUE_URL", "unused-in-worker-tests")
    monkeypatch.setenv("FLEET_MANAGEMENT_ACCESS", "operator")
    store.client.create_table(
        TableName="rollouts",
        BillingMode="PAY_PER_REQUEST",
        AttributeDefinitions=[{"AttributeName": key, "AttributeType": "S"} for key in ("pk", "sk")],
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
    )
    store.registry.update_item(
        Key={"id": "AGENT#account-a"},
        UpdateExpression="SET auth_mode = :iam, allow_writes = :yes",
        ExpressionAttributeValues={":iam": "iam", ":yes": True},
    )
    client = Mock()
    client.verify.return_value = {"capabilities": {"reviewed_rule_releases": True}}
    client.request.return_value = (
        200,
        {"valid": True, "plan_digest": "reviewed-rev-7", "operations": []},
    )
    manager = Rollouts(store, agent_factory=lambda *a, **k: client)
    plan = manager.plan({"agent_ids": ["account-a"], "manifest": {"rules": ["fixture"]}})
    client.reset_mock()
    return manager, client, plan


def test_worker_keeps_original_review_and_duplicate_delivery_never_sends_again(rollout):
    manager, client, plan = rollout
    client.request.return_value = (200, {"completed": [{"rule_id": "one"}]})
    assert manager.execute(plan["rollout_id"], "account-a") == "succeeded"
    assert client.request.call_args.kwargs["body"]["expected_plan_digest"] == "reviewed-rev-7"
    assert manager.execute(plan["rollout_id"], "account-a") == "already_claimed"
    client.request.assert_called_once()
    assert manager.status(plan["rollout_id"])["complete"]


def test_uncertain_write_is_persisted_and_not_retried(rollout):
    manager, client, plan = rollout
    client.request.side_effect = FleetError("agent_unreachable", 502)
    assert manager.execute(plan["rollout_id"], "account-a") == "unknown"
    assert manager.execute(plan["rollout_id"], "account-a") == "already_claimed"
    client.request.assert_called_once()
    assert manager.status(plan["rollout_id"])["targets"][0]["state"] == "unknown"


def test_registration_change_blocks_dispatch_and_partial_results_are_preserved(rollout):
    manager, client, plan = rollout
    manager.store.registry.update_item(
        Key={"id": "AGENT#account-a"},
        UpdateExpression="SET rev = :rev",
        ExpressionAttributeValues={":rev": 2},
    )
    assert manager.execute(plan["rollout_id"], "account-a") == "not_sent"
    client.request.assert_not_called()


def test_apply_needs_review_digest_and_matching_permission(rollout, monkeypatch):
    manager, client, plan = rollout
    with pytest.raises(FleetError, match="review_digest_required"):
        manager.enqueue(plan["rollout_id"], {"review_digest": "modified"})
    monkeypatch.setenv("FLEET_MANAGEMENT_ACCESS", "responder")
    with pytest.raises(FleetError, match="reviewed_management_access"):
        manager.enqueue(plan["rollout_id"], {"review_digest": plan["review_digest"]})
    client.request.assert_not_called()


def test_operator_worker_cannot_process_a_responder_review(rollout):
    manager, client, plan = rollout
    manager.table.update_item(
        Key={"pk": plan["rollout_id"], "sk": "META"},
        UpdateExpression="SET #access = :access",
        ExpressionAttributeNames={"#access": "access"},
        ExpressionAttributeValues={":access": "responder"},
    )
    with pytest.raises(FleetError, match="worker_access_mismatch"):
        manager.execute(plan["rollout_id"], "account-a")
    client.request.assert_not_called()
    assert manager.status(plan["rollout_id"])["targets"][0]["state"] == "planned"


def test_interrupted_claim_becomes_unknown_in_status_without_replaying(rollout):
    from datetime import UTC, datetime

    manager, client, plan = rollout
    manager.table.update_item(
        Key={"pk": plan["rollout_id"], "sk": "TARGET#account-a"},
        UpdateExpression="SET #state = :sending, started_at = :old",
        ExpressionAttributeNames={"#state": "state"},
        ExpressionAttributeValues={
            ":sending": "sending",
            ":old": datetime.fromtimestamp(time.time() - 121, UTC).isoformat(),
        },
    )
    assert manager.status(plan["rollout_id"])["targets"][0]["state"] == "unknown"
    assert manager.execute(plan["rollout_id"], "account-a") == "already_claimed"
    client.request.assert_not_called()


# P4 cancellation: the existing worker retains uncertain/sent outcomes.
def cancellation(plan, **extra):
    return {
        "review_digest": plan["review_digest"],
        "request_id": "a" * 32,
        "reason": "Stop remaining reviewed targets",
        **extra,
    }


def test_cancellation_fences_unclaimed_work_and_retry_is_idempotent(rollout):
    manager, client, plan = rollout
    first = manager.cancel(
        plan["rollout_id"], cancellation(plan), authenticated_actor="fixture-actor"
    )
    assert first["targets"][0]["state"] == "cancelled"
    assert first["cancellation"]["actor"] == "fixture-actor"
    assert (
        manager.cancel(plan["rollout_id"], cancellation(plan), authenticated_actor="fixture-actor")
        == first
    )
    assert manager.execute(plan["rollout_id"], "account-a") == "cancelled"
    with pytest.raises(FleetError, match="rollout_cancelled"):
        manager.enqueue(plan["rollout_id"], {"review_digest": plan["review_digest"]})
    client.request.assert_not_called()


def test_cancellation_cannot_overwrite_an_uncertain_result(rollout):
    manager, client, plan = rollout
    client.request.side_effect = FleetError("agent_unreachable", 502)
    assert manager.execute(plan["rollout_id"], "account-a") == "unknown"
    result = manager.cancel(
        plan["rollout_id"], cancellation(plan), authenticated_actor="fixture-actor"
    )
    assert result["targets"][0]["state"] == "unknown"
    assert manager.execute(plan["rollout_id"], "account-a") == "cancelled"
    client.request.assert_called_once()


def test_cancellation_during_send_preserves_actual_completed_result(rollout):
    manager, client, plan = rollout

    def sent(*args, **kwargs):
        status = manager.cancel(
            plan["rollout_id"], cancellation(plan), authenticated_actor="fixture-actor"
        )
        assert status["targets"][0]["state"] == "sending"
        return 200, {"completed": ["fixture"]}

    client.request.side_effect = sent
    assert manager.execute(plan["rollout_id"], "account-a") == "succeeded"
    status = manager.status(plan["rollout_id"])
    assert status["cancellation"] and status["targets"][0]["state"] == "succeeded"
    client.request.assert_called_once()


def test_cancellation_after_worker_read_is_fenced_at_atomic_claim(rollout, monkeypatch):
    manager, client, plan = rollout
    original = manager.get
    fired = False

    def interleave(rollout_id, sk="META"):
        nonlocal fired
        old = original(rollout_id, sk)
        if not fired and sk == "META":
            fired = True
            manager.cancel(rollout_id, cancellation(plan), authenticated_actor="fixture-actor")
        return old

    monkeypatch.setattr(manager, "get", interleave)
    assert manager.execute(plan["rollout_id"], "account-a") == "cancelled"
    client.request.assert_not_called()


def test_interrupted_cancellation_retains_fence_and_resumes_target_marking(rollout, monkeypatch):
    from botocore.exceptions import ClientError

    manager, client, plan = rollout
    update = manager.table.update_item

    def interrupted(**kwargs):
        if kwargs["Key"]["sk"].startswith("TARGET#"):
            raise ClientError(
                {"Error": {"Code": "ProvisionedThroughputExceededException"}}, "UpdateItem"
            )
        return update(**kwargs)

    monkeypatch.setattr(manager.table, "update_item", interrupted)
    with pytest.raises(ClientError):
        manager.cancel(plan["rollout_id"], cancellation(plan), authenticated_actor="fixture-actor")
    assert manager.get(plan["rollout_id"], "TARGET#account-a")["state"] == "planned"
    assert manager.execute(plan["rollout_id"], "account-a") == "cancelled"
    monkeypatch.setattr(manager.table, "update_item", update)
    assert (
        manager.cancel(plan["rollout_id"], cancellation(plan), authenticated_actor="fixture-actor")[
            "targets"
        ][0]["state"]
        == "cancelled"
    )
    client.request.assert_not_called()


def test_cancellation_changed_receipt_or_management_access_fails(rollout, monkeypatch):
    manager, client, plan = rollout
    manager.cancel(plan["rollout_id"], cancellation(plan), authenticated_actor="fixture-actor")
    with pytest.raises(FleetError, match="request_conflict"):
        manager.cancel(
            plan["rollout_id"],
            cancellation(plan, reason="different"),
            authenticated_actor="fixture-actor",
        )
    monkeypatch.setenv("FLEET_MANAGEMENT_ACCESS", "responder")
    with pytest.raises(FleetError, match="reviewed_management_access"):
        manager.cancel(plan["rollout_id"], cancellation(plan), authenticated_actor="fixture-actor")
    client.request.assert_not_called()
