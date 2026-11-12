import time
from unittest.mock import MagicMock

import pytest

from opencdr_fleet.models import (
    FleetError,
    cursor_decode,
    cursor_encode,
    public_registration,
    registration,
)
from opencdr_fleet.store import Store, _runtime_sdk


def test_reused_sdk_connections_still_read_current_registration(store, agent_record):
    first = Store()
    second = Store()
    assert first.client is second.client and first.ddb is second.ddb
    assert first.get_agent("account-a")["enabled"] is True
    store.registry.update_item(
        Key={"id": "AGENT#account-a"},
        UpdateExpression="SET enabled = :enabled, rev = :rev",
        ExpressionAttributeValues={":enabled": False, ":rev": 2},
    )
    assert second.get_agent("account-a")["enabled"] is False
    assert first.get_agent("account-a")["rev"] == 2


def test_query_store_does_not_construct_unused_service_clients(store):
    session = MagicMock()
    scoped = Store(session=session)
    assert session.client.call_count == 1
    assert session.client.call_args.args == ("dynamodb",)
    assert scoped.s3 is scoped.s3
    assert session.client.call_count == 2
    assert session.client.call_args.args == ("s3",)
    assert scoped.client is not Store().client


def test_sdk_cache_respects_region_and_explicit_profile(monkeypatch):
    session = MagicMock()
    monkeypatch.setattr("opencdr_fleet.store.boto3.Session", session)
    _runtime_sdk.cache_clear()
    try:
        a = _runtime_sdk("us-east-1", "one")
        assert _runtime_sdk("us-east-1", "one") is a
        assert _runtime_sdk("us-east-1", "two") is not a
        assert _runtime_sdk("eu-west-1", "two") is not a
        assert session.call_count == 3
    finally:
        _runtime_sdk.cache_clear()


def test_registry_rejects_duplicate_identity_and_stale_updates(store, agent_record):
    duplicate = public_registration(agent_record)
    for key in ("rev", "created_at", "updated_at"):
        duplicate.pop(key)
    duplicate["agent_id"] = "another-name"
    with pytest.raises(FleetError, match="already_registered"):
        store.save_agent(registration(duplicate), create=True)
    duplicate["agent_id"] = "account-a"
    duplicate["expected_rev"] = 9
    with pytest.raises(FleetError, match="revision_conflict"):
        store.save_agent(registration(duplicate), create=False)


def test_poll_lease_fences_an_old_worker_after_registration_changes(store, agent_record):
    sequence = int(time.time() * 1000)
    item, token = store.claim("account-a", 1, sequence)
    assert store.claim("account-a", 1, sequence) is None
    replacement = {
        k: v
        for k, v in public_registration(agent_record).items()
        if k not in ("rev", "created_at", "updated_at")
    }
    replacement.update(expected_rev=1, enabled=False)
    changed = store.save_agent(registration(replacement), create=False)
    assert changed["rev"] == 2
    assert not store.finish(item, token, sequence, {"agent_id": "account-a", "health": "healthy"})
    assert store.get_status("account-a") == {}


def test_completed_sequence_rejects_duplicates_and_older_jobs(store, agent_record):
    item, token = store.claim("account-a", 1, 100)
    assert store.finish(item, token, 100, {"agent_id": "account-a"})
    assert store.claim("account-a", 1, 100) is None
    assert store.claim("account-a", 1, 99) is None
    assert store.claim("account-a", 1, 101)


def test_multi_chunk_configuration_roundtrips_and_unchanged_content_is_reused(store, agent_record):
    docs = {"list:large": {"values": ["value" * 200] * 800}, "rule:signal:r": {"rev": 3}}
    generation = store.snapshot("account-a", docs, None)
    store.status.put_item(Item={"agent_id": "account-a", "snapshot_generation": generation})
    assert store.snapshot("account-a", docs, generation) == generation
    one = store.configuration("account-a", 1)
    two = store.configuration("account-a", 1, one["next_token"])
    assert {item["resource_key"]: item["document"] for item in one["items"] + two["items"]} == docs
    assert two["next_token"] is None


def test_snapshot_pagination_stays_pinned_across_a_new_poll(store, agent_record):
    first = store.snapshot("account-a", {"rule:signal:a": {}, "rule:signal:b": {}}, None)
    store.status.put_item(Item={"agent_id": "account-a", "snapshot_generation": first})
    page = store.configuration("account-a", 1)
    second = store.snapshot("account-a", {"rule:signal:a": {"rev": 2}}, first)
    store.status.put_item(Item={"agent_id": "account-a", "snapshot_generation": second})
    rest = store.configuration("account-a", 1, page["next_token"])
    assert rest["generation"] == first
    assert rest["is_current"] is False
    assert rest["items"][0]["resource_key"] == "rule:signal:b"


def test_cache_cursor_cannot_read_another_agent(store, agent_record):
    generation = store.snapshot("account-a", {"rule:a": {}, "rule:b": {}}, None)
    store.status.put_item(Item={"agent_id": "account-a", "snapshot_generation": generation})
    cursor = cursor_decode(store.configuration("account-a", 1)["next_token"])
    cursor["agent_id"] = "another-agent"
    with pytest.raises(FleetError, match="invalid_cursor"):
        store.configuration("account-a", 1, cursor_encode(cursor))


def test_polling_role_reads_secure_strings_only(store, agent_record):
    assert store.credentials(agent_record) == ("test-read-key", None)
    with pytest.raises(FleetError, match="writes_disabled"):
        store.credentials(agent_record, write=True)
    store.ssm.put_parameter(
        Name=f"{store.prefix}/account-a/read-key", Value="plain", Type="String", Overwrite=True
    )
    with pytest.raises(FleetError, match="invalid_agent_credential"):
        store.credentials(agent_record)


def test_old_observations_and_changed_registrations_are_stale(store, agent_record):
    store.status.put_item(
        Item={
            "agent_id": "account-a",
            "registration_rev": 1,
            "status_success_ms": int(time.time() * 1000),
            "configuration_success_ms": 1,
        }
    )
    view = store.view_status(agent_record)
    assert not view["status_stale"] and view["configuration_stale"]
    assert store.view_status({**agent_record, "rev": 2})["status_stale"]
