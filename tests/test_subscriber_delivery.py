import hashlib
from unittest.mock import MagicMock

import pytest
from test_detections import iam_agent as iam_agent_fixture

from opencdr_fleet import subscriber_delivery as relay
from opencdr_fleet._contracts.case_api import Access
from opencdr_fleet._contracts.case_contract import CaseError
from opencdr_fleet._contracts.delegation import CURRENT

iam_agent = iam_agent_fixture
IDENTITY = {
    "userArn": "arn:aws:sts::123456789012:assumed-role/analyst/s",
    "caller": "AROAABCDEFGHIJKLMNOP:s",
}
ACTOR = "aws:123456789012:AROAABCDEFGHIJKLMNOP"


@pytest.fixture
def subscriber(detection_store, iam_agent, monkeypatch):
    store = detection_store
    store.client.create_table(
        TableName="cases",
        BillingMode="PAY_PER_REQUEST",
        AttributeDefinitions=[{"AttributeName": k, "AttributeType": "S"} for k in ("pk", "sk")],
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
    )
    monkeypatch.setenv("CASE_TABLE_NAME", "cases")
    access = Access(store.client, "cases", ACTOR, store.get_agent)

    def grant(actor=ACTOR, scopes=None, rev=0):
        return access.update(
            {
                "principal": actor,
                "agent_ids": ["account-a"] if scopes is None else scopes,
                "expected_rev": rev,
                "request_id": f"{rev + 1:032x}",
                "reason": "Fixture subscription",
            }
        )

    grant()
    agent = MagicMock()
    agent.verify.return_value = {"capabilities": {"detection_consumers": "1.0.0"}}

    def response(method, path, body=None):
        fixed = path.split("/")[3]
        state = {
            "consumer_id": fixed,
            "principal": "lambda-role",
            "rev": 1,
            "acknowledged_sequence": 0,
        }
        if path.endswith("/read"):
            return 200, {
                "consumer": state,
                "items": [],
                "deployment": {
                    "account_id": "111111111111",
                    "home_region": "us-east-1",
                    "stage": "prod",
                },
            }
        return 200, state

    agent.delivery_request.side_effect = response
    monkeypatch.setattr(relay, "Agent", lambda *args: agent)

    def call(method="GET", action=None, body=None, identity=None):
        return relay.handle(
            store,
            method,
            "account-a",
            "notifications-fixture",
            action,
            body or {},
            identity or IDENTITY,
        )

    return call, grant, agent


def test_relay_isolates_service_principals_and_preserves_core_owner(subscriber):
    call, grant, agent = subscriber
    assert call()[1]["principal"] == ACTOR
    first = agent.delivery_request.call_args.args[1]
    second_actor = "aws:123456789012:AROAABCDEFGHIJKLMNOPQ"
    grant(second_actor)
    second_identity = {**IDENTITY, "caller": "AROAABCDEFGHIJKLMNOPQ:s"}
    assert call(identity=second_identity)[1]["principal"] == second_actor
    assert first != agent.delivery_request.call_args.args[1]
    assert first.endswith(
        "subscriber-" + hashlib.sha256((ACTOR + ":notifications-fixture").encode()).hexdigest()
    )
    code, page = call("POST", "read", {"expected_rev": 1, "limit": 20})
    assert code == 200 and page["consumer"]["consumer_id"] == "notifications-fixture"
    assert page["deployment"]["account_id"] == "111111111111"


def test_revoked_scope_and_delegated_call_never_reach_core(subscriber):
    call, grant, agent = subscriber
    grant(scopes=[], rev=1)
    with pytest.raises(CaseError, match="delivery_scope_forbidden"):
        call()
    agent.delivery_request.assert_not_called()
    token = CURRENT.set(object())
    try:
        with pytest.raises(CaseError, match="subscription_requires_service_iam"):
            call()
    finally:
        CURRENT.reset(token)


@pytest.mark.parametrize(
    "action,body",
    [
        ("recover", {}),
        ("read", {"principal": ACTOR}),
        (None, {"start": "head"}),
        ("ack", {"cursor": "forged"}),
    ],
)
def test_subscription_relay_cannot_reset_or_change_principal(subscriber, action, body):
    call, _, agent = subscriber
    with pytest.raises(CaseError, match="invalid_delivery_request"):
        call("POST", action, body)
    agent.delivery_request.assert_not_called()


def test_authority_rechecked_after_network_verification(subscriber):
    call, grant, agent = subscriber

    def revoke():
        grant(scopes=[], rev=1)
        return {"capabilities": {"detection_consumers": "1.0.0"}}

    agent.verify.side_effect = revoke
    with pytest.raises(CaseError, match="delivery_authority_changed"):
        call()
    agent.delivery_request.assert_not_called()


def test_wrong_owner_or_consumer_cannot_confirm_delivery(subscriber):
    call, _, agent = subscriber
    agent.delivery_request.side_effect = None
    agent.delivery_request.return_value = (200, {"consumer_id": "someone-else"})
    with pytest.raises(CaseError, match="delivery_consumer_identity_mismatch"):
        call()
    agent.delivery_request.return_value = (200, {"deployment": {}, "consumer": {}})
    with pytest.raises(CaseError, match="delivery_owner_identity_mismatch"):
        call("POST", "read", {"expected_rev": 1, "limit": 20})


def test_unknown_delivery_result_is_never_retried(subscriber):
    call, _, agent = subscriber
    agent.delivery_request.side_effect = TimeoutError("unknown acknowledgement")
    with pytest.raises(TimeoutError):
        call("POST", "ack", {"expected_rev": 1, "receipt_id": "a" * 32})
    assert agent.delivery_request.call_count == 1


def test_explicit_new_checkpoint_is_forwarded_without_reset_access(subscriber):
    call, _, agent = subscriber
    body = {"initial_cursor": "opaque-reviewed-cursor", "checkpoint_sha256": "a" * 64}
    assert call("POST", body=body)[0] == 200
    assert agent.delivery_request.call_args.kwargs["body"] == body
    agent.delivery_request.reset_mock()
    for method, invalid in [
        ("GET", body),
        ("POST", {"initial_cursor": "cursor"}),
        ("POST", {**body, "checkpoint_sha256": "not-a-digest"}),
    ]:
        with pytest.raises(CaseError):
            call(method, body=invalid)
    agent.delivery_request.assert_not_called()
