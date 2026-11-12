from io import BytesIO
from unittest.mock import Mock

import pytest

from opencdr_fleet.agent import Agent, NoRedirect, route
from opencdr_fleet.models import FleetError, endpoint, registration


@pytest.mark.parametrize(
    "url",
    [
        "http://abc.execute-api.us-east-1.amazonaws.com/dev",
        "https://localhost",
        "https://169.254.169.254/latest",
        "https://evil.example",
        "https://user@abc.execute-api.us-east-1.amazonaws.com",
        "https://abc.execute-api.eu-west-1.amazonaws.com/prod",
        "https://abc.execute-api.us-east-1.amazonaws.com/../admin",
    ],
)
def test_endpoints_are_validated_before_any_credential_is_used(url):
    with pytest.raises(FleetError):
        endpoint(url, "us-east-1")


@pytest.mark.parametrize(
    "path",
    [
        "https://evil.example",
        "//evil.example",
        "/settings/../status",
        "/settings/%2e%2e",
        "/status?api_key=secret",
        "/unknown",
        "/rules#fragment",
    ],
)
def test_proxy_paths_cannot_escape_to_a_different_endpoint(path):
    with pytest.raises(FleetError):
        route("GET", path)


def test_unknown_registration_fields_and_plaintext_keys_are_rejected():
    with pytest.raises(FleetError, match="unknown_registration_fields"):
        registration({"api_key": "do-not-persist-me"})


def test_detection_feed_is_read_only_in_forwarding_contract():
    route("GET", "/detections/feed")
    for method in ("POST", "PUT", "DELETE"):
        with pytest.raises(FleetError):
            route(method, "/detections/feed")


def test_delivery_transport_is_iam_only_and_cannot_write_configuration(store, agent_record):
    agent = Agent({**agent_record, "auth_mode": "iam"}, "")
    response = BytesIO(b'{"rev":1}')
    response.code = 200
    agent.opener.open = Mock(return_value=response)
    assert agent.delivery_request("POST", "/detections/consumers/test", body={})[0] == 200
    request = agent.opener.open.call_args.args[0]
    assert request.full_url.endswith("/management/delivery/detections/consumers/test")
    assert request.get_header("Authorization").startswith("AWS4-HMAC-SHA256")
    for path in (
        "/settings/global",
        "/detections/consumers/../rules",
        "/detections/consumers/test?owner=other",
    ):
        with pytest.raises(FleetError, match="unsupported_delivery_route"):
            agent.delivery_request("POST", path, body={})
    with pytest.raises(FleetError):
        Agent(agent_record, "key").delivery_request("POST", "/detections/consumers/test", body={})
    with pytest.raises(FleetError):
        route("POST", "/detections/consumers/test")
    with pytest.raises(FleetError):
        route("POST", "/detections/consumers/recovery-test/recover")
    response = BytesIO(b'{"rev":1}')
    response.code = 200
    agent.opener.open = Mock(return_value=response)
    assert (
        agent.delivery_request("POST", "/detections/consumers/recovery-test/recover", body={})[0]
        == 200
    )
    assert "/management/delivery/" in agent.opener.open.call_args.args[0].full_url


def test_iam_uses_temporary_credentials_and_the_observer_path(store, agent_record):
    record = {**agent_record, "auth_mode": "iam"}
    assert store.credentials(record) == ("", None)
    agent = Agent(record, "")
    response = BytesIO(b'{"ok":true}')
    response.code = 200
    agent.opener.open = Mock(return_value=response)
    assert agent.request("GET", "/status")[0] == 200
    request = agent.opener.open.call_args.args[0]
    assert request.full_url.endswith("/management/observer/status")
    assert request.get_header("Authorization").startswith("AWS4-HMAC-SHA256")
    assert not request.has_header("X-api-key")
    with pytest.raises(FleetError, match="writes_disabled"):
        agent.request("PUT", "/settings/global", body={"expected_rev": 0})


def test_identity_mismatch_blocks_the_operation(agent_record, report):
    agent = Agent(agent_record, "read", "write")
    agent.get = Mock(
        return_value={
            **report,
            "deployment": {**report["deployment"], "account_id": "999999999999"},
        }
    )
    with pytest.raises(FleetError, match="identity_mismatch"):
        agent.verify()


def test_transport_refuses_redirects_and_preserves_http_conflict_body(agent_record):
    assert (
        NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://other.example") is None
    )
    agent = Agent(agent_record, "read", "write")
    response = BytesIO(b'{"message":"conflict","completed":[{"rule_id":"first"}]}')
    response.code = 409
    agent.opener.open = Mock(return_value=response)
    status, body = agent.request("POST", "/rule-releases/apply", body={})
    assert status == 409 and body["completed"] == [{"rule_id": "first"}]
    assert agent.opener.open.call_count == 1


def test_pagination_handles_empty_filtered_pages_and_rejects_cursor_loops(agent_record):
    agent = Agent(agent_record, "read")
    agent.get = Mock(side_effect=[{"items": [], "next_token": "next"}, {"items": [{"id": 1}]}])
    assert list(agent.pages("/rules")) == [{"id": 1}]
    agent.get = Mock(return_value={"items": [], "next_token": "loop"})
    with pytest.raises(FleetError, match="repeated_agent_cursor"):
        list(agent.pages("/rules"))


@pytest.mark.parametrize(
    "method,access,path",
    [
        ("GET", "observer", "/detections/handling"),
        ("PUT", "triage", "/detections/handling"),
        ("GET", "observer", "/detections/outcomes"),
        ("GET", "observer", "/detections/outcomes/history"),
    ],
)
def test_handling_relay_preserves_human_and_original_expiry_with_core_audience(
    store, agent_record, method, access, path
):
    import json

    from opencdr_fleet._contracts.delegation import CURRENT

    authority = Mock()
    authority.claim = {
        "issuer": "opencdr-saas",
        "tenant": "org-a",
        "subject": "user-a",
        "audience": {"account_id": "999999999999", "home_region": "us-east-1", "stage": "prod"},
        "issued_at": 1000,
        "expires_at": 1030,
    }
    token = CURRENT.set(authority)
    agent = Agent({**agent_record, "auth_mode": "iam", "allow_triage": True}, "")
    response = BytesIO(b'{"code":"identity_denied"}')
    response.code = 403
    agent.opener.open = Mock(return_value=response)
    body = {"expected_rev": 1, "request_id": "a" * 32} if method == "PUT" else None
    try:
        if "outcomes" in path:
            result = agent.outcomes_request(path, query={"detection_id": "d"})
        else:
            result = agent.handling_request(method, path, body=body, query={"detection_id": "d"})
        assert result[0] == 403
    finally:
        CURRENT.reset(token)
    request = agent.opener.open.call_args.args[0]
    assert request.get_method() == "POST"
    assert request.full_url.endswith("/management/" + access + "/delegated")
    assertion = json.loads(request.data)
    assert assertion["identity"] == {
        **authority.claim,
        "audience": {
            "account_id": agent_record["account_id"],
            "home_region": agent_record["region"],
            "stage": agent_record["stage"],
        },
    }
    assert assertion["operation"] == {
        "method": method,
        "path": path,
        "query": {"detection_id": "d"},
        "body": body or {},
    }
    authority.fresh.assert_called_once()
    agent.opener.open.assert_called_once()
