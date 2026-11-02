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
