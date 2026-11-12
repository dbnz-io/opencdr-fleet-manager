import json
import time
from types import SimpleNamespace

import pytest
from test_cases import ACTOR, IDENTITY
from test_cases import cases as cases_fixture
from test_detection_queries import indexed as indexed_fixture

from opencdr_fleet import handlers, identity
from opencdr_fleet._contracts.delegation import actor_id
from opencdr_fleet._contracts.identity_store import Identities

cases, indexed = cases_fixture, indexed_fixture
OWNER = {"account_id": "123456789012", "home_region": "us-east-1", "stage": "test"}


@pytest.mark.parametrize("tier", [None, "triage", "administrator"])
def test_fleet_entrypoint_binds_human_and_scopes_reads_without_live_fanout(
    cases, monkeypatch, tier
):
    _, store = cases
    monkeypatch.setattr(handlers, "Store", lambda: store)
    monkeypatch.setattr(identity, "Store", lambda: store)
    if tier:
        monkeypatch.setenv("FLEET_MANAGEMENT_ACCESS", tier)
    else:
        monkeypatch.delenv("FLEET_MANAGEMENT_ACCESS", raising=False)
    prefix = f"/management/{tier}" if tier else ""
    admin = Identities(store.client, "cases", "owner-admin", store.get_agent)
    common = {"expected_rev": 0, "request_id": "0" * 32, "reason": "Reviewed"}
    admin.update(
        "issuer",
        "opencdr-saas",
        {**common, "tenant": "org-a", "principals": [ACTOR], "enabled": True},
    )
    actor = actor_id("opencdr-saas", "org-a", "user-a")
    admin.update(
        "subject",
        actor,
        {
            **common,
            "issuer": "opencdr-saas",
            "tenant": "org-a",
            "subject": "user-a",
            "permissions": ["read", "triage"],
            "agent_ids": ["a"],
            "enabled": True,
        },
    )
    context = SimpleNamespace(
        invoked_function_arn="arn:aws:lambda:us-east-1:123456789012:function:api",
        aws_request_id="test",
    )

    def call(method, path, body=None, query=None, delegated=True):
        now = int(time.time())
        envelope = {
            "identity": {
                "issuer": "opencdr-saas",
                "tenant": "org-a",
                "subject": "user-a",
                "audience": OWNER,
                "issued_at": now,
                "expires_at": now + 60,
            },
            "operation": {"method": method, "path": path, "body": body or {}, "query": query or {}},
        }
        event = {
            "path": prefix + ("/v1/delegated" if delegated else path),
            "httpMethod": "POST" if delegated else method,
            "requestContext": {"identity": IDENTITY},
            "body": json.dumps(envelope if delegated else body or {}),
            "queryStringParameters": {} if delegated else query or {},
        }
        result = handlers.api(event, context)
        return result["statusCode"], json.loads(result["body"])

    body = {
        "request_id": "a" * 32,
        "reason": "Triage",
        "title": "Scoped case",
        "description": "",
        "severity": "high",
        "agent_ids": ["a"],
    }
    code, value = call("POST", "/v1/cases", body)
    assert code == 200, value
    assert value["case"]["created_by"] == actor
    assert call("POST", "/v1/cases", body, delegated=False)[0] == 403
    assert call("POST", "/v1/cases", {**body, "agent_ids": ["b"]})[0] == 403
    code, page = call("GET", "/v1/detections")
    assert code == 200, page
    assert page["items"] and {v["agent_id"] for v in page["items"]} == {"a"}
    assert {v["agent_id"] for v in page["coverage"]["agents"]} == {"a"}
    assert call("GET", "/v1/detections", query={"agent_ids": "b"})[0] == 403
    assert call("POST", "/v1/rollouts", {})[0] == 403
