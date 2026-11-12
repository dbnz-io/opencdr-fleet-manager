import json
import time
from types import SimpleNamespace

import pytest
from test_cases import ACTOR, IDENTITY
from test_cases import cases as cases_fixture
from test_detection_queries import indexed as indexed_fixture

from opencdr_fleet import handlers

cases, indexed = cases_fixture, indexed_fixture


@pytest.fixture
def review_http(cases, monkeypatch):
    _, store = cases
    monkeypatch.setattr(handlers, "Store", lambda: store)
    context = SimpleNamespace(
        invoked_function_arn="arn:aws:lambda:us-east-1:123456789012:function:api",
        aws_request_id="review",
    )

    def call(tier, method, path, body=None):
        monkeypatch.setenv("FLEET_MANAGEMENT_ACCESS", tier)
        event = {
            "httpMethod": method,
            "path": "/management/" + tier + "/v1" + path,
            "requestContext": {"identity": IDENTITY},
            "body": json.dumps(body or {}),
        }
        r = handlers.api(event, context)
        return r["statusCode"], json.loads(r["body"])

    return call


def payload():
    return {
        "expected_rev": 0,
        "request_id": "a" * 32,
        "reason": "Owner grant",
        "grant": {
            "enabled": True,
            "expires_at": int(time.time()) + 3600,
            "permissions": ["approve", "mutate", "policy_admin"],
            "operations": ["release.apply"],
            "target_ids": ["a"],
        },
    }


def test_fleet_review_registry_is_local_scoped_and_records_authenticated_actor(review_http):
    route = "/review-grants/" + ACTOR
    code, body = review_http("administrator", "PUT", route, payload())
    assert code == 200, body
    assert body["grant"]["updated_by"] == ACTOR
    assert review_http("administrator", "PUT", route, payload())[1]["idempotent"]
    assert review_http("observer", "GET", "/reviews")[1]["items"] == []
    bad = payload()
    bad["grant"]["target_ids"] = ["missing"]
    assert review_http("administrator", "PUT", route, bad)[0] == 404


@pytest.mark.parametrize("tier", ["observer", "triage", "operator", "responder", "integration"])
def test_other_fleet_entrypoints_cannot_write_review_grants(review_http, tier):
    assert review_http(tier, "PUT", "/review-grants/" + ACTOR, payload())[0] == 403
