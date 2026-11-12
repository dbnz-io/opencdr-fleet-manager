import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from opencdr_fleet import handlers
from opencdr_fleet.agent import Agent

IDENTITY = {
    "userArn": "arn:aws:sts::123456789012:assumed-role/operator/s",
    "caller": "AROAABCDEFGHIJKLMNOP:s",
}


@pytest.fixture
def library_api(store, monkeypatch):
    store.client.create_table(
        TableName="library",
        BillingMode="PAY_PER_REQUEST",
        AttributeDefinitions=[{"AttributeName": k, "AttributeType": "S"} for k in ("pk", "sk")],
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
    )
    store.s3.create_bucket(Bucket="library-artifacts")
    monkeypatch.setenv("LIBRARY_TABLE_NAME", "library")
    monkeypatch.setenv("LIBRARY_BUCKET", "library-artifacts")
    monkeypatch.setattr(
        Agent, "verify", MagicMock(side_effect=AssertionError("Library fanout forbidden"))
    )
    monkeypatch.setattr(handlers, "Store", lambda: store)
    context = SimpleNamespace(
        invoked_function_arn="arn:aws:lambda:us-east-1:123456789012:function:library",
        aws_request_id="test",
    )

    def call(tier, method, path, body=None, query=None, identity=None):
        monkeypatch.setenv("FLEET_MANAGEMENT_ACCESS", tier)
        response = handlers.api(
            {
                "path": f"/management/{tier}/v1" + path,
                "httpMethod": method,
                "body": json.dumps(body or {}),
                "queryStringParameters": query or {},
                "requestContext": {"identity": identity if identity is not None else IDENTITY},
            },
            context,
        )
        return response["statusCode"], json.loads(response["body"])

    return call


def test_library_authority_and_iam_roles_through_real_fleet_entrypoint(library_api):
    call = library_api
    body = {
        "kind": "signal",
        "runtime_id": "r1",
        "title": "Draft",
        "description": "",
        "request_id": "a" * 32,
        "reason": "author",
    }
    for tier in ["observer", "triage", "delivery", "integration"]:
        assert call(tier, "POST", "/library/items", body)[0] == 403
    code, result = call("operator", "POST", "/library/items", body)
    assert code == 200, result
    assert result["deployment"] == {
        "account_id": "123456789012",
        "home_region": "us-east-1",
        "stage": "test",
    }
    cid = result["item"]["content_id"]
    assert result["item"]["created_by"] == "aws:123456789012:AROAABCDEFGHIJKLMNOP"
    assert call("operator", "POST", "/library/items", body)[1]["idempotent"]
    assert call("observer", "GET", "/library/items")[1]["page_count"] == 1
    assert call("triage", "GET", f"/library/items/{cid}")[0] == 200
    assert (
        call("operator", "GET", "/library/items", identity={"userArn": IDENTITY["userArn"]})[0]
        == 403
    )
    assert call("operator", "POST", f"/library/items/{cid}/deploy", {})[0] == 404


def test_missing_library_capability_never_falls_back(library_api, monkeypatch):
    monkeypatch.delenv("LIBRARY_BUCKET")
    assert library_api("operator", "GET", "/library/items")[0] == 503
