import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from test_detection_queries import indexed as indexed_fixture

from opencdr_fleet import handlers
from opencdr_fleet.cases import handle

indexed = indexed_fixture
IDENTITY = {
    "userArn": "arn:aws:sts::123456789012:assumed-role/analyst/s",
    "caller": "AROAABCDEFGHIJKLMNOP:s",
}
ACTOR = "aws:123456789012:AROAABCDEFGHIJKLMNOP"


@pytest.fixture
def cases(indexed, monkeypatch):
    store, _ = indexed
    store.client.create_table(
        TableName="cases",
        BillingMode="PAY_PER_REQUEST",
        AttributeDefinitions=[{"AttributeName": k, "AttributeType": "S"} for k in ("pk", "sk")],
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
    )
    store.s3.create_bucket(Bucket="case-evidence")
    monkeypatch.setenv("CASE_TABLE_NAME", "cases")
    monkeypatch.setenv("CASE_EVIDENCE_BUCKET", "case-evidence")
    from opencdr_fleet.agent import Agent

    monkeypatch.setattr(
        Agent, "verify", MagicMock(side_effect=AssertionError("Case fanout forbidden"))
    )

    def call(tier, method, path, body=None, query=None, identity=None):
        monkeypatch.setenv("FLEET_MANAGEMENT_ACCESS", tier)
        return handle(store, method, path, body or {}, query or {}, identity or IDENTITY)

    return call, store


def grant(call, scope=None, rev=0):
    return call(
        "administrator",
        "PUT",
        "/case-access",
        {
            "request_id": f"{rev:032x}",
            "reason": "Account access",
            "expected_rev": rev,
            "principal": ACTOR,
            "agent_ids": ["a", "b"] if scope is None else scope,
        },
    )


def test_explicit_grants_fail_closed_and_cannot_be_self_escalated(cases):
    call, _ = cases
    assert call("administrator", "GET", "/cases")[0] == 403
    assert call("observer", "GET", "/case-access")[1]["access"]["rev"] == 0
    assert call("triage", "PUT", "/case-access", {})[0] == 403
    assert grant(call)[0] == 200
    body = {
        "request_id": "a" * 32,
        "reason": "Triage",
        "title": "Cross account",
        "description": "private",
        "severity": "critical",
        "agent_ids": ["a", "b"],
    }
    code, created = call("triage", "POST", "/cases", body)
    assert code == 200, created
    cid = created["case"]["case_id"]
    for i, name in enumerate(["a", "b"]):
        code, result = call(
            "triage",
            "POST",
            f"/cases/{cid}/detections",
            {
                "request_id": f"{i + 1:032x}",
                "reason": "Verified evidence",
                "expected_rev": i + 1,
                "agent_id": name,
                "detection_id": name + "-0",
            },
        )
        assert code == 200, result
    attachment = result["case"]["attachments"][0]
    assert (
        call(
            "observer",
            "GET",
            f"/cases/{cid}/evidence",
            query={"attachment_id": attachment["attachment_id"]},
        )[0]
        == 200
    )
    assert grant(call, ["a"], 1)[0] == 200
    assert call("observer", "GET", "/cases")[1]["items"] == []
    for suffix in ["", "/history", "/evidence"]:
        code, _ = call(
            "observer",
            "GET",
            f"/cases/{cid}" + suffix,
            query={"attachment_id": attachment["attachment_id"]} if suffix == "/evidence" else {},
        )
        assert code == 404
    assert call("triage", "POST", "/cases", body)[0] == 403


def test_missing_gateway_canonical_identity_and_unknown_principals(cases):
    call, _ = cases
    assert (
        call("administrator", "GET", "/case-access", identity={"userArn": IDENTITY["userArn"]})[0]
        == 403
    )
    assert call("observer", "GET", "/case-access", query={"principal": "someone"})[0] == 403
    assert call("administrator", "GET", "/case-access", query={"principal": "someone"})[0] == 400


def test_real_management_entrypoint_triage_and_observer_permissions(cases, monkeypatch):
    call, store = cases
    grant(call)
    monkeypatch.setattr(handlers, "Store", lambda: store)
    context = SimpleNamespace(
        invoked_function_arn="arn:aws:lambda:us-east-1:123456789012:function:cases",
        aws_request_id="test",
    )
    body = {
        "request_id": "a" * 32,
        "reason": "test",
        "title": "Case",
        "description": "",
        "severity": "high",
        "agent_ids": ["a"],
    }
    for tier, expected in [("observer", 403), ("triage", 200)]:
        monkeypatch.setenv("FLEET_MANAGEMENT_ACCESS", tier)
        response = handlers.api(
            {
                "path": f"/management/{tier}/v1/cases",
                "httpMethod": "POST",
                "body": json.dumps(body),
                "requestContext": {"identity": IDENTITY},
            },
            context,
        )
        assert response["statusCode"] == expected, response
    result = handlers.api(
        {
            "path": "/management/triage/v1/case-access",
            "httpMethod": "PUT",
            "body": "{}",
            "requestContext": {"identity": IDENTITY},
        },
        context,
    )
    assert result["statusCode"] == 403


def test_connector_binding_reports_without_member_fanout(cases, monkeypatch):
    call, store = cases
    assert grant(call)[0] == 200
    code, result = call(
        "triage",
        "POST",
        "/cases",
        {
            "request_id": "c" * 32,
            "reason": "test",
            "title": "Triage",
            "description": "",
            "severity": "high",
            "agent_ids": ["a"],
        },
    )
    assert code == 200
    cid = result["case"]["case_id"]
    binding = {
        "request_id": "d" * 32,
        "reason": "trust",
        "expected_rev": 0,
        "principal": ACTOR,
        "agent_ids": ["a"],
        "enabled": True,
        "incident_origin": "https://siem.test",
        "max_age_seconds": 3600,
    }
    assert call("triage", "PUT", "/case-integrations/siem", binding)[0] == 403
    assert call("administrator", "PUT", "/case-integrations/siem", binding)[0] == 200
    report = {
        "request_id": "e" * 32,
        "reason": "check",
        "integration_id": "siem",
        "incident_id": "INC-1",
        "sequence": 1,
        "result": "ok",
        "url": "https://siem.test/1",
        "status": "closed upstream",
        "source_updated_at": "2026-01-01T00:00:00Z",
    }
    assert call("administrator", "POST", f"/cases/{cid}/external-status", report)[0] == 403
    assert call("integration", "POST", f"/cases/{cid}/external-status", report)[0] == 200
    assert call("integration", "GET", f"/cases/{cid}")[0] == 403
    result = call("observer", "GET", f"/cases/{cid}")[1]["case"]
    assert (
        result["status"] == "open" and result["external_status"][0]["status"] == "closed upstream"
    )


def test_fleet_routing_preview_uses_local_projection_without_case_writes(cases):
    call, _ = cases
    grant(call)
    policy = {
        "policy_id": "a" * 32,
        "revision": 1,
        "enabled": True,
        "mode": "join",
        "agent_ids": ["a"],
        "rule": {"kind": "signal", "rule_id": "r1", "content_sha256": "f" * 64},
        "group_by": ["severity"],
        "window_seconds": 300,
        "closed_case": "manual",
    }
    code, result = call(
        "triage",
        "POST",
        "/cases/routing/preview",
        {"policy": policy, "agent_id": "a", "detection_id": "a-0"},
    )
    assert code == 200, result
    assert result["preview"]["action"] == "manual" and result["preview"]["side_effects"] is False
    assert result["preview"]["owner"].startswith("123456789012:")
    assert call("observer", "GET", "/cases")[1]["items"] == []
