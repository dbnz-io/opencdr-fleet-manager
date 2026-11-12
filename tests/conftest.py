from __future__ import annotations

import boto3
import pytest
from moto import mock_aws

from opencdr_fleet.models import registration
from opencdr_fleet.store import Store


@pytest.fixture
def store(monkeypatch):
    for key, value in {
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
        "AWS_DEFAULT_REGION": "us-east-1",
        "REGISTRY_TABLE": "registry",
        "STATUS_TABLE": "status",
        "CACHE_TABLE": "configuration",
        "CREDENTIAL_PREFIX": "/opencdr-fleet-manager/test/agents",
        "SECURITY_ACCOUNT_ID": "123456789012",
        "FLEET_STAGE": "test",
    }.items():
        monkeypatch.setenv(key, value)
    with mock_aws():
        ddb = boto3.client("dynamodb")
        ddb.create_table(
            TableName="registry",
            BillingMode="PAY_PER_REQUEST",
            AttributeDefinitions=[
                {"AttributeName": key, "AttributeType": "S"}
                for key in ("id", "record_type", "agent_id")
            ],
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "agents",
                    "KeySchema": [
                        {"AttributeName": "record_type", "KeyType": "HASH"},
                        {"AttributeName": "agent_id", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                }
            ],
        )
        ddb.create_table(
            TableName="status",
            BillingMode="PAY_PER_REQUEST",
            AttributeDefinitions=[{"AttributeName": "agent_id", "AttributeType": "S"}],
            KeySchema=[{"AttributeName": "agent_id", "KeyType": "HASH"}],
        )
        ddb.create_table(
            TableName="configuration",
            BillingMode="PAY_PER_REQUEST",
            AttributeDefinitions=[
                {"AttributeName": key, "AttributeType": "S"} for key in ("pk", "sk")
            ],
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
        )
        queue = boto3.client("sqs").create_queue(QueueName="poll")["QueueUrl"]
        monkeypatch.setenv("POLL_QUEUE_URL", queue)
        yield Store()


@pytest.fixture
def detection_store(store, monkeypatch):
    monkeypatch.setenv("DETECTION_TABLE", "detections")
    monkeypatch.setenv("DETECTION_BUCKET", "fleet-detection-evidence")
    store.client.create_table(
        TableName="detections",
        BillingMode="PAY_PER_REQUEST",
        AttributeDefinitions=[
            {"AttributeName": k, "AttributeType": "S"} for k in ("pk", "sk", "day", "order")
        ],
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "by-day",
                "KeySchema": [
                    {"AttributeName": "day", "KeyType": "HASH"},
                    {"AttributeName": "order", "KeyType": "RANGE"},
                ],
                "Projection": {
                    "ProjectionType": "INCLUDE",
                    "NonKeyAttributes": [
                        "agent_id",
                        "account_id",
                        "region",
                        "stage",
                        "detection_id",
                        "kind",
                        "committed_at",
                        "revision",
                        "summary",
                        "expires_at",
                    ],
                },
            }
        ],
    )
    store.s3.create_bucket(Bucket="fleet-detection-evidence")
    queue = store.sqs.create_queue(QueueName="detections")["QueueUrl"]
    monkeypatch.setenv("DETECTION_QUEUE_URL", queue)
    return store


@pytest.fixture
def agent_record(store):
    item = store.save_agent(
        registration(
            {
                "agent_id": "account-a",
                "auth_mode": "legacy-api-key",
                "account_id": "111111111111",
                "region": "us-east-1",
                "stage": "prod",
                "api_url": "https://abc123.execute-api.us-east-1.amazonaws.com/prod",
            }
        ),
        create=True,
    )
    store.ssm.put_parameter(
        Name=f"{store.prefix}/account-a/read-key", Value="test-read-key", Type="SecureString"
    )
    return item


@pytest.fixture
def report():
    return {
        "product": "OpenCDR Core",
        "status": "ok",
        "core_version": "1.3.0",
        "management_contract_version": "2.0.0",
        "security_profile": "hardened",
        "deployment": {"account_id": "111111111111", "home_region": "us-east-1", "stage": "prod"},
        "features": {"archive_enabled": True, "xray_enabled": False},
        "management_api": {"monthly_quota": 1000000},
        "capabilities": {"runtime_rule_verification": True},
    }


@pytest.fixture(autouse=True)
def moto_table_ids(monkeypatch):
    """Moto omits AWS TableId; model a distinct immutable ID for each table."""
    import uuid

    from moto.dynamodb.models import Table

    original = Table.describe

    def describe(self, base_key="TableDescription"):
        result = original(self, base_key)
        result[base_key]["TableId"] = str(
            uuid.uuid5(uuid.NAMESPACE_URL, self.table_arn + ":" + str(self.created_at))
        )
        return result

    monkeypatch.setattr(Table, "describe", describe)
