import importlib.util
from pathlib import Path
from unittest.mock import Mock

import pytest

spec = importlib.util.spec_from_file_location(
    "bootstrap", Path(__file__).resolve().parents[1] / "scripts/bootstrap_agent.py"
)
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)


def sessions(agent_record):
    security, core, gateway, ssm = Mock(), Mock(), Mock(), Mock()
    security.client.side_effect = lambda service: {
        "sts": Mock(get_caller_identity=lambda: {"Account": "222222222222"}),
        "ssm": ssm,
    }[service]
    core.client.side_effect = lambda service: {
        "sts": Mock(get_caller_identity=lambda: {"Account": agent_record["account_id"]}),
        "apigateway": gateway,
    }[service]
    pages = {
        "get_usage_plans": [
            {"items": [{"id": "plan", "apiStages": [{"apiId": "abc123", "stage": "prod"}]}]}
        ],
        "get_api_keys": [{"items": []}],
    }
    gateway.get_paginator.side_effect = lambda operation: Mock(
        paginate=lambda **kwargs: pages[operation]
    )
    gateway.create_api_key.return_value = {"id": "key-id", "value": "secret-no-output"}
    return security, core, gateway, ssm


def test_onboarding_transfers_a_read_scoped_key_without_printing_it(agent_record, capsys):
    security, core, gateway, ssm = sessions(agent_record)
    names = bootstrap.bootstrap(security, core, agent_record, "prod", "222222222222")
    gateway.create_api_key.assert_called_once_with(
        name="opencdr-prod-api-key-fleet-read", enabled=True
    )
    assert names == ["/opencdr-fleet-manager/prod/agents/account-a/read-key"]
    assert ssm.put_parameter.call_args.kwargs["Value"] == "secret-no-output"
    assert ssm.put_parameter.call_args.kwargs["Type"] == "SecureString"
    assert "secret-no-output" not in capsys.readouterr().out


def test_onboarding_never_changes_aws_resources_if_security_profile_is_wrong(agent_record):
    security, core, gateway, ssm = sessions(agent_record)
    with pytest.raises(RuntimeError, match="wrong account"):
        bootstrap.bootstrap(security, core, agent_record, "prod", "999999999999")
    gateway.create_api_key.assert_not_called()
    ssm.put_parameter.assert_not_called()


def test_existing_disabled_key_is_not_silently_reenabled():
    gateway = Mock()
    gateway.get_paginator.return_value.paginate.return_value = [
        {"items": [{"id": "old", "name": "fleet-read"}]}
    ]
    gateway.get_api_key.return_value = {"enabled": False, "value": "secret"}
    with pytest.raises(RuntimeError, match="disabled"):
        bootstrap.scoped_key(gateway, "plan", "fleet-read")
    gateway.create_api_key.assert_not_called()
    gateway.create_usage_plan_key.assert_not_called()


def test_scoped_key_onboarding_uses_real_sdk_pagination_and_reuses_the_key(store):
    import boto3

    gateway = boto3.client("apigateway")
    plan = gateway.create_usage_plan(name="test-fleet")
    name = "opencdr-prod-api-key-fleet-read"
    first = bootstrap.scoped_key(gateway, plan["id"], name)
    second = bootstrap.scoped_key(gateway, plan["id"], name)
    assert first == second
    assert len(gateway.get_api_keys()["items"]) == 1
