from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


class Loader(yaml.SafeLoader):
    pass


def intrinsic(loader, suffix, node):
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node)
    else:
        value = loader.construct_mapping(node)
    return {suffix: value}


Loader.add_multi_constructor("!", intrinsic)


def test_every_endpoint_has_iam_and_schedule_is_one_minute():
    template = yaml.load((ROOT / "serverless.yml").read_text(), Loader=Loader)
    functions = template["functions"]
    for event in functions["api"]["events"]:
        assert event["http"]["authorizer"] == "aws_iam"
    assert functions["schedule"]["events"][0]["schedule"]["rate"] == "rate(1 minute)"
    source = functions["poll"]["events"][0]["sqs"]
    assert source["functionResponseType"] == "ReportBatchItemFailures"
    assert source["batchSize"] == 1
    resources = template["resources"]["Resources"]
    assert (
        resources["PollQueue"]["Properties"]["VisibilityTimeout"]
        >= 6 * functions["poll"]["timeout"]
    )
    for name in ["RegistryTable", "StatusTable", "ConfigurationTable"]:
        assert resources[name]["DeletionPolicy"] == "Retain"
        assert resources[name]["UpdateReplacePolicy"] == "Retain"
        assert resources[name]["Properties"]["SSESpecification"]["SSEEnabled"] is True


def test_poller_cannot_read_operator_keys_or_send_commands_to_agents():
    template = yaml.load((ROOT / "serverless.yml").read_text(), Loader=Loader)
    statements = template["functions"]["poll"]["iamRoleStatements"]
    assert "write-key" not in str(statements)
    assert "ssm:PutParameter" not in str(statements)
    assert "sts:AssumeRole" not in str(statements)
    assert template["package"]["artifact"] == "build/fleet-manager.zip"


def test_openapi_covers_deployed_routes_and_contract_version():
    template = yaml.load((ROOT / "serverless.yml").read_text(), Loader=Loader)
    spec = yaml.safe_load((ROOT / "openapi.yml").read_text())
    assert spec["info"]["version"] == "1.0.0"
    assert spec["security"] == [{"awsSigV4": []}]
    for event in template["functions"]["api"]["events"]:
        path = "/" + event["http"]["path"].replace("{proxy+}", "{proxy}")
        assert path in spec["paths"]
        method = event["http"]["method"]
        if method != "any":
            assert method in spec["paths"][path]


def test_polling_uses_a_queue_cap_without_reserving_account_concurrency():
    template = yaml.load((ROOT / 'serverless.yml').read_text(), Loader=Loader)
    poll = template['functions']['poll']
    assert 'reservedConcurrency' not in poll
    assert template['params']['default']['pollConcurrency'] == 2
    assert poll['events'][0]['sqs']['maximumConcurrency'] == '${param:pollConcurrency}'
