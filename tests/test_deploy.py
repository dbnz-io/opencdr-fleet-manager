import importlib.util
from pathlib import Path
from unittest.mock import Mock

import pytest

spec = importlib.util.spec_from_file_location(
    "deploy", Path(__file__).resolve().parents[1] / "scripts/deploy.py"
)
deploy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)


@pytest.mark.parametrize("hosts", [None, "core.example.com,another.example.com"])
def test_deploy_omits_empty_serverless_parameter_and_uses_the_same_package(monkeypatch, hosts):
    args = [
        "deploy.py", "--profile", "security-admin", "--security-account-id", "735252692417",
        "--region", "us-east-1", "--stage", "dev",
    ]
    if hosts:
        args.extend(["--allowed-agent-hosts", hosts])
    monkeypatch.setattr(deploy.sys, "argv", args)
    session = Mock()
    session.client.return_value.get_caller_identity.return_value = {"Account": "735252692417"}
    monkeypatch.setattr(deploy.boto3, "Session", Mock(return_value=session))
    run = Mock()
    monkeypatch.setattr(deploy.subprocess, "run", run)
    deploy.main()
    build, package, execute = [call.args[0] for call in run.call_args_list]
    assert build[1].endswith("scripts/package.py")
    assert package[1] == "package" and execute[1:4] == ["deploy", "--package", ".serverless"]
    assert package[2:] == execute[4:]
    assert "--param=allowedAgentHosts=" not in package
    if hosts:
        assert f"--param=allowedAgentHosts={hosts}" in package
    assert run.call_args_list[1].kwargs["env"]["AWS_PROFILE"] == "security-admin"


def test_account_mismatch_fails_before_packaging_or_aws_changes(monkeypatch):
    monkeypatch.setattr(deploy.sys, "argv", [
        "deploy.py", "--profile", "security-admin", "--security-account-id", "735252692417",
    ])
    session = Mock()
    session.client.return_value.get_caller_identity.return_value = {"Account": "111111111111"}
    monkeypatch.setattr(deploy.boto3, "Session", Mock(return_value=session))
    run = Mock()
    monkeypatch.setattr(deploy.subprocess, "run", run)
    with pytest.raises(SystemExit):
        deploy.main()
    run.assert_not_called()


def test_package_only_explains_that_no_stack_was_deployed(monkeypatch, capsys):
    monkeypatch.setattr(deploy.sys, "argv", [
        "deploy.py", "--profile", "security-admin", "--security-account-id", "735252692417",
        "--stage", "prod", "--package-only",
    ])
    session = Mock()
    session.client.return_value.get_caller_identity.return_value = {"Account": "735252692417"}
    monkeypatch.setattr(deploy.boto3, "Session", Mock(return_value=session))
    run = Mock()
    monkeypatch.setattr(deploy.subprocess, "run", run)
    deploy.main()
    assert len(run.call_args_list) == 2
    assert run.call_args_list[1].args[0][1] == "package"
    assert "No AWS stack was created or updated" in capsys.readouterr().out
