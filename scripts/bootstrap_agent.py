#!/usr/bin/env python3
"""Create/reuse scoped Core keys and copy them to the security account, locally."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

import boto3
from botocore.exceptions import ClientError

from opencdr_fleet.models import registration


def scoped_key(gateway, plan_id: str, name: str) -> str:
    matches = [
        key
        for page in gateway.get_paginator("get_api_keys").paginate(nameQuery=name)
        for key in page.get("items", [])
        if key["name"] == name
    ]
    if len(matches) > 1:
        raise RuntimeError("Duplicate named keys exist; review them before onboarding")
    if matches:
        key = gateway.get_api_key(apiKey=matches[0]["id"], includeValue=True)
        if not key.get("enabled"):
            raise RuntimeError("Existing fleet key is disabled; review it before onboarding")
    else:
        key = gateway.create_api_key(name=name, enabled=True)
    try:
        gateway.create_usage_plan_key(usagePlanId=plan_id, keyId=key["id"], keyType="API_KEY")
    except ClientError as error:
        if error.response["Error"]["Code"] != "ConflictException":
            raise
        bound = [
            item["id"]
            for page in gateway.get_paginator("get_usage_plan_keys").paginate(usagePlanId=plan_id)
            for item in page.get("items", [])
        ]
        if key["id"] not in bound:
            raise RuntimeError(
                "Fleet key could not be verified in the selected usage plan"
            ) from None
    return key["value"]


def bootstrap(security, core, agent: dict, fleet_stage: str, security_account_id: str):
    if security.client("sts").get_caller_identity()["Account"] != security_account_id:
        raise RuntimeError("Security profile is authenticated to the wrong account")
    if core.client("sts").get_caller_identity()["Account"] != agent["account_id"]:
        raise RuntimeError("Core profile is authenticated to the wrong account")
    if agent.get("auth_mode", "legacy-api-key") == "iam":
        stack = security.client("cloudformation").describe_stacks(
            StackName=f"opencdr-fleet-manager-{fleet_stage}"
        )["Stacks"][0]
        outputs = {item["OutputKey"]: item["OutputValue"] for item in stack.get("Outputs", [])}
        required = [
            "PollRoleArn",
            "DetectionPollRoleArn",
            "ManagementObserverRoleArn",
            "ManagementOperatorRoleArn",
            "ManagementResponderRoleArn",
            "ManagementAdministratorRoleArn",
            "RolloutOperatorRoleArn",
            "RolloutResponderRoleArn",
            "RolloutAdministratorRoleArn",
        ]
        if any(key not in outputs for key in required):
            raise RuntimeError("Upgrade Fleet Manager before IAM onboarding")
        return {
            "auth_mode": "iam",
            "core_parameters": {
                "managementPrincipalArns": ",".join(outputs[key] for key in required)
            },
        }
    host = urlsplit(agent["api_url"]).hostname
    if not re.fullmatch(r"[a-z0-9]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com(?:\.cn)?", host):
        raise RuntimeError(
            "Bootstrap requires Core's execute-api URL; custom-domain keys can be imported manually"
        )
    gateway = core.client("apigateway")
    api_id = host.split(".")[0]
    plans = [
        plan["id"]
        for page in gateway.get_paginator("get_usage_plans").paginate()
        for plan in page.get("items", [])
        if any(
            stage.get("apiId") == api_id and stage.get("stage") == agent["stage"]
            for stage in plan.get("apiStages", [])
        )
    ]
    if len(plans) != 1:
        raise RuntimeError("Expected exactly one usage plan for this Core API and stage")
    params = security.client("ssm")
    prefix = f"/opencdr-fleet-manager/{fleet_stage}/agents/{agent['agent_id']}"
    kinds = [("read", "read")]
    if agent["allow_writes"]:
        kinds.append(("write", "read-rules-settings-ir_roles-ir_actions"))
    for kind, scopes in kinds:
        value = scoped_key(gateway, plans[0], f"opencdr-{agent['stage']}-api-key-fleet-{scopes}")
        params.put_parameter(
            Name=f"{prefix}/{kind}-key", Value=value, Type="SecureString", Overwrite=True
        )
    return [f"{prefix}/{kind}-key" for kind, _ in kinds]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--security-profile", required=True)
    parser.add_argument("--security-account-id", required=True)
    parser.add_argument("--region", default="us-east-1", help="Fleet manager region")
    parser.add_argument("--fleet-stage", default="prod")
    parser.add_argument("--core-profile", required=True)
    parser.add_argument("--file", required=True, help="Reviewed agent registration JSON")
    args = parser.parse_args()
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", args.fleet_stage):
        parser.error("invalid fleet stage")
    with Path(args.file).open() as source:
        agent = registration(json.load(source))
    security = boto3.Session(profile_name=args.security_profile, region_name=args.region)
    core = boto3.Session(profile_name=args.core_profile, region_name=agent["region"])
    try:
        names = bootstrap(security, core, agent, args.fleet_stage, args.security_account_id)
    except (RuntimeError, ClientError) as error:
        # Never print API key values or AWS response payloads.
        parser.error(
            str(error)
            if isinstance(error, RuntimeError)
            else "AWS rejected credential setup; verify profile permissions"
        )
    if isinstance(names, dict):
        print(json.dumps(names, indent=2))
        print("Apply these Core trust parameters, verify signed access, then register the agent.")
        return
    for name in names:
        print(f"Stored {name}")
    print("Credentials are ready. Register the reviewed file through the fleet API next.")


if __name__ == "__main__":
    main()
