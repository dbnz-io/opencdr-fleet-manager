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


def test_every_endpoint_has_iam_and_schedule_uses_configured_interval():
    template = yaml.load((ROOT / "serverless.yml").read_text(), Loader=Loader)
    functions = template["functions"]
    for event in functions["api"]["events"]:
        assert event["http"]["authorizer"] == "aws_iam"
    assert functions["schedule"]["events"][0]["schedule"]["rate"] == "rate(1 minute)"
    assert template["resources"]["extensions"]["ScheduleEventsRuleSchedule1"]["Properties"][
        "ScheduleExpression"
    ]["Fn::If"] == [
        "PollEveryMinute",
        "rate(1 minute)",
        "rate(${param:pollIntervalMinutes} minutes)",
    ]
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


def test_recovery_can_pin_evidence_bucket_without_renaming_existing_normal_deployments():
    template = yaml.load((ROOT / "serverless.yml").read_text(), Loader=Loader)
    assert template["params"]["default"]["detectionEvidenceBucketName"] == ""
    assert template["resources"]["Conditions"]["HasPinnedDetectionBucket"] == {
        "Not": [{"Equals": ["${param:detectionEvidenceBucketName}", ""]}]
    }
    binding = template["resources"]["Resources"]["DetectionBucket"]["Properties"]["BucketName"]
    assert binding == {
        "If": [
            "HasPinnedDetectionBucket",
            "${param:detectionEvidenceBucketName}",
            {"Ref": "AWS::NoValue"},
        ]
    }


def test_handoff_audit_write_is_limited_to_administrators_and_worker_cannot_create_core_plans():
    template = yaml.load((ROOT / "serverless.yml").read_text(), Loader=Loader)
    for name, function in template["functions"].items():
        statements = function.get("iamRoleStatements", [])
        if "HANDOFF#*" in str(statements):
            assert name in {"api", "managementAdministrator"}
    for name in ("api", "managementAdministrator"):
        statements = template["functions"][name]["iamRoleStatements"]
        assert "HANDOFF#*" in str(statements)
        assert any(
            s["Action"] == "dynamodb:ConditionCheckItem"
            and s["Resource"] == {"GetAtt": "DetectionTable.Arn"}
            for s in statements
        )
    worker = str(template["functions"]["detectionPoll"]["iamRoleStatements"])
    assert "management/delivery/detections/consumers/*" in worker
    assert "management/administrator" not in worker


def test_management_roles_cannot_escalate_via_registry_or_other_rollout_queues():
    template = yaml.load((ROOT / "serverless.yml").read_text(), Loader=Loader)
    for access in ("operator", "responder"):
        function = template["functions"]["management" + access.title()]
        assert function["environment"]["FLEET_MANAGEMENT_ACCESS"] == access
        assert "ssm:PutParameter" not in str(function["iamRoleStatements"])
        for statement in function["iamRoleStatements"]:
            if "dynamodb:PutItem" in statement.get("Action", []):
                keys = statement["Condition"]["ForAllValues:StringLike"]["dynamodb:LeadingKeys"]
                if statement["Resource"] == {"GetAtt": "CaseTable.Arn"}:
                    assert keys in (
                        ["CASE", "EXTENSION#*", "AUDIT#*", "REQUEST#*", "LINK#*"],
                        [
                            "REVIEW#*",
                            "REVIEW_INDEX#*",
                            "REVIEW_REQUEST#*",
                            "REVIEW_AUDIT#*",
                            "REVIEW_EXECUTION#*",
                            "ROUTING#*",
                            "ROUTING_ACTIVATION#*",
                            "ROUTING_DELIVERY#*",
                            "ROUTING_OUTCOME#*",
                        ],
                    )
                elif statement["Resource"] == {"GetAtt": "ConfigurationTable.Arn"}:
                    assert keys == ["FLEET_GROUP#*"]
                    assert statement["Action"] in {
                        "dynamodb:PutItem",
                        "dynamodb:ConditionCheckItem",
                    }
                elif statement["Resource"] == {"GetAtt": "DetectionTable.Arn"}:
                    assert keys == ["AGENT#*"]
                    assert statement["Action"] == "dynamodb:ConditionCheckItem"
                elif statement["Resource"] == {"GetAtt": "LibraryTable.Arn"}:
                    assert keys == [
                        "ITEM",
                        "IDENTITY#*",
                        "VERSION#*",
                        "AUDIT#*",
                        "REQUEST#*",
                        "RELEASE",
                        "TEST#*",
                        "COMPILE#*",
                        "MAPPING#*",
                    ]
                else:
                    assert statement["Resource"] == {"GetAtt": "RolloutTable.Arn"}
                    assert keys == [access + "-*"]
    for function in ("poll", "managementObserver"):
        statements = template["functions"][function]["iamRoleStatements"]
        invocations = [s["Resource"] for s in statements if s["Action"] == "execute-api:Invoke"]
        assert invocations and all("/GET/management/observer/" in str(r) for r in invocations)


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


def test_library_resources_retained_and_writes_are_authoring_only():
    config = yaml.load((ROOT / "serverless.yml").read_text(), Loader=Loader)
    for name in ["LibraryTable", "LibraryBucket"]:
        resource = config["resources"]["Resources"][name]
        assert resource["DeletionPolicy"] == resource["UpdateReplacePolicy"] == "Retain"
        assert "TimeToLiveSpecification" not in resource["Properties"]
    assert (
        config["resources"]["Resources"]["LibraryBucket"]["Properties"]["VersioningConfiguration"][
            "Status"
        ]
        == "Enabled"
    )
    for name, fn in config["functions"].items():
        statements = [s for s in fn.get("iamRoleStatements", []) if "Library" in str(s["Resource"])]
        assert bool(statements) == (
            name
            in {
                "api",
                "managementObserver",
                "managementTriage",
                "managementOperator",
                "managementResponder",
                "managementAdministrator",
            }
        )
        actions = {
            action
            for s in statements
            for action in ([s["Action"]] if isinstance(s["Action"], str) else s["Action"])
        }
        assert not actions & {"dynamodb:DeleteItem", "dynamodb:UpdateItem", "s3:DeleteObject"}
        assert ("dynamodb:PutItem" in actions) == (
            name in {"api", "managementOperator", "managementResponder", "managementAdministrator"}
        )


def test_polling_uses_a_queue_cap_without_reserving_account_concurrency():
    template = yaml.load((ROOT / "serverless.yml").read_text(), Loader=Loader)
    poll = template["functions"]["poll"]
    assert "reservedConcurrency" not in poll
    assert template["params"]["default"]["pollConcurrency"] == 2
    assert poll["events"][0]["sqs"]["maximumConcurrency"] == "${param:pollConcurrency}"


def test_detection_collection_is_independent_with_narrow_delivery_access():
    template = yaml.load((ROOT / "serverless.yml").read_text(), Loader=Loader)
    functions, resources = template["functions"], template["resources"]["Resources"]
    worker = functions["detectionPoll"]
    permissions = str(worker["iamRoleStatements"])
    assert "dynamodb:ConditionCheckItem" in permissions
    assert any(
        statement["Resource"] == {"GetAtt": "DetectionTable.Arn"}
        and "dynamodb:ConditionCheckItem" in statement["Action"]
        for statement in worker["iamRoleStatements"]
    )
    assert "/GET/management/observer/" in permissions
    assert "/POST/management/delivery/detections/consumers/" in permissions
    assert "/GET/management/delivery/detections/consumers/" in permissions
    assert "/POST/management/delivery/" not in str(functions["poll"]["iamRoleStatements"])
    assert "ssm:" not in permissions and "sts:AssumeRole" not in permissions
    assert "write-key" not in permissions and "/management/operator/" not in permissions
    assert worker["events"][0]["sqs"]["batchSize"] == 1
    assert resources["DetectionQueue"]["Properties"]["VisibilityTimeout"] >= 6 * worker["timeout"]
    assert (
        functions["detectionSchedule"]["events"][0]["schedule"]["enabled"]
        == "${strToBool(${param:detectionPollingEnabled})}"
    )
    for name in ("DetectionTable", "DetectionBucket"):
        assert (
            resources[name]["DeletionPolicy"] == resources[name]["UpdateReplacePolicy"] == "Retain"
        )
    assert resources["DetectionTable"]["Properties"]["PointInTimeRecoverySpecification"][
        "PointInTimeRecoveryEnabled"
    ]
    projection = resources["DetectionTable"]["Properties"]["GlobalSecondaryIndexes"][0][
        "Projection"
    ]
    assert projection["ProjectionType"] == "INCLUDE"
    assert "payload" not in projection["NonKeyAttributes"]
    assert all(
        resources["DetectionBucket"]["Properties"]["PublicAccessBlockConfiguration"].values()
    )


def test_triage_roles_are_narrow_and_projection_worker_can_update_only_local_state():
    template = yaml.load((ROOT / "serverless.yml").read_text(), Loader=Loader)
    functions = template["functions"]
    triage = functions["managementTriage"]
    assert triage["environment"]["FLEET_MANAGEMENT_ACCESS"] == "triage"
    policy = str(triage["iamRoleStatements"])
    assert "/PUT/management/triage/detections/handling" in policy
    assert "/management/operator/" not in policy and "/management/responder/" not in policy
    for name in ("managementObserver", "detectionPoll", "poll"):
        assert "/PUT/management/triage/" not in str(functions[name]["iamRoleStatements"])
    writes = [
        row
        for row in functions["detectionPoll"]["iamRoleStatements"]
        if "DetectionTable" in str(row["Resource"])
    ]
    assert "dynamodb:UpdateItem" in str(writes)


def test_case_storage_retention_and_account_grant_write_authority():
    template = yaml.load((ROOT / "serverless.yml").read_text(), Loader=Loader)
    resources, functions = template["resources"]["Resources"], template["functions"]
    assert resources["CaseTable"]["DeletionPolicy"] == "Retain"
    assert resources["CaseBucket"]["DeletionPolicy"] == "Retain"
    assert "TimeToLiveSpecification" not in resources["CaseTable"]["Properties"]
    assert "LifecycleConfiguration" not in resources["CaseBucket"]["Properties"]
    assert resources["CaseTable"]["Properties"]["PointInTimeRecoverySpecification"][
        "PointInTimeRecoveryEnabled"
    ]
    assert all(resources["CaseBucket"]["Properties"]["PublicAccessBlockConfiguration"].values())
    for name in [
        "api",
        "managementObserver",
        "managementTriage",
        "managementOperator",
        "managementResponder",
        "managementAdministrator",
    ]:
        grantWrites = [
            s
            for s in functions[name]["iamRoleStatements"]
            if s["Resource"] == {"GetAtt": "CaseTable.Arn"}
            and s["Action"] == "dynamodb:PutItem"
            and "ACCESS" in str(s.get("Condition"))
        ]
        assert bool(grantWrites) == (name in {"api", "managementAdministrator"})
    for name in ["poll", "detectionPoll"]:
        assert "CaseTable" not in str(functions[name]["iamRoleStatements"])
        assert "CaseBucket" not in str(functions[name]["iamRoleStatements"])


def test_authoring_evidence_partitions_are_allowed_only_for_library_writers():
    config = yaml.load((ROOT / "serverless.yml").read_text(), Loader=Loader)
    expected = {
        "ITEM",
        "IDENTITY#*",
        "VERSION#*",
        "AUDIT#*",
        "REQUEST#*",
        "RELEASE",
        "TEST#*",
        "COMPILE#*",
        "MAPPING#*",
    }
    for name, fn in config["functions"].items():
        writes = [
            s
            for s in fn.get("iamRoleStatements", [])
            if "LibraryTable" in str(s["Resource"]) and s["Action"] == "dynamodb:PutItem"
        ]
        for statement in writes:
            assert name in {
                "api",
                "managementOperator",
                "managementResponder",
                "managementAdministrator",
            }
            assert (
                set(statement["Condition"]["ForAllValues:StringLike"]["dynamodb:LeadingKeys"])
                == expected
            )


def test_p4_identity_epoch_writer_is_limited_to_identity_administrators():
    for path, allowed in [
        (ROOT / "serverless.yml", {"api", "managementAdministrator"}),
    ]:
        template = yaml.load(path.read_text(), Loader=Loader)
        found = set()
        for name, function in template["functions"].items():
            for statement in function.get("iamRoleStatements", []):
                actions = (
                    statement["Action"]
                    if isinstance(statement["Action"], list)
                    else [statement["Action"]]
                )
                if "IDENTITY_AUTHORITY" not in str(statement) or not set(actions) & {
                    "dynamodb:PutItem",
                    "dynamodb:UpdateItem",
                    "dynamodb:DeleteItem",
                }:
                    continue
                found.add(name)
                assert statement["Action"] == "dynamodb:UpdateItem"
                assert statement["Resource"] == {"GetAtt": "CaseTable.Arn"}
                assert statement["Condition"] == {
                    "ForAllValues:StringEquals": {"dynamodb:LeadingKeys": ["IDENTITY_AUTHORITY"]}
                }
        assert found == allowed


def test_review_grant_and_policy_writes_are_only_owned_by_administrators():
    for path, admins in [
        (ROOT / "serverless.yml", {"api", "managementAdministrator"}),
    ]:
        template = yaml.load(path.read_text(), Loader=Loader)
        writers = set()
        for name, function in template["functions"].items():
            for statement in function.get("iamRoleStatements", []):
                keys = (
                    statement.get("Condition", {})
                    .get("ForAllValues:StringLike", {})
                    .get("dynamodb:LeadingKeys", [])
                )
                actions = (
                    statement["Action"]
                    if isinstance(statement["Action"], list)
                    else [statement["Action"]]
                )
                if ("REVIEW_GRANT#*" in keys or "REVIEW_POLICY" in keys) and set(actions) & {
                    "dynamodb:PutItem",
                    "dynamodb:UpdateItem",
                    "dynamodb:DeleteItem",
                }:
                    assert name in admins
                    assert statement["Action"] == "dynamodb:PutItem"
                    assert statement["Resource"] == {"GetAtt": "CaseTable.Arn"}
                    writers.add(name)
                if name not in admins and statement["Resource"] == {"GetAtt": "CaseTable.Arn"}:
                    assert not any(k in {"*", "REVIEW*", "REVIEW_*"} for k in keys)
        assert writers == admins


def test_reviewed_workers_can_only_read_and_fence_owner_authority():
    template = yaml.load((ROOT / "serverless.yml").read_text(), Loader=Loader)
    assert template["params"]["default"]["reviewEnforcement"] == "true"
    for name in ("rolloutOperator", "rolloutResponder", "rolloutAdministrator"):
        authority = [
            s
            for s in template["functions"][name]["iamRoleStatements"]
            if s["Resource"] == {"GetAtt": "CaseTable.Arn"}
        ]
        assert len(authority) == 2
        ownership = [s for s in authority if "ForAllValues:StringEquals" in s.get("Condition", {})]
        assert len(ownership) == 1
        assert ownership[0]["Condition"]["ForAllValues:StringEquals"]["dynamodb:LeadingKeys"] == [
            "OWNERSHIP"
        ]
        assert set(ownership[0]["Action"]) == {"dynamodb:GetItem", "dynamodb:ConditionCheckItem"}
        authority = [s for s in authority if s not in ownership]
        assert len(authority) == 1
        assert set(authority[0]["Action"]) == {"dynamodb:GetItem", "dynamodb:ConditionCheckItem"}
        assert set(
            authority[0]["Condition"]["ForAllValues:StringLike"]["dynamodb:LeadingKeys"]
        ) == {
            "REVIEW_POLICY",
            "REVIEW#*",
            "REVIEW_GRANT#*",
            "IDENTITY_SUBJECT",
            "IDENTITY_ISSUER",
            "IDENTITY_AUTHORITY",
        }
    poll = str(template["functions"]["poll"]["iamRoleStatements"])
    assert "cloudformation:" not in poll and "lambda:UpdateFunction" not in poll


def test_new_openapi_routes_and_local_references_resolve():
    spec = yaml.safe_load((ROOT / "openapi.yml").read_text())
    for path in [
        "/v1/reviews",
        "/v1/review-policy",
        "/v1/rollouts/{rollout_id}/prepare",
        "/v1/rollouts/{rollout_id}/cancel",
        "/v1/rollouts/{rollout_id}/reconcile/{agent_id}",
    ]:
        assert path in spec["paths"]
    plan = spec["paths"]["/v1/rollouts/plan"]["post"]["requestBody"]["content"]["application/json"][
        "schema"
    ]
    assert plan["properties"]["targets"]["maxItems"] == 100

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "$ref":
                    assert value.startswith("#/")
                    current = spec
                    for part in value[2:].split("/"):
                        current = current[part]
                else:
                    walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(spec)


def test_routing_and_allocations_have_narrow_atomic_checkpoint_permissions():
    template = yaml.load((ROOT / "serverless.yml").read_text(), Loader=Loader)
    functions = template["functions"]
    for name in ["api", "managementOperator", "managementResponder", "managementAdministrator"]:
        statements = functions[name]["iamRoleStatements"]
        assert any(
            s["Action"] == "dynamodb:ConditionCheckItem"
            and s["Resource"] == {"GetAtt": "ConfigurationTable.Arn"}
            and s["Condition"]["ForAllValues:StringLike"]["dynamodb:LeadingKeys"]
            == ["FLEET_GROUP#*"]
            for s in statements
        )
    for name in ["managementOperator", "managementResponder"]:
        assert any(
            s["Action"] == "dynamodb:ConditionCheckItem"
            and s["Resource"] == {"GetAtt": "DetectionTable.Arn"}
            and s["Condition"]["ForAllValues:StringLike"]["dynamodb:LeadingKeys"] == ["AGENT#*"]
            for s in functions[name]["iamRoleStatements"]
        )
    for name in [
        "poll",
        "detectionPoll",
        "rolloutOperator",
        "rolloutResponder",
        "rolloutAdministrator",
    ]:
        assert "subscriber-*" not in str(functions[name]["iamRoleStatements"])
    for name in [
        "api",
        "managementObserver",
        "managementOperator",
        "managementResponder",
        "managementAdministrator",
        "managementTriage",
    ]:
        assert "consumers/subscriber-*" in str(functions[name]["iamRoleStatements"])


def test_historical_extensions_do_not_grant_connector_or_polling_mutations():
    template = yaml.load((ROOT / "serverless.yml").read_text(), Loader=Loader)
    for name in ["managementIntegration", "poll", "detectionPoll"]:
        statements = template["functions"][name]["iamRoleStatements"]
        for statement in statements:
            if "dynamodb:PutItem" in statement.get("Action", []):
                assert "EXTENSION#*" not in str(statement)
