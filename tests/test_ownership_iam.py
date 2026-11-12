"""Engine workers can check ownership, but gain no ownership-write permission."""

from pathlib import Path

import pytest
import yaml
from test_infrastructure import Loader


@pytest.mark.parametrize("repo", ["opencdr-fleet-manager", "opencdr-internal"])
def test_fence_reads_and_condition_checks_match_each_touched_native_table(repo):
    root = Path(__file__).resolve().parents[2]
    path = root / repo / "serverless.yml"
    if not path.exists():
        pytest.skip("Sibling Core template checked in integration workspace")
    document = yaml.load(path.read_text(), Loader=Loader)
    checked = 0
    for name, function in document["functions"].items():
        statements = function.get("iamRoleStatements", [])
        for statement in statements:
            if statement.get("Condition", {}).get("ForAllValues:StringEquals", {}).get(
                "dynamodb:LeadingKeys"
            ) != ["OWNERSHIP"]:
                continue
            assert set(statement["Action"]) == {
                "dynamodb:GetItem",
                "dynamodb:ConditionCheckItem",
            }, name
            assert statement["Effect"] == "Allow"
            checked += 1
    assert checked >= 8
