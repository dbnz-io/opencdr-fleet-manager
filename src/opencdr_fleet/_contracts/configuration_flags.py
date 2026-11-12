"""Versioned runtime flag contract. Infrastructure flags come from pinned Deploy artifacts."""

from .approval_contract import require
from .case_store import digest

FLAGS = [
    {
        "id": "rule.enabled",
        "resource": "rule",
        "field": "enabled",
        "type": "boolean",
        "permission": "rule.write",
        "effect": "evaluator_refresh",
    },
    {
        "id": "rule.notify",
        "resource": "rule",
        "field": "notify",
        "type": "boolean",
        "permission": "rule.write",
        "effect": "future_detection_delivery",
    },
    {
        "id": "settings.notifications_enabled",
        "resource": "settings",
        "field": "notifications_enabled",
        "type": "boolean",
        "permission": "configuration.write",
        "effect": "future_notification_delivery",
    },
    {
        "id": "integration.enabled",
        "resource": "integration",
        "field": "enabled",
        "type": "boolean",
        "permission": "configuration.write",
        "effect": "future_ingestion",
    },
    {
        "id": "responder.enabled",
        "resource": "responder",
        "field": "enabled",
        "type": "boolean",
        "permission": "response.execute",
        "effect": "future_response_execution",
    },
]


def validate(resource, document):
    if not isinstance(document, dict):
        return
    for item in FLAGS:
        if item["resource"] == resource and item["field"] in document:
            require(type(document[item["field"]]) is bool, "runtime_flag_must_be_boolean")


def catalog():
    return {
        "schema_version": "1.0.0",
        "catalog_sha256": digest(FLAGS),
        "flags": FLAGS,
        "application": "reviewed_owner_mutation",
        "expected_revision_required": True,
        "activation_requires_verification": True,
        "infrastructure": {
            "application": "reviewed_deploy_plan",
            "authority": "deployment_iam",
            "catalog": "opencdr-deploy release flags <release-directory> --sha256 <manifest-digest>",
            "polling_roles_can_deploy": False,
        },
        "pause_semantics": {
            "web_connection": "web access only",
            "fleet_ingestion": "collection only",
            "runtime_flag": "explicit reviewed runtime mutation",
        },
    }
