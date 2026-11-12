"""Monotonic Core-owned handling projection; evidence and TTL never change."""

from ._contracts.detection_query import canonical
from .models import FleetError
from .store import wire


def existing_operation(collection, key, existing, entry, digest):
    candidate = entry.get("handling")
    previous = existing.get("handling", {})
    if existing["payload_sha256"] != digest:
        raise FleetError("detection_evidence_conflict", 409)
    condition, values = "payload_sha256 = :digest", {":digest": digest}
    if candidate is not None:
        revision = int(previous.get("rev", 0))
        if (
            candidate["rev"] == revision
            and previous
            and canonical(candidate) != canonical(previous)
        ):
            raise FleetError("detection_handling_revision_conflict", 409)
        condition += " AND " + (
            "handling.rev = :rev" if previous else "attribute_not_exists(handling)"
        )
        if previous:
            values[":rev"] = revision
        if candidate["rev"] > revision:
            return {
                "Update": {
                    "TableName": collection.table.name,
                    "Key": wire(key),
                    "UpdateExpression": "SET handling = :handling",
                    "ConditionExpression": condition,
                    "ExpressionAttributeValues": wire({**values, ":handling": candidate}),
                }
            }
    return {
        "ConditionCheck": {
            "TableName": collection.table.name,
            "Key": wire(key),
            "ConditionExpression": condition,
            "ExpressionAttributeValues": wire(values),
        }
    }


def validate_state(value, *, allow_initial=False):
    from ._contracts.detection_handling import initial, validate

    if (
        not isinstance(value, dict)
        or set(value) != set(initial())
        or value.get("schema_version") != "1.0.0"
    ):
        raise ValueError("Invalid handling projection")
    if allow_initial and canonical(value) == canonical(initial()):
        return
    if type(value["rev"]) is not int or value["rev"] < 1:
        raise ValueError("Invalid handling revision")
    changes = {k: value[k] for k in ("status", "disposition", "assigned_to", "note")}
    links = []
    for link in value["external_refs"]:
        if (
            set(link)
            != {
                "integration_id",
                "incident_id",
                "url",
                "status",
                "provenance",
                "sync_state",
                "last_synced_at",
            }
            or link["provenance"] != "manual"
            or link["sync_state"] != "unverified"
            or link["last_synced_at"] is not None
        ):
            raise ValueError("Unverified integration state")
        links.append({k: link[k] for k in ("integration_id", "incident_id", "url", "status")})
    changes["external_refs"] = links
    validate(
        {
            "changes": changes,
            "reason": "validate",
            "expected_rev": value["rev"],
            "request_id": "0" * 32,
        },
        initial(),
    )
    if not isinstance(value["updated_at"], str) or not isinstance(value["updated_by"], str):
        raise ValueError("Handling attribution is required")
