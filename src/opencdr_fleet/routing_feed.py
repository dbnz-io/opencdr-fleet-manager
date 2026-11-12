"""Fleet-owned ordered projection; never fan out to member Core while routing."""

import os
import time

from boto3.dynamodb.conditions import Key

from ._contracts.approval_contract import require
from ._contracts.case_store import digest, wire
from .detection_queries import handle
from .detections import Detections


class RoutingFeed:
    def __init__(self, store):
        self.store = store
        self.collection = Detections(store)

    def current(self, name):
        registration = self.store.get_agent(name)
        state = self.collection.checkpoint(name)
        require(
            os.getenv("DETECTION_POLLING_ENABLED", "true") == "true"
            and registration["enabled"]
            and state.get("automation_epoch")
            and state.get("registration_rev") == registration["rev"]
            and state.get("state") in {"ready", "catching_up"},
            "routing_projection_unavailable",
            409,
        )
        return registration, state

    def start(self, names):
        result = {}
        for name in names:
            registration, state = self.current(name)
            result[name] = {
                "table": self.collection.table.name,
                "epoch": state["automation_epoch"],
                "registration_rev": int(registration["rev"]),
                "sequence": int(state.get("last_sequence", 0)),
            }
        return result

    def read(self, name, position, limit):
        registration, state = self.current(name)
        require(
            position["table"] == self.collection.table.name
            and position["epoch"] == state["automation_epoch"]
            and position["registration_rev"] == registration["rev"],
            "routing_projection_binding_changed",
            409,
        )
        after, high = int(position["sequence"]), int(state.get("last_sequence", 0))
        require(after <= high, "routing_checkpoint_ahead", 409)
        items = []
        if after < high:
            items = self.collection.table.query(
                KeyConditionExpression=Key("pk").eq(
                    "ROUTING_FEED#" + name + "#" + position["epoch"]
                )
                & Key("sk").between(f"{after + 1:020d}", f"{high:020d}"),
                ConsistentRead=True,
                Limit=limit,
            )["Items"]
            require(bool(items), "routing_retention_gap", 410)
        for entry in items:
            require(
                entry["sequence"] == after + 1 and entry["expires_at"] > time.time(),
                "routing_retention_gap",
                410,
            )
            after += 1
        fences = [
            {
                "ConditionCheck": {
                    "TableName": self.collection.table.name,
                    "Key": wire({"pk": "AGENT#" + name, "sk": "CHECKPOINT"}),
                    "ConditionExpression": "generation = :generation AND automation_epoch = :epoch",
                    "ExpressionAttributeValues": wire(
                        {":generation": state["generation"], ":epoch": position["epoch"]}
                    ),
                }
            },
            {
                "ConditionCheck": {
                    "TableName": self.store.registry.name,
                    "Key": wire({"id": registration["id"]}),
                    "ConditionExpression": "rev = :rev AND enabled = :enabled",
                    "ExpressionAttributeValues": wire(
                        {":rev": registration["rev"], ":enabled": True}
                    ),
                }
            },
        ]
        return {
            "items": items,
            "position": {**position, "sequence": after},
            "has_more": after < high,
            "fences": fences,
        }

    def resolve(self, name, entry):
        code, value = handle(
            "/v1/detections/detail",
            {"agent_id": name, "detection_id": entry["detection_id"]},
            self.store,
        )
        require(
            code == 200 and digest(value["evidence"]) == entry["payload_sha256"],
            "routing_projection_evidence_changed",
            409,
        )
        return {
            "item": value["item"],
            "evidence": value["evidence"],
            "routing_eligibility": {
                "source": "live" if entry["automation_origin"] == "live" else "ineligible",
                "historical": entry["change_type"] != "detection.created",
            },
        }
