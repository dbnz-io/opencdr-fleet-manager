"""Fleet-owned, reviewed group/ring membership; selection never dispatches work."""

import json
import re
from concurrent.futures import ThreadPoolExecutor

from boto3.dynamodb.conditions import Key

from ._contracts.approval_contract import integer, plan, require, text
from ._contracts.case_contract import CaseError
from ._contracts.case_store import digest, public, wire
from .models import agent_id, cursor_decode, cursor_encode, now_iso, public_registration


def group_id(value):
    require(
        isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", value),
        "invalid_group_id",
    )
    return value


class Groups:
    def __init__(self, store, reviews):
        self.store, self.reviews, self.table = store, reviews, store.cache
        self.partition = "FLEET_GROUP#" + reviews.namespace

    def get(self, identity):
        group_id(identity)
        row = self.table.get_item(
            Key={"pk": self.partition, "sk": identity}, ConsistentRead=True
        ).get("Item")
        return json.loads(json.dumps(row, default=lambda value: int(value))) if row else None

    def visible(self, row, *, fresh=True):
        if fresh:
            self.reviews.authority.begin()
        allowed = self.reviews.visible(
            {
                "plan": {
                    "operation": "configuration.write",
                    "targets": [{"target_id": name} for name in row["agent_ids"]],
                }
            }
        )
        self.reviews.authority.fences()
        self.reviews.check_access()
        return allowed

    def prepare(self, operation):
        result = self.compile(operation, self.reviews.actor)
        return {key: result[key] for key in ["plan", "material"]}

    def compile(self, operation, actor):
        require(
            isinstance(operation, dict)
            and set(operation) == {"kind", "group_id", "expected_rev", "group"}
            and operation["kind"] == "group.configure",
            "invalid_group_operation",
        )
        identity = group_id(operation["group_id"])
        integer(operation["expected_rev"])
        value = operation["group"]
        required = {"title", "kind", "enabled", "agent_ids"}
        if isinstance(value, dict) and value.get("kind") == "allocation":
            required.add("desired")
        require(
            isinstance(value, dict) and set(value) == required,
            "invalid_group",
        )
        text(value["title"], 160)
        require(
            value["kind"] in {"group", "ring", "allocation"} and type(value["enabled"]) is bool,
            "invalid_group",
        )
        require(
            isinstance(value["agent_ids"], list) and 1 <= len(value["agent_ids"]) <= 100,
            "select_1_to_100_group_members",
        )
        names = sorted(agent_id(name) for name in value["agent_ids"])
        require(len(set(names)) == len(names), "duplicate_group_member")
        previous = self.get(identity)
        require(
            operation["expected_rev"] == int((previous or {}).get("rev", 0)),
            "group_revision_conflict",
            409,
        )
        targets = sorted(set(names) | set((previous or {}).get("agent_ids", [])))
        require(len(targets) <= 100, "group_change_scope_limit", 413)
        self.reviews.authority.begin()
        self.reviews.authority_for(
            self.reviews.actor, "mutate", targets, operation="configuration.write"
        )
        # Membership consists of stable registry IDs. Current registration revisions
        # are captured when resolving a selection, then independently pinned by
        # the rollout planner. No registry or polling settings are modified here.
        for name in names:
            self.store.get_agent(name)
        content = {**operation, "group": {**value, "agent_ids": names}}
        dependencies = {"previous": previous}
        if value["kind"] == "allocation":
            from .desired_allocations import resolve

            dependencies["compilation"] = resolve(self.store, actor, value["desired"])
        fixed = plan(
            {
                "operation": "configuration.write",
                "content_sha256": digest(content),
                "dependencies_sha256": digest(dependencies),
                "response_required": False,
                "targets": [
                    {
                        "target_id": name,
                        "registration_rev": 0,
                        "snapshot_sha256": digest(
                            {"owner": self.reviews.owner, "group": content, "target": name}
                        ),
                        "expected_revisions": {"group": operation["expected_rev"]},
                    }
                    for name in targets
                ],
            }
        )
        row = {
            "pk": self.partition,
            "sk": identity,
            "group_id": identity,
            **content["group"],
            "rev": operation["expected_rev"] + 1,
            "updated_by": actor,
            "updated_at": now_iso(),
        }
        guard = (
            {
                "ConditionExpression": "rev = :rev",
                "ExpressionAttributeValues": wire({":rev": operation["expected_rev"]}),
            }
            if previous
            else {"ConditionExpression": "attribute_not_exists(pk)"}
        )
        self.reviews.authority.fences()
        self.reviews.check_access()
        return {
            "plan": fixed,
            "material": {"content": content, "dependencies": dependencies},
            "writes": [
                {"Put": {"TableName": self.table.name, "Item": wire(row), **guard}},
                {
                    "Put": {
                        "TableName": self.table.name,
                        "Item": wire(
                            {
                                **row,
                                "pk": self.partition + "#VERSION#" + identity,
                                "sk": f"{row['rev']:012d}",
                            }
                        ),
                        "ConditionExpression": "attribute_not_exists(pk)",
                    }
                },
            ],
            "fences": [],
            "result": {
                "kind": "fleet_group",
                "group_id": identity,
                "group_rev": row["rev"],
                "group_sha256": digest(row),
                "runtime_activation": "not_applicable",
            },
        }

    def read(self, identity):
        row = self.get(identity)
        require(row and self.visible(row), "group_not_found", 404)
        return {"group": public(row)}

    def listing(self, query):
        require(set(query) <= {"limit", "after"}, "invalid_group_query")
        raw = query.get("limit", "20")
        require(
            isinstance(raw, str) and raw.isdigit() and 1 <= int(raw) <= 50, "invalid_group_limit"
        )
        context = digest({"owner": self.reviews.owner, "actor": self.reviews.actor})
        token = cursor_decode(query.get("after"))
        args = {
            "KeyConditionExpression": Key("pk").eq(self.partition),
            "ConsistentRead": True,
            "Limit": int(raw),
        }
        if token:
            require(
                set(token) == {"context", "last"} and token["context"] == context,
                "group_cursor_context_changed",
            )
            args["ExclusiveStartKey"] = {"pk": self.partition, "sk": group_id(token["last"])}
        self.reviews.authority.begin()
        page = self.table.query(**args)
        items = [public(row) for row in page["Items"] if self.visible(row, fresh=False)]
        self.reviews.authority.fences()
        self.reviews.check_access()
        after = (
            cursor_encode({"context": context, "last": page["LastEvaluatedKey"]["sk"]})
            if page.get("LastEvaluatedKey")
            else None
        )
        return {"items": items, "next_after": after, "snapshot": False}

    def resolve(self, identity, expected_rev):
        integer(expected_rev, 1)
        row = self.read(identity)["group"]
        require(row["enabled"] and row["rev"] == expected_rev, "group_disabled_or_changed", 409)

        def member(name):
            try:
                current = self.store.get_agent(name)
                return {
                    "agent_id": name,
                    "registration_rev": int(current["rev"]),
                    "registration_sha256": digest(public_registration(current)),
                    "enabled": current["enabled"],
                    "allow_writes": current["allow_writes"],
                }
            except CaseError:
                raise
            except Exception:
                return {"agent_id": name, "state": "unavailable"}

        with ThreadPoolExecutor(max_workers=8) as pool:
            targets = list(pool.map(member, row["agent_ids"]))
        latest = self.read(identity)["group"]
        require(latest["rev"] == expected_rev, "group_changed_during_resolution", 409)
        selection = {
            "group_id": identity,
            "group_rev": expected_rev,
            "targets": targets,
            **({"desired": row["desired"]} if row["kind"] == "allocation" else {}),
        }
        return {
            **selection,
            "selection_sha256": digest(selection),
            "dispatch_allowed": False,
            "detail": "Selection only. Create Core approvals, then freeze a reviewed rollout.",
        }
