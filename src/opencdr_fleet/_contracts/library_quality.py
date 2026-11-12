"""Immutable native test evidence and compilation. No runtime mutations."""

from time import monotonic

from .case_contract import identifier
from .case_store import digest, stamp
from .detection_query import canonical
from .library_contract import MAX_RELEASE_ITEMS, LibraryError, command, references


class LibraryQuality:
    def native(self):
        if self.evaluator is None:
            raise LibraryError("library_evaluator_unavailable", 503)
        return self.evaluator

    def closure(self, roots):
        pending, found, identities = list(roots), {}, {}
        while pending:
            ref = pending.pop()
            if ref["content_id"] in found:
                old = found[ref["content_id"]][0]
                if any(old[k] != ref[k] for k in ("version", "artifact_sha256")):
                    raise LibraryError("library_dependency_version_conflict", 409)
                continue
            if len(found) >= MAX_RELEASE_ITEMS:
                raise LibraryError("library_release_dependency_limit", 413)
            row = self.check_reference(ref)
            artifact = self.artifact(row)
            identity = (row["kind"], row["runtime_id"])
            if identity in identities:
                raise LibraryError("library_runtime_identity_conflict", 409)
            identities[identity] = row["content_id"]
            found[row["content_id"]] = (row, artifact)
            pending.extend(row["dependencies"])
        return found

    def quality_artifact(self, partition, identity, body, metadata, operation, request):
        from .library_store import view

        if len(canonical(body).encode()) > 131072:
            raise LibraryError("library_artifact_too_large", 413)
        fingerprint = digest(body)
        key = f"library/quality/{partition}/{identity}/{fingerprint}.json"
        row = {
            "pk": partition,
            "sk": identity,
            **metadata,
            "artifact_key": key,
            "artifact_sha256": fingerprint,
            "created_at": stamp(),
            "created_by": self.actor,
            "request_id": request["request_id"],
            "reason": request["reason"],
        }
        self.put_artifact(key, body)
        return self.commit(operation, request, {"record": view(row)}, [self.put(row)])

    def test_version(self, content_id, body):
        command(body, {"reference", "events", "expected_matches"})
        identifier(content_id)
        ref = references([body["reference"]])[0]
        if ref["content_id"] != content_id:
            raise LibraryError("library_reference_identity_mismatch")
        events, expected = body["events"], body["expected_matches"]
        if (
            not isinstance(events, list)
            or len(events) > 100
            or any(not isinstance(e, dict) for e in events)
            or not isinstance(expected, list)
            or any(type(i) is not int or not 0 <= i < len(events) for i in expected)
            or expected != sorted(set(expected))
        ):
            raise LibraryError("invalid_library_fixture")
        operation = "test:" + content_id
        prior = self.receipt(operation, body)
        if prior:
            return prior
        native = self.native()
        closure = self.closure([ref])
        row, artifact = closure[content_id]
        lists = {r["runtime_id"]: a["document"] for r, a in closure.values() if r["kind"] == "list"}
        if row["kind"] != "list" and not events:
            raise LibraryError("library_rule_fixture_requires_events")
        if row["kind"] == "list" and (events or expected):
            raise LibraryError("library_list_test_has_no_events")
        started = monotonic()
        try:
            dependency_errors = [
                error
                for value in lists.values()
                for error in native.validate(value, lists)["errors"]
            ]
            result = (
                {
                    "valid": False,
                    "errors": dependency_errors,
                    "matches": [],
                    "evaluated": 0,
                    "skipped": 0,
                }
                if dependency_errors
                else native.evaluate(artifact["document"], events, lists)
            )
            actual = sorted({m["event_index"] for m in result["matches"]})
            disposition = (
                "invalid" if not result["valid"] else ("passed" if actual == expected else "failed")
            )
        except TimeoutError:
            result, disposition = {"valid": False, "code": "evaluation_budget_exceeded"}, "timeout"
        except (ValueError, TypeError, KeyError, OverflowError):
            result, disposition = {"valid": False, "code": "invalid_evaluation_fixture"}, "invalid"
        evaluator = native.provenance()
        evidence = {
            "schema_version": "1.0.0",
            "reference": ref,
            "dependencies": [
                dict(
                    content_id=r["content_id"],
                    version=int(r["version"]),
                    artifact_sha256=r["artifact_sha256"],
                )
                for r, _ in sorted(closure.values(), key=lambda pair: pair[0]["content_id"])
            ],
            "fixture": {"events": events, "expected_matches": expected},
            "result": result,
            "disposition": disposition,
            "evaluator": evaluator,
            "elapsed_ms": round((monotonic() - started) * 1000),
            "operational_effects": False,
        }
        identity = digest({"actor": self.actor, "request_id": body["request_id"]})[:32]
        return self.quality_artifact(
            "TEST#" + content_id,
            identity,
            evidence,
            {
                "test_id": identity,
                "reference": ref,
                "disposition": disposition,
                "fixture_sha256": digest(evidence["fixture"]),
                "evaluator_sha256": evaluator["sha256"],
                "elapsed_ms": evidence["elapsed_ms"],
            },
            operation,
            body,
        )

    def quality_read(self, partition, identity):
        from .library_store import view

        row = self.required(partition, identifier(identity))
        artifact = self.artifact(row)
        freshness = {
            "observed_at": stamp(),
            "evaluator_current": artifact.get("evaluator", {}).get("sha256")
            == self.native().provenance()["sha256"],
        }
        ref = artifact.get("reference")
        if ref:
            freshness["latest_version"] = int(
                self.item(ref["content_id"])["latest_version"]
            ) == int(ref["version"])
        return {"record": view(row), "artifact": artifact, "freshness": freshness}

    def compile_release(self, release_id, body):
        command(body, {"artifact_sha256"})
        identifier(release_id)
        operation = "compile:" + release_id
        prior = self.receipt(operation, body)
        if prior:
            return prior
        release = self.required("RELEASE", release_id)
        if body["artifact_sha256"] != release["artifact_sha256"]:
            raise LibraryError("library_reference_digest_mismatch", 409)
        frozen = self.artifact(release)
        closure = self.closure(frozen["roots"])
        native = self.native()
        lists = {r["runtime_id"]: a["document"] for r, a in closure.values() if r["kind"] == "list"}
        errors, rules = [], []
        for row, artifact in sorted(closure.values(), key=lambda pair: pair[0]["content_id"]):
            validation = native.validate(artifact["document"], lists)
            errors.extend(
                {"content_id": row["content_id"], **error} for error in validation["errors"]
            )
            if row["kind"] != "list":
                rules.append(artifact["document"])
        manifest = None
        if rules:
            manifest = {
                "release_id": release_id,
                "release_version": release["artifact_sha256"],
                "contract_version": native.RULE_CONTRACT_VERSION,
                "rules": rules,
                "removal_policy": "ignore",
            }
            validation = native.validate_manifest(manifest)
            errors.extend(validation["errors"])
            manifest["manifest_digest"] = native.manifest_digest(manifest)
        artifact = {
            "schema_version": "1.0.0",
            "release_id": release_id,
            "source_artifact_sha256": release["artifact_sha256"],
            "evaluator": native.provenance(),
            "valid": not errors,
            "errors": errors,
            "rule_manifest": manifest,
            "lists": [lists[k] for k in sorted(lists)],
            "dependency_order": ["lists", "rules"],
            "deployment_state": "not_requested",
            "runtime_state": {"desired": None, "stored": None, "active": None},
            "promotion_requires_review": True,
            "rollback_requires_review": True,
        }
        identity = digest({"actor": self.actor, "request_id": body["request_id"]})[:32]
        return self.quality_artifact(
            "COMPILE#" + release_id,
            identity,
            artifact,
            {
                "compilation_id": identity,
                "release_id": release_id,
                "valid": not errors,
                "source_artifact_sha256": release["artifact_sha256"],
            },
            operation,
            body,
        )

    def map_legacy_release(self, release_id, body):
        command(body, {"compilation_id", "legacy_manifest", "manifest_digest"})
        identifier(release_id)
        operation = "mapping:" + release_id
        prior = self.receipt(operation, body)
        if prior:
            return prior
        compilation = self.required("COMPILE#" + release_id, identifier(body["compilation_id"]))
        compiled = self.artifact(compilation)
        native = self.native()
        legacy = body["legacy_manifest"]
        validation = native.validate_manifest(legacy)
        if not validation["valid"] or native.manifest_digest(legacy) != body["manifest_digest"]:
            raise LibraryError("library_legacy_manifest_invalid", 409)
        if not compiled["valid"] or not compiled["rule_manifest"]:
            raise LibraryError("library_compilation_invalid", 409)
        # Compare authored content; only documented top-level runtime observations
        # are excluded. Conditions and nested values are compared without stripping.
        observations = {
            "rev",
            "timestamp",
            "created_by",
            "updated_by",
            "rule_version",
            "release_id",
            "release_version",
            "content_fingerprint",
            "catalog_generation",
        }

        def rules(manifest):
            return sorted(
                (
                    {k: v for k, v in rule.items() if k not in observations}
                    for rule in manifest["rules"]
                ),
                key=lambda r: (r["rule_kind"], r["rule_id"]),
            )

        if rules(legacy) != rules(compiled["rule_manifest"]):
            raise LibraryError("library_legacy_content_mismatch", 409)
        identity = digest({"actor": self.actor, "request_id": body["request_id"]})[:32]
        artifact = {
            "schema_version": "1.0.0",
            "release_id": release_id,
            "compilation_id": body["compilation_id"],
            "compilation_sha256": compilation["artifact_sha256"],
            "legacy_manifest": legacy,
            "manifest_digest": body["manifest_digest"],
            "verification": "content_equivalence",
            "evaluator": native.provenance(),
            "runtime_state": {"desired": None, "stored": None, "active": None},
            "deployment_state": "not_requested",
            "rollback_requires_review": True,
        }
        return self.quality_artifact(
            "MAPPING#" + release_id,
            identity,
            artifact,
            {
                "mapping_id": identity,
                "release_id": release_id,
                "compilation_id": body["compilation_id"],
                "legacy_release_id": legacy["release_id"],
                "legacy_release_version": legacy["release_version"],
                "manifest_digest": body["manifest_digest"],
                "verification": "content_equivalence",
            },
            operation,
            body,
        )
