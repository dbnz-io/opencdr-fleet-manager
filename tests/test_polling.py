import time

from opencdr_fleet.models import FleetError
from opencdr_fleet.polling import poll, redact


class FakeAgent:
    def __init__(
        self, registration, read_key, write_key=None, deadline=None, *, report=None, fail=None
    ):
        self.report, self.fail, self.requests = report, fail, 0

    def verify(self):
        self.requests += 1
        if self.fail == "identity":
            raise FleetError("agent_identity_mismatch", 409)
        return self.report

    def get(self, path):
        self.requests += 1
        if path == "/rules/runtime-status":
            return {"generation": "a", "status": "propagating"}
        if path == "/lists/admins":
            if self.fail == "list":
                raise FleetError("agent_unreachable", 502)
            return {"list_id": "admins", "rev": 2, "values": ["alice"]}
        if path == "/integrations":
            return {"parsers": [], "bucket": "ingestion"}
        raise AssertionError(path)

    def request(self, method, path, **kwargs):
        self.requests += 1
        assert method == "GET" and path == "/settings/global"
        return 200, {
            "rev": 1,
            "channels": {"slack": {"webhook_url": "secret-url", "enabled": True}},
        }

    def pages(self, path, query=None):
        self.requests += 1
        return iter(
            {
                "/rules": [{"rule_id": "login", "rule_kind": "signal", "rev": 3}],
                "/lists": [{"list_id": "admins", "rev": 2}],
                "/ir-roles": [],
            }[path]
        )


def factory(report, fail=None):
    return lambda *args, **kwargs: FakeAgent(*args, **kwargs, report=report, fail=fail)


def message(sequence=None):
    return {"agent_id": "account-a", "rev": 1, "sequence": sequence or int(time.time() * 1000)}


def test_complete_poll_preserves_agent_activation_and_scrubs_notification_secrets(
    store, agent_record, report
):
    assert poll(store, message(), factory(report)) == "published"
    state = store.get_status("account-a")
    assert state["health"] == "healthy"
    assert state["runtime"]["status"] == "propagating"  # not claimed active by fleet
    assert state["report"]["features"]["archive_enabled"] is True
    cached = store.configuration("account-a", 50)
    settings = next(
        item["document"] for item in cached["items"] if item["resource_key"] == "setting:global"
    )
    assert settings["channels"]["slack"]["webhook_url"] == "***REDACTED***"
    assert "secret-url" not in str(cached)


def test_failed_collection_keeps_last_complete_generation_and_marks_it_stale(
    store, agent_record, report
):
    seq = int(time.time() * 1000)
    poll(store, message(seq), factory(report))
    before = store.get_status("account-a")
    poll(store, message(seq + 1), factory(report, "list"))
    after = store.get_status("account-a")
    assert after["snapshot_generation"] == before["snapshot_generation"]
    assert after["configuration_success_ms"] == before["configuration_success_ms"]
    assert after["configuration_state"] == "failed"
    assert after["health"] == "degraded"


def test_identity_mismatch_does_not_cache_the_wrong_agents_configuration(
    store, agent_record, report
):
    poll(store, message(), factory(report, "identity"))
    state = store.get_status("account-a")
    assert state["health"] == "identity_mismatch"
    assert "snapshot_generation" not in state


def test_old_jobs_do_not_consume_an_agent_api_quota(store, agent_record, report):
    assert poll(store, message(int(time.time() * 1000) - 1801000), factory(report)) == "expired"
    assert store.get_status("account-a") == {}


def test_revision_unchanged_uses_one_health_request_and_change_refreshes(
    store, agent_record, report
):
    report["configuration"] = {"supported": True, "generation": "v1", "writing": False}
    seq = int(time.time() * 1000)
    poll(store, message(seq), factory(report))
    initial = store.get_status("account-a")
    poll(store, message(seq + 1), factory(report))
    reused = store.get_status("account-a")
    assert reused["snapshot_generation"] == initial["snapshot_generation"]
    assert reused["poll_request_count"] == 1
    assert reused["health"] == "healthy"
    report["configuration"]["generation"] = "v2"
    poll(store, message(seq + 2), factory(report))
    assert store.get_status("account-a")["poll_request_count"] > 1
    assert store.get_status("account-a")["core_configuration_generation"] == "v2"


def test_inflight_configuration_cannot_publish_a_snapshot(store, agent_record, report):
    report["configuration"] = {"supported": True, "generation": "v1", "writing": True}
    poll(store, message(), factory(report))
    state = store.get_status("account-a")
    assert state["configuration_state"] == "failed"
    assert "snapshot_generation" not in state
    assert state["estimated_monthly_poll_requests"] is None


def test_failed_health_check_preserves_full_collection_cost(store, agent_record, report):
    report["configuration"] = {"supported": True, "generation": "v1", "writing": False}
    seq = int(time.time() * 1000)
    poll(store, message(seq), factory(report))
    before = store.get_status("account-a")
    full_count = before["full_poll_request_count"]
    assert full_count > 1
    assert before["estimated_monthly_poll_requests"] == 1440 * 31 + (full_count - 1) * 24 * 31
    poll(store, message(seq + 1), factory(report, "identity"))
    failed = store.get_status("account-a")
    assert failed["poll_request_count"] == 1
    assert failed["full_poll_request_count"] == full_count
    assert failed["estimated_monthly_poll_requests"] == before["estimated_monthly_poll_requests"]
    poll(store, message(seq + 2), factory(report))
    reused = store.get_status("account-a")
    assert reused["poll_request_count"] == 1
    assert reused["full_poll_request_count"] == full_count


def test_invalid_previous_cost_measurement_forces_full_snapshot(store, agent_record, report):
    report["configuration"] = {"supported": True, "generation": "v1", "writing": False}
    seq = int(time.time() * 1000)
    poll(store, message(seq), factory(report))
    old = store.get_status("account-a")
    old["full_poll_request_count"] = 1
    store.status.put_item(Item=old)
    poll(store, message(seq + 1), factory(report))
    assert store.get_status("account-a")["full_poll_request_count"] > 1


def test_agent_without_generation_uses_full_poll_cost(store, agent_record, report):
    report["configuration"] = {"supported": True, "generation": "v1", "writing": False}
    seq = int(time.time() * 1000)
    poll(store, message(seq), factory(report))
    report.pop("configuration")
    poll(store, message(seq + 1), factory(report))
    after = store.get_status("account-a")
    assert "core_configuration_generation" not in after
    assert after["estimated_monthly_poll_requests"] == after["poll_request_count"] * 1440 * 31


def test_quota_is_flagged_without_modifying_the_agent(store, agent_record, report):
    report["management_api"]["monthly_quota"] = 10000
    poll(store, message(), factory(report))
    assert store.get_status("account-a")["quota_warning"] == "agent_quota_insufficient"


def test_redaction_covers_custom_channel_and_header_credentials():
    assert redact(
        {"channels": {"custom": {"password": "p", "api_key": "k", "headers": {"X": "h"}}}}
    ) == {
        "channels": {
            "custom": {
                "password": "***REDACTED***",
                "api_key": "***REDACTED***",
                "headers": "***REDACTED***",
            }
        }
    }


def test_redaction_covers_webhook_urls_and_custom_auth_fields():
    assert redact(
        {"targets": [{"url": "https://example.com/private-token", "auth": "secret"}]}
    ) == {"targets": [{"url": "***REDACTED***", "auth": "***REDACTED***"}]}


class InventoryAgent(FakeAgent):
    def pages(self, path, query=None):
        if path == "/configuration/inventory":
            self.requests += 1
            assert query["kind"] in {"settings", "integrations"}
            return iter(
                [{"resource_id": "extra-profile", "rev": 3}]
                if query["kind"] == "settings"
                else [{"resource_id": "extra-binding", "rev": 8}]
            )
        return super().pages(path, query)

    def request(self, method, path, **kwargs):
        if path == "/settings/extra-profile":
            self.requests += 1
            return 200, {
                "setting_id": "extra-profile",
                "rev": 3,
                "channels": {"webhook_url": "secret"},
            }
        if path == "/integrations/extra-binding":
            self.requests += 1
            return 200, {"integration_id": "extra-binding", "rev": 8, "credentials": "secret"}
        return super().request(method, path, **kwargs)


def test_inventory_discovers_unregistered_profiles_and_bindings_without_losing_redaction(
    store, agent_record, report
):
    report["capabilities"]["configuration_inventory"] = "1.0.0"
    assert (
        poll(store, message(), lambda *a, **kw: InventoryAgent(*a, **kw, report=report))
        == "published"
    )
    state = store.get_status("account-a")
    assert state["configuration_coverage"]["profile_and_binding_enumeration"] == "all_saved"
    assert state["configuration_coverage"]["settings_ids"] == ["extra-profile"]
    assert state["configuration_coverage"]["integration_ids"] == ["extra-binding"]
    cached = store.configuration("account-a", 50)
    assert "secret" not in str(cached)
    assert {x["resource_key"] for x in cached["items"]} >= {
        "setting:extra-profile",
        "integration:extra-binding",
    }


def test_inventory_revision_conflict_preserves_last_complete_snapshot(store, agent_record, report):
    first = int(time.time() * 1000)
    poll(store, message(first), factory(report))
    before = store.get_status("account-a")["snapshot_generation"]
    report["capabilities"]["configuration_inventory"] = "1.0.0"

    class Changed(InventoryAgent):
        def request(self, method, path, **kwargs):
            code, value = super().request(method, path, **kwargs)
            if path == "/settings/extra-profile":
                value["rev"] = 4
            return code, value

    poll(store, message(first + 1), lambda *a, **kw: Changed(*a, **kw, report=report))
    after = store.get_status("account-a")
    assert after["snapshot_generation"] == before
    assert after["configuration_state"] == "failed"
    assert after["error_code"] == "configuration_changed_during_collection"
