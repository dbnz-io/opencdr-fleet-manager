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
