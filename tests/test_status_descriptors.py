from opencdr_fleet.polling import redact


def test_known_auth_descriptors_survive_but_arbitrary_secrets_remain_redacted():
    assert redact({"auth_mode": "observer", "response_authority": True}) == {
        "auth_mode": "observer",
        "response_authority": True,
    }
    assert redact({"auth_mode": "secret-value", "response_authority": "secret-value"}) == {
        "auth_mode": "***REDACTED***",
        "response_authority": "***REDACTED***",
    }
