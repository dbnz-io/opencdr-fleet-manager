"""One execution policy for signals, correlations and response consumers."""


def response_allowed(event: dict) -> bool:
    return (
        event.get("evaluation_mode", "production") == "production"
        and event.get("response_mode", "armed") in {"armed", "dry-run"}
        and (event.get("provenance") or {}).get("mode") != "analysis"
    )


def apply_execution_policy(event: dict) -> dict:
    if event.get("evaluation_mode", "production") != "production":
        event["notify"] = False
    if not response_allowed(event):
        event.update(response_module="", response_actions=[], resolved_response_actions=[])
    return event
