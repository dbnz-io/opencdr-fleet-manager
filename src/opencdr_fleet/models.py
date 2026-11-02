"""Validation and transport contracts. Core remains authoritative for agent state."""

from __future__ import annotations

import base64
import json
import os
import re
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any
from urllib.parse import urlsplit

ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
RESOURCE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
REGION = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-\d$")
MAX_RESPONSE = 2_000_000


class FleetError(Exception):
    def __init__(self, code: str, status: int = 400):
        self.code, self.status = code, status
        super().__init__(code)


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


def json_text(value: Any) -> str:
    def encode(item):
        if isinstance(item, Decimal):
            return int(item) if item == int(item) else float(item)
        raise TypeError(type(item).__name__)

    return json.dumps(
        value, default=encode, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )


def agent_id(value: str) -> str:
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise FleetError("invalid_agent_id")
    return value


def endpoint(value: str, region: str) -> str:
    if not isinstance(value, str) or any(c.isspace() or ord(c) < 32 for c in value):
        raise FleetError("invalid_agent_url")
    try:
        url = urlsplit(value)
        valid = (
            url.scheme == "https"
            and url.port in (None, 443)
            and url.hostname
            and not url.username
            and not url.password
            and not url.query
            and not url.fragment
        )
    except ValueError:
        valid = False
    if not valid:
        raise FleetError("invalid_agent_url")
    suffix = "amazonaws.com.cn" if region.startswith("cn-") else "amazonaws.com"
    aws_host = re.fullmatch(
        r"[a-z0-9]+\.execute-api\." + re.escape(region + "." + suffix), url.hostname
    )
    custom_hosts = {
        host.strip().lower()
        for host in os.getenv("ALLOWED_AGENT_HOSTS", "").split(",")
        if host.strip()
    }
    if not aws_host and url.hostname not in custom_hosts:
        raise FleetError("agent_host_not_allowed")
    if any(part in (".", "..") for part in url.path.split("/")) or "%" in url.path or "\\" in value:
        raise FleetError("invalid_agent_url")
    return value.rstrip("/")


def registration(value: Any, name: str | None = None) -> dict:
    if not isinstance(value, dict):
        raise FleetError("registration_must_be_object")
    allowed = {
        "agent_id",
        "name",
        "account_id",
        "region",
        "stage",
        "api_url",
        "enabled",
        "allow_writes",
        "settings_ids",
        "integration_ids",
        "expected_rev",
    }
    if set(value) - allowed:
        raise FleetError("unknown_registration_fields")
    result = dict(value)
    result["agent_id"] = agent_id(name or value.get("agent_id", ""))
    if name and value.get("agent_id", name) != name:
        raise FleetError("agent_id_mismatch")
    if not isinstance(result.get("account_id"), str) or not re.fullmatch(
        r"\d{12}", result["account_id"]
    ):
        raise FleetError("invalid_account_id")
    if not isinstance(result.get("region"), str) or not REGION.fullmatch(result["region"]):
        raise FleetError("invalid_region")
    if not isinstance(result.get("stage"), str) or not RESOURCE_ID.fullmatch(result["stage"]):
        raise FleetError("invalid_stage")
    result["api_url"] = endpoint(result.get("api_url"), result["region"])
    result.setdefault("name", result["agent_id"])
    if not isinstance(result["name"], str) or not 1 <= len(result["name"]) <= 100:
        raise FleetError("invalid_name")
    for flag, default in (("enabled", True), ("allow_writes", False)):
        result.setdefault(flag, default)
        if not isinstance(result[flag], bool):
            raise FleetError("invalid_registration_boolean")
    for field, default in (("settings_ids", ["global"]), ("integration_ids", [])):
        result.setdefault(field, default)
        ids = result[field]
        pattern = ID if field == "integration_ids" else RESOURCE_ID
        if (
            not isinstance(ids, list)
            or len(ids) > 50
            or len(set(map(str, ids))) != len(ids)
            or any(not isinstance(x, str) or not pattern.fullmatch(x) for x in ids)
        ):
            raise FleetError("invalid_configuration_ids")
    rev = result.pop("expected_rev", None)
    if rev is not None and (isinstance(rev, bool) or not isinstance(rev, int) or rev < 1):
        raise FleetError("invalid_expected_rev")
    result["expected_rev"] = rev
    return result


def public_registration(item: dict) -> dict:
    return {
        key: value
        for key, value in item.items()
        if key not in {"id", "record_type", "poll_token", "lease_until", "completed_sequence"}
    }


def cursor_encode(value: dict) -> str:
    return base64.urlsafe_b64encode(json_text(value).encode()).decode().rstrip("=")


def cursor_decode(value: str | None) -> dict | None:
    if not value:
        return None
    try:
        if len(value) > 4096:
            raise ValueError()
        result = json.loads(
            base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
        )
        if not isinstance(result, dict):
            raise ValueError()
        return result
    except (ValueError, TypeError):
        raise FleetError("invalid_cursor") from None


def page_size(value: Any) -> int:
    try:
        size = int(value or 20)
    except (ValueError, TypeError):
        raise FleetError("invalid_limit") from None
    if not 1 <= size <= 50:
        raise FleetError("invalid_limit")
    return size
