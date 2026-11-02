"""Bounded HTTPS forwarding. Credentials never follow redirects or caller-supplied URLs."""

from __future__ import annotations

import json
import re
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .models import MAX_RESPONSE, FleetError, endpoint, json_text


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def route(method: str, path: str) -> None:
    if not isinstance(method, str) or method not in {"GET", "POST", "PUT", "DELETE"}:
        raise FleetError("unsupported_core_method")
    if not isinstance(path, str) or len(path) > 2048:
        raise FleetError("invalid_agent_path")
    parsed = urlsplit(path)
    if (
        parsed.scheme
        or parsed.netloc
        or parsed.query
        or parsed.fragment
        or "%" in path
        or "\\" in path
        or any(ord(c) < 32 for c in path)
    ):
        raise FleetError("invalid_agent_path")
    segment = r"[A-Za-z0-9_.:-]{1,128}"
    patterns = {
        "GET": [
            r"/(status|help|signals|signals/stats|logs|rules|rules/schema|rules/metrics|rules/runtime-status|lists|settings|ir-roles|ir-actions|integrations)",
            rf"/(rules|lists|settings|ir-roles|ir-actions|integrations)/{segment}",
            rf"/integrations/{segment}/jobs(?:/{segment})?",
        ],
        "POST": [
            r"/(rules|lists|settings|ir-roles|rules/validate|rules/evaluate|rule-releases/plan|rule-releases/apply)",
            rf"/integrations/{segment}/preview",
            rf"/integrations/{segment}/jobs/{segment}/replay",
            rf"/ir-actions/{segment}/rollback",
        ],
        "PUT": [rf"/(rules|lists|settings|ir-roles|integrations)/{segment}"],
        "DELETE": [rf"/(rules|lists|settings|ir-roles)/{segment}"],
    }
    if path.endswith(("/.", "/..")) or not any(
        re.fullmatch(p, path) for p in patterns.get(method, [])
    ):
        raise FleetError("unsupported_core_route")


class Agent:
    def __init__(
        self,
        registration: dict,
        read_key: str,
        write_key: str | None = None,
        deadline: float | None = None,
    ):
        self.registration = registration
        self.url = endpoint(registration["api_url"], registration["region"])
        self.read_key, self.write_key = read_key, write_key
        self.deadline = deadline or time.monotonic() + 20
        self.opener = build_opener(NoRedirect())
        self.requests = 0

    def request(
        self, method: str, path: str, *, query: dict | None = None, body=None
    ) -> tuple[int, object]:
        route(method, path)
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise FleetError("agent_deadline_exceeded", 504)
        if method != "GET" and not self.write_key:
            raise FleetError("agent_writes_disabled", 403)
        if query is not None and (
            not isinstance(query, dict)
            or len(query) > 30
            or any(
                not isinstance(k, str)
                or not isinstance(v, (str, list))
                or (isinstance(v, list) and any(not isinstance(x, str) for x in v))
                for k, v in query.items()
            )
        ):
            raise FleetError("invalid_query")
        suffix = "?" + urlencode(query, doseq=True) if query else ""
        raw = json_text(body).encode() if body is not None else None
        if raw and len(raw) > MAX_RESPONSE:
            raise FleetError("request_too_large", 413)
        if method in ("GET", "DELETE") and body is not None:
            raise FleetError("body_not_supported")
        request = Request(
            self.url + path + suffix,
            data=raw,
            method=method,
            headers={
                "x-api-key": self.read_key if method == "GET" else self.write_key,
                "Content-Type": "application/json",
            },
        )
        self.requests += 1
        try:
            try:
                response = self.opener.open(request, timeout=min(5, remaining))
            except HTTPError as error:
                response = error
            with response:
                data = response.read(MAX_RESPONSE + 1)
                if len(data) > MAX_RESPONSE:
                    raise FleetError("agent_response_too_large", 502)
                try:
                    value = json.loads(data) if data else None
                except (ValueError, UnicodeError):
                    raise FleetError("agent_response_not_json", 502) from None
                return response.code, value
        except (URLError, TimeoutError, OSError):
            raise FleetError("agent_unreachable", 502) from None

    def get(self, path: str, query: dict | None = None):
        status, body = self.request("GET", path, query=query)
        if status != 200:
            raise FleetError(f"agent_http_{status}", 502)
        if not isinstance(body, dict):
            raise FleetError("agent_response_not_object", 502)
        return body

    def verify(self) -> dict:
        status = self.get("/status")
        if status.get("status") != "ok" or not isinstance(status.get("capabilities"), dict):
            raise FleetError("invalid_agent_status", 502)
        identity = status.get("deployment", {})
        expected = self.registration
        if (
            status.get("product") != "OpenCDR Core"
            or not isinstance(identity, dict)
            or identity.get("account_id") != expected["account_id"]
            or identity.get("home_region") != expected["region"]
            or identity.get("stage") != expected["stage"]
        ):
            raise FleetError("agent_identity_mismatch", 409)
        version = status.get("management_contract_version", "")
        if not isinstance(version, str) or version.split(".")[0] != "2":
            raise FleetError("unsupported_core_contract", 409)
        return status

    def pages(self, path: str, query: dict | None = None):
        seen = set()
        for _ in range(200):
            page = self.get(path, query)
            items = page.get("items")
            if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
                raise FleetError("invalid_agent_page", 502)
            yield from items
            token = page.get("next_token")
            if not token:
                if page.get("has_next"):
                    raise FleetError("missing_agent_cursor", 502)
                return
            if not isinstance(token, str) or token in seen:
                raise FleetError("repeated_agent_cursor", 502)
            seen.add(token)
            query = {**(query or {}), "next_token": token}
        raise FleetError("agent_page_limit_exceeded", 502)


def resource_path(kind: str, resource_id: str) -> str:
    return f"/{kind}/{quote(resource_id, safe='')}"
