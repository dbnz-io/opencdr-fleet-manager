"""Shared operational case contract; tracking is separate from SIEM investigation."""

import re

from .detection_query import canonical

STATUSES = {"open", "investigating", "contained", "closed"}
SEVERITIES = {"critical", "high", "medium"}
MAX_ATTACHMENTS = 30


class CaseError(Exception):
    def __init__(self, code, status=400):
        self.code, self.status = code, status
        super().__init__(code)


def text(value, maximum, *, empty=False):
    if not isinstance(value, str) or len(value) > maximum or (not empty and not value.strip()):
        raise CaseError("invalid_case_text")
    return value


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{32}", value):
        raise CaseError("invalid_case_identifier")
    return value


def agents(value):
    if (
        not isinstance(value, list)
        or not 1 <= len(value) <= 100
        or any(
            not isinstance(v, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", v) for v in value
        )
        or len(set(value)) != len(value)
    ):
        raise CaseError("invalid_case_account_scope")
    return sorted(value)


def principal(identity):
    from .delegation import delegated_actor

    return delegated_actor() or iam_principal(identity)


def iam_principal(identity):
    arn, caller = identity.get("userArn"), identity.get("caller")
    if not isinstance(arn, str) or not isinstance(caller, str):
        raise CaseError("case_iam_identity_required", 403)
    match = re.fullmatch(r"arn:(aws(?:-us-gov|-cn)?):(iam|sts)::([0-9]{12}):(.+)", arn)
    role = caller.split(":", 1)[0]
    if (
        not match
        or not re.fullmatch(r"(?:AROA|AIDA)[A-Z0-9]{12,64}", role)
        or not (
            (role.startswith("AROA") and match[4].startswith(("assumed-role/", "role/")))
            or (role.startswith("AIDA") and match[4].startswith("user/"))
        )
    ):
        raise CaseError("case_iam_identity_required", 403)
    return ":".join((match[1], match[3], role))


def revision(value):
    if type(value) is not int or value < 0:
        raise CaseError("invalid_case_revision")
    return value


def request(body, fields, *, create=False):
    required = {"request_id", "reason", *fields} | (set() if create else {"expected_rev"})
    if not isinstance(body, dict) or set(body) != required:
        raise CaseError("invalid_case_request")
    identifier(body["request_id"])
    text(body["reason"], 1000)
    if not create:
        revision(body["expected_rev"])
    if len(canonical(body).encode()) > 24_000:
        raise CaseError("case_request_too_large", 413)


def changes(value):
    if (
        not isinstance(value, dict)
        or not value
        or set(value) - {"title", "description", "severity", "status", "assigned_to"}
    ):
        raise CaseError("invalid_case_changes")
    for key, val in value.items():
        if key in {"title", "description"}:
            text(val, 200 if key == "title" else 4000, empty=key == "description")
        elif key == "assigned_to":
            if val is not None:
                text(val, 256)
        elif not isinstance(val, str) or val not in (STATUSES if key == "status" else SEVERITIES):
            raise CaseError("invalid_case_state")
    return value
