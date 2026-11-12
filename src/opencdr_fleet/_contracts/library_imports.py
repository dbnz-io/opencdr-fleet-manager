"""Pinned Git source verification. No arbitrary URLs, redirects or credentials."""

import hashlib
import json
import re
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .library_contract import MAX_DOCUMENT_BYTES, LibraryError, provenance


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise LibraryError("library_import_redirect_rejected", 502)


def fetch_git(origin):
    provenance(origin)
    match = re.fullmatch(
        r"https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)", origin["repository"]
    )
    if origin["kind"] != "git-import" or not match or any(p in {".", ".."} for p in match.groups()):
        raise LibraryError("library_verified_import_requires_github")
    # Fixed public host, no redirects/proxy credentials, and a commit rather than a ref.
    owner, repo = match.groups()
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/{origin['commit']}/{quote(origin['path'], safe='/')}"
    try:
        with build_opener(ProxyHandler({}), NoRedirect()).open(
            Request(
                url, headers={"Accept": "application/json", "User-Agent": "OpenCDR-library-import"}
            ),
            timeout=5,
        ) as response:
            raw = response.read(MAX_DOCUMENT_BYTES + 1)
    except (HTTPError, URLError, TimeoutError):
        raise LibraryError("library_source_unavailable", 502) from None
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise LibraryError("library_source_too_large", 413)
    if hashlib.sha256(raw).hexdigest() != origin["upstream_sha256"]:
        raise LibraryError("library_upstream_digest_mismatch", 409)
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError):
        raise LibraryError("library_source_must_be_json") from None
    return value
