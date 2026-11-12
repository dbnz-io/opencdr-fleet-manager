"""Shared library routes. No runtime writes, approvals or deployment jobs."""

import re

from .library_contract import LibraryError
from .library_store import view


def dispatch(library, method, path, body, query):
    match = re.fullmatch(r"/library/items/([a-f0-9]{32})/runtime-source", path)
    if match and method == "GET" and set(query) == {"source_deployment", "source_revision"}:
        from .case_contract import text
        from .case_store import digest

        if library.runtime_reader is None:
            raise LibraryError("library_runtime_import_unavailable", 503)
        head = library.item(match[1])
        source = library.runtime_reader(
            head, text(query["source_deployment"], 256), text(query["source_revision"], 128)
        )
        return {
            "content_id": head["content_id"],
            "source_deployment": query["source_deployment"],
            "source_revision": query["source_revision"],
            "source_sha256": digest(source["document"]),
            **source,
        }
    match = re.fullmatch(r"/library/releases/([a-f0-9]{32})/mappings(?:/([a-f0-9]{32}))?", path)
    if match:
        release_id, mapping_id = match.groups()
        library.required("RELEASE", release_id)
        if method == "GET":
            if mapping_id and not query:
                return library.quality_read("MAPPING#" + release_id, mapping_id)
            if not mapping_id:
                return library.listing("MAPPING#" + release_id, query)
        if method == "POST" and not mapping_id and not query:
            return library.map_legacy_release(release_id, body)
    match = re.fullmatch(r"/library/items/([a-f0-9]{32})/runtime-imports", path)
    if match and method == "POST" and not query:
        return library.import_runtime_version(match[1], body)
    match = re.fullmatch(r"/library/items/([a-f0-9]{32})/imports", path)
    if match and method == "POST" and not query:
        return library.import_version(match[1], body)
    match = re.fullmatch(r"/library/items/([a-f0-9]{32})/tests(?:/([a-f0-9]{32}))?", path)
    if match:
        content_id, test_id = match.groups()
        library.item(content_id)
        if method == "GET":
            if test_id and not query:
                return library.quality_read("TEST#" + content_id, test_id)
            if not test_id:
                return library.listing("TEST#" + content_id, query)
        if method == "POST" and not test_id and not query:
            return library.test_version(content_id, body)
    match = re.fullmatch(r"/library/releases/([a-f0-9]{32})/compilations(?:/([a-f0-9]{32}))?", path)
    if match:
        release_id, compilation_id = match.groups()
        library.required("RELEASE", release_id)
        if method == "GET":
            if compilation_id and not query:
                return library.quality_read("COMPILE#" + release_id, compilation_id)
            if not compilation_id:
                return library.listing("COMPILE#" + release_id, query)
        if method == "POST" and not compilation_id and not query:
            return library.compile_release(release_id, body)
    if path == "/library/items":
        if method == "GET":
            return library.listing("ITEM", query)
        if method == "POST" and not query:
            return library.create(body)
    if path == "/library/releases":
        if method == "GET":
            return library.listing("RELEASE", query)
        if method == "POST" and not query:
            return library.freeze(body)
    match = re.fullmatch(r"/library/releases/([a-f0-9]{32})(/artifact)?", path)
    if match and method == "GET" and not query:
        row = library.required("RELEASE", match[1])
        return {"release": view(row), **({"manifest": library.artifact(row)} if match[2] else {})}
    match = re.fullmatch(
        r"/library/items/([a-f0-9]{32})(?:/(history|versions)(?:/([0-9]{1,16})(/artifact)?)?)?",
        path,
    )
    if match:
        content_id, sub, number, artifact = match.groups()
        head = library.item(content_id)
        if method == "GET":
            if not sub and not query:
                return {"item": view(head)}
            if sub in {"history", "versions"} and not number:
                return library.listing(
                    ("AUDIT#" if sub == "history" else "VERSION#") + content_id, query, numeric=True
                )
            if sub == "versions" and number and not query:
                row = library.version(content_id, int(number))
                return {
                    "version": view(row),
                    **({"artifact": library.artifact(row)} if artifact else {}),
                }
        if method == "PUT" and not sub and not query:
            return library.update(content_id, body)
        if method == "POST" and sub == "versions" and not number and not query:
            return library.save_version(content_id, body)
    raise LibraryError("library_route_not_found", 404)
