"""Native Core evaluator adapter shared byte-for-byte with Fleet authoring."""

import hashlib
import json
import platform
from pathlib import Path

import regex
import regex._regex

from .detection_engine import _REGEX_MAX_SUBJECT_LEN, _REGEX_TIMEOUT_SECONDS
from .detection_lists import validate_list_document
from .evaluation_budget import budget
from .rule_management import RULE_CONTRACT_VERSION, evaluate_candidate, validate_candidate
from .rule_release import manifest_digest as manifest_digest
from .rule_release import validate_manifest as validate_manifest

MODULES = (
    "library_evaluator",
    "evaluation_budget",
    "execution_policy",
    "ingestion",
    "rule_management",
    "rule_release",
    "rule_schema",
    "detection_engine",
    "detection_lists",
    "correlation_engine",
    "ocsf_min_parser",
    "response_actions",
)


def provenance():
    sources = {
        name: hashlib.sha256(Path(__file__).with_name(name + ".py").read_bytes()).hexdigest()
        for name in MODULES
    }
    identity = {
        "sources": sources,
        "contract_version": RULE_CONTRACT_VERSION,
        "regex_version": regex.__version__,
        "regex_binary_sha256": hashlib.sha256(Path(regex._regex.__file__).read_bytes()).hexdigest(),
        "regex_timeout_seconds": _REGEX_TIMEOUT_SECONDS,
        "regex_max_subject_length": _REGEX_MAX_SUBJECT_LEN,
        "python_version": platform.python_version(),
    }
    return {
        **identity,
        "sha256": hashlib.sha256(
            json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }


def validate(document, lists):
    if "list_id" in document and "rule_kind" not in document:
        try:
            validate_list_document(document)
            return {"valid": True, "errors": [], "warnings": []}
        except ValueError as error:
            return {
                "valid": False,
                "errors": [{"code": "invalid_list", "message": str(error)}],
                "warnings": [],
            }
    return validate_candidate(document, available_lists=set(lists))


def evaluate(document, events, lists):
    with budget(2.0):
        if "list_id" in document and "rule_kind" not in document:
            return {**validate(document, lists), "matches": [], "evaluated": 0, "skipped": 0}
        return evaluate_candidate(document, events, lists=lists)
