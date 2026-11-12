import importlib.util
import json
import tomllib
from pathlib import Path
from unittest.mock import Mock

import opencdr_fleet

ROOT = Path(__file__).resolve().parents[1]


def test_service_version_matches_python_and_node_metadata():
    assert (
        tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
        == opencdr_fleet.__version__
    )
    assert json.loads((ROOT / "package.json").read_text())["version"] == opencdr_fleet.__version__


def test_hash_regeneration_produces_valid_multiline_pip_requirements(tmp_path):
    spec = importlib.util.spec_from_file_location("lock", ROOT / "scripts/lock-runtime.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    script = tmp_path / "scripts" / "lock-runtime.py"
    script.parent.mkdir()
    module.__file__ = str(script)
    response = Mock()
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    response.read.return_value = json.dumps(
        {"urls": [{"digests": {"sha256": "a" * 64}, "packagetype": "bdist_wheel", "yanked": False}]}
    ).encode()
    module.urlopen = lambda *a, **k: response
    module.main()
    text = (tmp_path / "requirements.lock").read_text()
    assert text.count("--hash=sha256:") == len(module.VERSIONS)
    assert "+    --hash" not in text and chr(92) + "n" not in text
    assert "boto3==1.43.119 " + chr(92) + chr(10) in text


def test_shared_detection_contract_pin_and_optional_core_parity():
    import hashlib

    source = ROOT / "src/opencdr_fleet/_contracts/detection_query.py"
    pin = json.loads(source.with_name("contracts-pin.json").read_text())
    assert hashlib.sha256(source.read_bytes()).hexdigest() == pin["sha256"]
    canonical = ROOT.parent / pin["canonical_source"]
    if canonical.exists():
        assert canonical.read_bytes() == source.read_bytes()


def test_handling_contract_is_pinned_and_matches_core():
    import hashlib

    source = ROOT / "src/opencdr_fleet/_contracts/detection_handling.py"
    pin = json.loads(source.with_name("contracts-pin.json").read_text())
    assert hashlib.sha256(source.read_bytes()).hexdigest() == pin["handling_sha256"]
    canonical = ROOT.parent / "opencdr-internal/src/management/detection_handling.py"
    if canonical.exists():
        assert source.read_bytes() == canonical.read_bytes()


def test_case_contract_store_and_routes_are_pinned_and_match_core():
    import hashlib

    contracts = ROOT / "src/opencdr_fleet/_contracts"
    pin = json.loads((contracts / "contracts-pin.json").read_text())
    for name in [
        "case_contract",
        "case_store",
        "case_api",
        "case_integrations",
        "case_extensions",
        "library_contract",
        "library_store",
        "library_api",
        "library_quality",
        "library_imports",
        "delegation",
        "identity_store",
        "approval_contract",
        "approval_store",
        "approval_authority",
        "approval_api",
        "case_routing",
        "routing_execution",
        "routing_api",
        "routing_delivery",
        "case_mutations",
        "case_tuning",
        "mutation_execution",
        "configuration_flags",
    ]:
        source = contracts / (name + ".py")
        assert hashlib.sha256(source.read_bytes()).hexdigest() == pin[name + "_sha256"]
        core = ROOT.parent / "opencdr-internal/src/management" / (name + ".py")
        if core.exists():
            assert source.read_bytes() == core.read_bytes()


def test_native_evaluator_sources_match_reviewed_core_pins():
    import hashlib
    pin = json.loads((ROOT / "src/opencdr_fleet/_contracts/contracts-pin.json").read_text())
    assert len(pin["evaluator_sources"]) == 12
    for name, expected in pin["evaluator_sources"].items():
        source = ROOT / "src/opencdr_fleet/_evaluator" / (name + ".py")
        assert hashlib.sha256(source.read_bytes()).hexdigest() == expected
        core = ROOT.parent / "opencdr-internal/src/domain" / (name + ".py")
        if core.exists():
            assert source.read_bytes() == core.read_bytes()


def test_native_pin_covers_transitive_lazy_relative_imports():
    import ast
    pin = json.loads((ROOT / "src/opencdr_fleet/_contracts/contracts-pin.json").read_text())
    names = set(pin["evaluator_sources"])
    for name in names:
        tree = ast.parse((ROOT / "src/opencdr_fleet/_evaluator" / (name + ".py")).read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.level:
                assert node.level == 1 and node.module.split(".")[0] in names, (name, node.module)
