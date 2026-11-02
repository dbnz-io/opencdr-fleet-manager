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
