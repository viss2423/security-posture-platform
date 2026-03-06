import sys
from pathlib import Path
from types import SimpleNamespace

_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from app import repository_scan


def test_run_osv_scan_treats_missing_package_sources_as_empty(monkeypatch):
    monkeypatch.setattr(
        repository_scan.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=128,
            stdout="",
            stderr=(
                "Scanning dir /workspace/services/api\n"
                "No package sources found, --help for usage information.\n"
            ),
        ),
    )

    result = repository_scan._run_osv_scan(
        "/workspace/services/api",
        asset_key="secplat-repo",
    )

    assert result["exit_code"] == 128
    assert result["findings"] == []
