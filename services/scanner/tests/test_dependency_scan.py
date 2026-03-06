import sys
from pathlib import Path
from types import SimpleNamespace

_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

import dependency_scan
from dependency_scan import OSV_SOURCE, parse_osv_report, run_osv_scan


def test_parse_osv_report_returns_structured_findings():
    report = {
        "results": [
            {
                "source": {
                    "path": "/workspace/services/frontend/package-lock.json",
                    "type": "lockfile",
                },
                "packages": [
                    {
                        "package": {
                            "name": "lodash",
                            "version": "4.17.19",
                            "ecosystem": "npm",
                        },
                        "groups": [
                            {
                                "ids": ["GHSA-35jh-r3h4-6jhm"],
                                "aliases": [
                                    "CVE-2021-23337",
                                    "GHSA-35jh-r3h4-6jhm",
                                ],
                                "max_severity": "7.2",
                            },
                            {
                                "ids": ["GHSA-29mw-wpgm-hmr9"],
                                "aliases": [
                                    "CVE-2020-28500",
                                    "GHSA-29mw-wpgm-hmr9",
                                ],
                                "max_severity": "5.3",
                            },
                        ],
                        "vulnerabilities": [
                            {
                                "id": "GHSA-35jh-r3h4-6jhm",
                                "summary": "Command Injection in lodash",
                                "details": "Versions before 4.17.21 are vulnerable.",
                                "aliases": ["CVE-2021-23337"],
                                "database_specific": {"severity": "HIGH"},
                                "published": "2021-05-06T16:05:51Z",
                                "modified": "2025-08-12T21:55:57.719943Z",
                                "references": [
                                    {
                                        "type": "ADVISORY",
                                        "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-23337",
                                    }
                                ],
                                "affected": [
                                    {
                                        "package": {
                                            "name": "lodash",
                                            "ecosystem": "npm",
                                        },
                                        "ranges": [
                                            {
                                                "type": "SEMVER",
                                                "events": [
                                                    {"introduced": "0"},
                                                    {"fixed": "4.17.21"},
                                                ],
                                            }
                                        ],
                                    }
                                ],
                            },
                            {
                                "id": "GHSA-29mw-wpgm-hmr9",
                                "summary": "ReDoS in lodash",
                                "details": "Versions before 4.17.21 are vulnerable.",
                                "aliases": ["CVE-2020-28500"],
                                "database_specific": {"severity": "MODERATE"},
                                "affected": [
                                    {
                                        "package": {
                                            "name": "lodash",
                                            "ecosystem": "npm",
                                        },
                                        "ranges": [
                                            {
                                                "type": "SEMVER",
                                                "events": [
                                                    {"introduced": "4.0.0"},
                                                    {"fixed": "4.17.21"},
                                                ],
                                            }
                                        ],
                                    }
                                ],
                            },
                        ],
                    }
                ],
            }
        ]
    }

    findings = parse_osv_report(report, asset_key="secplat-repo")

    assert len(findings) == 2
    first = findings[0]
    assert first["source"] == OSV_SOURCE
    assert first["category"] == "dependency_vulnerability"
    assert first["vulnerability_id"] == "GHSA-35jh-r3h4-6jhm"
    assert first["package_name"] == "lodash"
    assert first["package_version"] == "4.17.19"
    assert first["package_ecosystem"] == "npm"
    assert first["fixed_version"] == "4.17.21"
    assert first["severity"] == "high"
    assert len(first["finding_key"]) == 32
    assert "Upgrade lodash from 4.17.19 to 4.17.21" in first["remediation"]
    assert first["scanner_metadata_json"]["source_path"].endswith("package-lock.json")
    assert "CVE-2021-23337" in first["scanner_metadata_json"]["aliases"]

    second = findings[1]
    assert second["severity"] == "medium"
    assert second["scanner_metadata_json"]["affected_ranges"][0]["events"][1]["fixed"] == "4.17.21"


def test_run_osv_scan_treats_missing_package_sources_as_empty(monkeypatch):
    monkeypatch.setattr(
        dependency_scan.subprocess,
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

    result = run_osv_scan("/workspace/services/api", asset_key="secplat-repo")

    assert result["exit_code"] == 128
    assert result["findings"] == []
    assert result["report"] == {"results": []}
