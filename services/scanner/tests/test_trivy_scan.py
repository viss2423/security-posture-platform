import json
import sys
from pathlib import Path

_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from trivy_scan import TRIVY_SOURCE, parse_trivy_report, run_trivy_scan


def test_parse_trivy_report_returns_vulnerability_and_misconfig_findings():
    report = {
        "SchemaVersion": 2,
        "ArtifactType": "filesystem",
        "Results": [
            {
                "Target": "package-lock.json",
                "Class": "lang-pkgs",
                "Type": "npm",
                "Packages": [
                    {
                        "ID": "lodash@4.17.19",
                        "Name": "lodash",
                        "Version": "4.17.19",
                        "Relationship": "direct",
                        "Identifier": {
                            "PURL": "pkg:npm/lodash@4.17.19",
                        },
                        "Locations": [
                            {
                                "StartLine": 14,
                                "EndLine": 17,
                            }
                        ],
                    }
                ],
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2021-23337",
                        "VendorIDs": [
                            "GHSA-35jh-r3h4-6jhm",
                        ],
                        "PkgID": "lodash@4.17.19",
                        "PkgName": "lodash",
                        "PkgIdentifier": {
                            "PURL": "pkg:npm/lodash@4.17.19",
                        },
                        "InstalledVersion": "4.17.19",
                        "FixedVersion": "4.17.21",
                        "Status": "fixed",
                        "SeveritySource": "ghsa",
                        "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-23337",
                        "DataSource": {
                            "ID": "ghsa",
                            "Name": "GitHub Security Advisory npm",
                        },
                        "Title": "nodejs-lodash: command injection via template",
                        "Description": "Lodash versions prior to 4.17.21 are vulnerable.",
                        "Severity": "HIGH",
                        "CVSS": {
                            "ghsa": {
                                "V3Score": 7.2,
                            }
                        },
                        "References": [
                            "https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
                            "https://nvd.nist.gov/vuln/detail/CVE-2021-23337",
                        ],
                        "PublishedDate": "2021-02-15T13:15:12.56Z",
                        "LastModifiedDate": "2024-11-21T05:51:31.643Z",
                        "Fingerprint": "sha256:test",
                    }
                ],
            },
            {
                "Target": "Dockerfile",
                "Class": "config",
                "Type": "dockerfile",
                "Misconfigurations": [
                    {
                        "Type": "Dockerfile Security Check",
                        "ID": "DS-0002",
                        "Title": "Image user should not be 'root'",
                        "Description": "Containers should not run as root.",
                        "Message": "Last USER command in Dockerfile should not be 'root'",
                        "Namespace": "builtin.dockerfile.DS002",
                        "Query": "data.builtin.dockerfile.DS002.deny",
                        "Resolution": "Add 'USER <non root user name>' line to the Dockerfile",
                        "Severity": "HIGH",
                        "PrimaryURL": "https://avd.aquasec.com/misconfig/ds-0002",
                        "References": [
                            "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/",
                            "https://avd.aquasec.com/misconfig/ds-0002",
                        ],
                        "Status": "FAIL",
                        "CauseMetadata": {
                            "Provider": "Dockerfile",
                            "Service": "general",
                            "StartLine": 2,
                            "EndLine": 2,
                            "Code": {
                                "Lines": [
                                    {
                                        "Number": 2,
                                        "Content": "USER root",
                                        "IsCause": True,
                                    }
                                ]
                            },
                        },
                    }
                ],
            },
        ],
    }

    findings = parse_trivy_report(report, asset_key="secplat-repo")

    assert len(findings) == 2

    vulnerability = findings[0]
    assert vulnerability["source"] == TRIVY_SOURCE
    assert vulnerability["category"] == "dependency_vulnerability"
    assert vulnerability["vulnerability_id"] == "CVE-2021-23337"
    assert vulnerability["package_name"] == "lodash"
    assert vulnerability["package_version"] == "4.17.19"
    assert vulnerability["package_ecosystem"] == "npm"
    assert vulnerability["fixed_version"] == "4.17.21"
    assert vulnerability["severity"] == "high"
    assert len(vulnerability["finding_key"]) == 32
    assert "Upgrade lodash from 4.17.19 to 4.17.21" in vulnerability["remediation"]
    assert vulnerability["scanner_metadata_json"]["target"] == "package-lock.json"
    assert vulnerability["scanner_metadata_json"]["locations"][0]["start_line"] == 14
    assert "GHSA-35jh-r3h4-6jhm" in vulnerability["scanner_metadata_json"]["aliases"]

    misconfiguration = findings[1]
    assert misconfiguration["source"] == TRIVY_SOURCE
    assert misconfiguration["category"] == "misconfiguration"
    assert misconfiguration["title"] == "Image user should not be 'root'"
    assert misconfiguration["severity"] == "high"
    assert misconfiguration["vulnerability_id"] is None
    assert misconfiguration["package_name"] is None
    assert misconfiguration["scanner_metadata_json"]["check_id"] == "DS-0002"
    assert misconfiguration["scanner_metadata_json"]["cause"]["start_line"] == 2
    assert (
        misconfiguration["scanner_metadata_json"]["cause"]["code_lines"][0]["content"]
        == "USER root"
    )


def test_run_trivy_scan_builds_expected_command(monkeypatch):
    observed = {}
    sample_report = {
        "Results": [
            {
                "Target": "package-lock.json",
                "Class": "lang-pkgs",
                "Type": "npm",
                "Vulnerabilities": [],
            }
        ]
    }

    class Completed:
        returncode = 0
        stdout = json.dumps(sample_report)
        stderr = "cached db"

    def fake_run(command, capture_output, text, timeout, check, env):
        observed["command"] = command
        observed["capture_output"] = capture_output
        observed["text"] = text
        observed["timeout"] = timeout
        observed["check"] = check
        observed["env_vex"] = env.get("TRIVY_DISABLE_VEX_NOTICE")
        return Completed()

    monkeypatch.setattr("trivy_scan.subprocess.run", fake_run)

    result = run_trivy_scan(
        "/workspace",
        asset_key="secplat-repo",
        trivy_bin="/usr/local/bin/trivy",
        scanners="vuln,misconfig",
        timeout_seconds=321,
    )

    assert observed["command"] == [
        "/usr/local/bin/trivy",
        "fs",
        "--format",
        "json",
        "--quiet",
        "--timeout",
        "321s",
        "--scanners",
        "vuln,misconfig",
        "/workspace",
    ]
    assert observed["capture_output"] is True
    assert observed["text"] is True
    assert observed["timeout"] == 321
    assert observed["check"] is False
    assert observed["env_vex"] == "true"
    assert result["stderr"] == "cached db"
    assert result["findings"] == []
