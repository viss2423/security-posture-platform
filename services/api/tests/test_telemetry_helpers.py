"""Telemetry normalization helper tests."""

from __future__ import annotations

import json

from app.telemetry import (
    _lag_stats,
    _parse_authlog_line,
    _read_events_from_file,
    build_keepalive_events,
    normalize_telemetry_event,
)


def test_normalize_suricata_alert_maps_expected_fields():
    row = normalize_telemetry_event(
        "suricata",
        {
            "timestamp": "2026-03-05T09:00:01.120000Z",
            "event_type": "alert",
            "src_ip": "203.0.113.10",
            "src_port": 51515,
            "dest_ip": "172.20.0.15",
            "dest_port": 80,
            "proto": "TCP",
            "alert": {
                "signature_id": 2024210,
                "signature": "ET WEB_SERVER Possible SQL Injection Attempt",
                "severity": 2,
            },
        },
    )
    assert row["event_type"] == "alert"
    assert row["src_ip"] == "203.0.113.10"
    assert row["dst_ip"] == "172.20.0.15"
    assert row["severity_text"] == "high"
    assert row["title"] == "ET WEB_SERVER Possible SQL Injection Attempt"


def test_normalize_zeek_dns_extracts_domain():
    row = normalize_telemetry_event(
        "zeek",
        {
            "ts": "2026-03-05T09:00:12Z",
            "event_type": "dns",
            "uid": "abc123",
            "id.orig_h": "172.20.0.15",
            "id.resp_h": "8.8.8.8",
            "query": "bad.example",
        },
    )
    assert row["event_type"] == "dns"
    assert row["domain"] == "bad.example"
    assert row["title"].startswith("Zeek DNS query")


def test_keepalive_events_generate_expected_source_shapes():
    suricata = build_keepalive_events("suricata")
    zeek = build_keepalive_events("zeek")
    auditd = build_keepalive_events("auditd")
    authlog = build_keepalive_events("authlog")
    cowrie = build_keepalive_events("cowrie")

    assert len(suricata) == 1
    assert suricata[0]["event_type"] == "alert"
    assert "timestamp" in suricata[0]

    assert len(zeek) == 1
    assert zeek[0]["event_type"] == "dns"
    assert zeek[0]["query"] == "keepalive.secplat-lab.example"

    assert len(auditd) == 1
    assert auditd[0]["type"] == "execve"

    assert len(authlog) == 1
    assert authlog[0]["event_type"] == "ssh_auth_failed"
    assert authlog[0]["process"] == "sshd"

    assert len(cowrie) == 2
    assert cowrie[0]["eventid"] == "cowrie.login.failed"
    assert cowrie[1]["eventid"] == "cowrie.command.input"


def test_parse_authlog_line_extracts_ssh_failure_fields():
    parsed = _parse_authlog_line(
        "Mar  6 10:11:12 secplat-host sshd[2222]: Failed password for invalid user admin from 203.0.113.25 port 50221 ssh2"
    )
    assert parsed is not None
    assert parsed["event_type"] == "ssh_auth_failed"
    assert parsed["src_ip"] == "203.0.113.25"
    assert parsed["src_port"] == 50221
    assert parsed["username"] == "admin"
    assert parsed["process"] == "sshd"


def test_normalize_authlog_event_maps_expected_fields():
    parsed = _parse_authlog_line(
        "Mar  6 10:11:13 secplat-host sudo: analyst : TTY=pts/0 ; PWD=/home/analyst ; USER=root ; COMMAND=/usr/bin/id"
    )
    assert parsed is not None
    row = normalize_telemetry_event("authlog", parsed)
    assert row["event_type"] == "sudo_command"
    assert row["severity_text"] == "high"
    assert row["protocol"] == "sudo"
    assert row["title"] == "Sudo command execution"


def test_read_events_from_file_includes_raw_lineage(tmp_path):
    file_path = tmp_path / "events.jsonl"
    rows = [
        {"event_type": "alert", "timestamp": "2026-03-05T09:00:00Z"},
        {"event_type": "dns", "timestamp": "2026-03-05T09:00:01Z"},
    ]
    file_path.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")

    parsed = _read_events_from_file(str(file_path))
    assert len(parsed) == 2
    assert parsed[0]["raw_offset"] == 1
    assert parsed[1]["raw_offset"] == 2
    assert parsed[0]["raw_path"] == str(file_path)
    assert parsed[1]["raw_path"] == str(file_path)


def test_lag_stats_returns_expected_percentile_and_bounds():
    stats = _lag_stats([1.0, 2.0, 3.0, 4.0, 100.0])
    assert stats["ingest_lag_seconds_avg"] == 22.0
    assert stats["ingest_lag_seconds_p95"] == 100.0
    assert stats["ingest_lag_seconds_max"] == 100.0
