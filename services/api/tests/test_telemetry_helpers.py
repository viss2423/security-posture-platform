"""Telemetry normalization helper tests."""

from __future__ import annotations

from app.telemetry import build_keepalive_events, normalize_telemetry_event


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
    cowrie = build_keepalive_events("cowrie")

    assert len(suricata) == 1
    assert suricata[0]["event_type"] == "alert"
    assert "timestamp" in suricata[0]

    assert len(zeek) == 1
    assert zeek[0]["event_type"] == "dns"
    assert zeek[0]["query"] == "keepalive.secplat-lab.example"

    assert len(auditd) == 1
    assert auditd[0]["type"] == "execve"

    assert len(cowrie) == 2
    assert cowrie[0]["eventid"] == "cowrie.login.failed"
    assert cowrie[1]["eventid"] == "cowrie.command.input"
