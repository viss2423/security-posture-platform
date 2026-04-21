from __future__ import annotations

from app.request_context import tenant_id_ctx
from app.telemetry import _build_opensearch_doc


def test_build_opensearch_doc_stamps_current_tenant_id():
    token = tenant_id_ctx.set("tenant-gold")
    try:
        doc = _build_opensearch_doc(
            event_id=42,
            source="cowrie",
            asset_key="gateway-1",
            normalized={
                "event_type": "cowrie.login.failed",
                "title": "Failed login",
                "description": "Failed login attempt",
                "severity_text": "high",
                "raw": {"eventid": "cowrie.login.failed", "username": "root"},
            },
            collector="ingestion",
            ingest_job_id=7,
            raw_offset=3,
            raw_path="/tmp/cowrie.json",
            ingest_lag_seconds=1.5,
            ti_match=False,
            ti_source=None,
        )
    finally:
        tenant_id_ctx.reset(token)

    assert doc["event_id"] == 42
    assert doc["org_id"] == "tenant-gold"
    assert doc["cowrie_eventid"] == "cowrie.login.failed"
