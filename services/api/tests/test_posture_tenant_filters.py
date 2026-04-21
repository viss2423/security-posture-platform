from __future__ import annotations

from app.request_context import tenant_id_ctx
from app.routers import posture


def test_fetch_posture_list_raw_scopes_search_to_current_tenant(monkeypatch):
    captured: dict[str, object] = {}

    def fake_opensearch_post(path, body, index):
        captured["path"] = path
        captured["body"] = body
        captured["index"] = index
        return {"hits": {"total": {"value": 0}, "hits": []}}

    monkeypatch.setattr(posture, "_opensearch_post", fake_opensearch_post)
    monkeypatch.setattr(posture.settings, "TENANCY_MODE", "multi", raising=False)
    posture._reset_posture_cache()
    token = tenant_id_ctx.set("tenant-acme")
    try:
        total, items = posture._fetch_posture_list_raw()
    finally:
        tenant_id_ctx.reset(token)

    assert total == 0
    assert items == []
    assert captured["path"] == "/_search"
    assert {"term": {"org_id.keyword": "tenant-acme"}} in captured["body"]["query"]["bool"][
        "filter"
    ]


def test_events_for_asset_scopes_search_to_current_tenant(monkeypatch):
    captured: dict[str, object] = {}

    def fake_opensearch_post(path, body, index):
        captured["path"] = path
        captured["body"] = body
        captured["index"] = index
        return {"hits": {"hits": []}}

    monkeypatch.setattr(posture, "_opensearch_post", fake_opensearch_post)
    monkeypatch.setattr(posture.settings, "TENANCY_MODE", "multi", raising=False)
    token = tenant_id_ctx.set("tenant-blue")
    try:
        out = posture._events_for_asset("asset-1", hours=24, size=10)
    finally:
        tenant_id_ctx.reset(token)

    assert out == []
    assert captured["path"] == "/_search"
    assert {"term": {"org_id.keyword": "tenant-blue"}} in captured["body"]["query"]["bool"][
        "filter"
    ]
