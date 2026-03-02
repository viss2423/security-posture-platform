from app.routers import posture


def test_fetch_posture_list_raw_uses_ttl_cache(monkeypatch):
    calls = {"count": 0}

    def fake_opensearch_post(path, body, index):
        calls["count"] += 1
        return {
            "hits": {
                "total": {"value": 1},
                "hits": [{"_source": {"asset_key": "asset-1", "status": "green"}}],
            }
        }

    monkeypatch.setattr(posture, "_opensearch_post", fake_opensearch_post)
    monkeypatch.setattr(posture.settings, "POSTURE_CACHE_TTL_SECONDS", 5.0)
    posture._reset_posture_cache()

    first_total, first_items = posture._fetch_posture_list_raw()
    second_total, second_items = posture._fetch_posture_list_raw()

    assert first_total == 1
    assert second_total == 1
    assert first_items == second_items
    assert calls["count"] == 1
