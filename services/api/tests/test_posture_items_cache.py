from app.routers import posture


class DummyState:
    def __init__(self, asset_id: str):
        self.asset_id = asset_id

    def model_dump(self, mode: str = "json"):
        return {
            "asset_id": self.asset_id,
            "asset_key": self.asset_id,
            "status": "green",
            "posture_score": 92,
        }


def test_build_merged_posture_items_uses_ttl_cache(monkeypatch):
    calls = {"raw": 0, "meta": 0}

    def fake_fetch_raw():
        calls["raw"] += 1
        return 1, [{"asset_key": "asset-1", "status": "green"}]

    def fake_raw_to_states(raw_items):
        return [DummyState(raw_items[0]["asset_key"])]

    def fake_metadata(db, asset_keys):
        calls["meta"] += 1
        return {
            asset_keys[0]: {
                "name": "Asset 1",
                "owner": "platform",
                "environment": "prod",
                "criticality": "high",
            }
        }

    monkeypatch.setattr(posture.settings, "POSTURE_CACHE_TTL_SECONDS", 5.0)
    monkeypatch.setattr(posture, "_fetch_posture_list_raw", fake_fetch_raw)
    monkeypatch.setattr(posture, "_raw_list_to_states", fake_raw_to_states)
    monkeypatch.setattr(posture, "_get_asset_metadata_batch", fake_metadata)
    posture._reset_posture_cache()

    first_items = posture._build_merged_posture_items(object())
    second_items = posture._build_merged_posture_items(object())

    assert len(first_items) == 1
    assert first_items == second_items
    assert first_items[0]["owner"] == "platform"
    assert calls["raw"] == 1
    assert calls["meta"] == 1
