from fastapi.testclient import TestClient

from app.main import app
from app.routers import health as health_router


def test_health():
    c = TestClient(app)
    r = c.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_queue_health_not_configured(monkeypatch):
    c = TestClient(app)
    monkeypatch.setattr(health_router, "queue_health", lambda: None)
    r = c.get("/queue/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "not_configured"


def test_queue_health_includes_dlq_streams(monkeypatch):
    c = TestClient(app)
    monkeypatch.setattr(
        health_router,
        "queue_health",
        lambda: {
            "redis": "ok",
            "streams": {
                "secplat.jobs.scan": 1,
                "secplat.events.notify": 2,
                "secplat.events.correlation": 3,
            },
            "dlq_streams": {
                "secplat.jobs.scan.dlq": 0,
                "secplat.events.notify.dlq": 0,
                "secplat.events.correlation.dlq": 1,
            },
            "pending": {},
        },
    )
    r = c.get("/queue/health")
    assert r.status_code == 200
    body = r.json()
    assert body["redis"] == "ok"
    assert "dlq_streams" in body
    assert body["dlq_streams"]["secplat.events.correlation.dlq"] == 1
