from fastapi.testclient import TestClient

from app.main import app


def test_health_endpoint() -> None:
    with TestClient(app) as client:
        response = client.get("/api/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"


def test_websocket_stream_announces_itself() -> None:
    with TestClient(app) as client:
        with client.websocket_connect("/ws/live") as websocket:
            message = websocket.receive_json()
            assert message["type"] == "hello"
            assert message["data"]["service"] == "NetSentry AI"


def test_demo_and_dashboard_flow() -> None:
    with TestClient(app) as client:
        start = client.post("/api/demo/start", json={"scenario": "mixed", "speed": 5, "reset": True})
        assert start.status_code == 200
        assert start.json()["running"] is True
        response = client.get("/api/summary")
        assert response.status_code == 200
        assert "timeline" in response.json()
        stop = client.post("/api/demo/stop")
        assert stop.status_code == 200
        assert stop.json()["running"] is False
