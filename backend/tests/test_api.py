from fastapi.testclient import TestClient
import time

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
        start = client.post(
            "/api/demo/start",
            json={"scenario": "mixed", "speed": 5, "reset": True},
        )
        assert start.status_code == 200
        assert start.json()["running"] is True

        deadline = time.monotonic() + 6
        delivered = 0
        while time.monotonic() < deadline:
            time.sleep(0.2)
            delivered = client.get("/api/health").json()["demo"]["windows_delivered"]
            if delivered:
                break
        assert delivered > 0

        response = client.get("/api/summary")
        assert response.status_code == 200
        assert "timeline" in response.json()

        flows = client.get("/api/flows?limit=1").json()
        assert flows
        assert flows[0]["window_start"].endswith("Z") or flows[0]["window_start"].endswith("+00:00")

        stop = client.post("/api/demo/stop")
        assert stop.status_code == 200
        assert stop.json()["running"] is False
