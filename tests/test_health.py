from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "message" in data
    assert data["health"] == "/health"
    assert "version" in data


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["app"] == "WhistleDrop"
    assert "version" in data


def test_api_v1_health_endpoint():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["app"] == "WhistleDrop"
    assert "version" in data


def test_cors_headers_allowed_origin():
    """Verify that requests from an allowed origin receive CORS headers."""
    response = client.get(
        "/health",
        headers={"Origin": "http://localhost:3000"},
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:3000"
    assert response.headers.get("access-control-allow-credentials") == "true"


def test_cors_headers_unallowed_origin():
    """Verify that requests from an unauthorized origin do not receive CORS allow headers."""
    response = client.get(
        "/health",
        headers={"Origin": "https://malicious-site.example.com"},
    )
    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers
