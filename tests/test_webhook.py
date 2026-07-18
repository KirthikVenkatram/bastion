"""Tests for the GitHub webhook entrypoint."""
import hashlib
import hmac
import json
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient
import pytest

from app.github_app.webhook import app


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "webhook-secret")
    return TestClient(app)


def signed_headers(event: str, payload: bytes) -> dict[str, str]:
    digest = hmac.new(b"webhook-secret", payload, hashlib.sha256).hexdigest()
    return {
        "X-GitHub-Event": event,
        "X-Hub-Signature-256": f"sha256={digest}",
        "Content-Type": "application/json",
    }


def test_valid_push_schedules_pipeline(client: TestClient) -> None:
    payload = json.dumps(
        {"repository": {"full_name": "acme/project"}, "installation": {"id": 12}}
    ).encode()

    with patch("app.github_app.webhook.run_pipeline", new=AsyncMock()) as run_pipeline:
        response = client.post("/webhook", content=payload, headers=signed_headers("push", payload))

    assert response.status_code == 200
    assert response.json() == {"status": "accepted"}
    run_pipeline.assert_awaited_once_with("acme/project", 12)


def test_invalid_signature_is_rejected(client: TestClient) -> None:
    payload = b'{"repository": {}}'

    response = client.post(
        "/webhook",
        content=payload,
        headers={"X-GitHub-Event": "push", "X-Hub-Signature-256": "sha256=invalid"},
    )

    assert response.status_code == 401


def test_unknown_event_is_accepted_without_pipeline(client: TestClient) -> None:
    payload = b'{"action": "opened"}'

    with patch("app.github_app.webhook.run_pipeline", new=AsyncMock()) as run_pipeline:
        response = client.post("/webhook", content=payload, headers=signed_headers("issues", payload))

    assert response.status_code == 200
    run_pipeline.assert_not_awaited()


def test_malformed_payload_is_rejected(client: TestClient) -> None:
    payload = b"not json"

    response = client.post("/webhook", content=payload, headers=signed_headers("push", payload))

    assert response.status_code == 400


def test_health_check(client: TestClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
