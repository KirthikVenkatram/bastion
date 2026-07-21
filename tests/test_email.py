"""Tests for ask-path email notifications."""
from unittest.mock import patch

import pytest

from app.notify.email import send_ask_notification


@pytest.mark.asyncio
async def test_send_ask_notification_sends_security_alert(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RESEND_API_KEY", "test-key")
    monkeypatch.setenv("NOTIFY_EMAIL_FROM", "bastion@example.com")

    with patch("app.notify.email.resend.Emails.send") as send:
        sent = await send_ask_notification(
            ["pusher@example.com", "maintainer@example.com"],
            "CVE-2024-1234",
            "requests",
            "2.31.0",
            "2.32.0",
            0.7,
            True,
            "https://github.com/acme/project/pull/42",
            "Bumps requests to its published security fix.",
        )

    assert sent is True
    assert send.call_args.args[0]["subject"] == (
        "Bastion: CVE-2024-1234 in requests needs your approval"
    )
    assert send.call_args.args[0]["to"] == ["pusher@example.com", "maintainer@example.com"]
    assert "actively exploited" in send.call_args.args[0]["text"]


@pytest.mark.asyncio
async def test_send_ask_notification_returns_false_on_api_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("RESEND_API_KEY", "test-key")
    monkeypatch.setenv("NOTIFY_EMAIL_FROM", "bastion@example.com")

    with patch("app.notify.email.resend.Emails.send", side_effect=RuntimeError("Resend failed")):
        sent = await send_ask_notification(
            ["maintainer@example.com"],
            "CVE-2024-1234",
            "requests",
            "2.31.0",
            "2.32.0",
            0.7,
            False,
            "https://github.com/acme/project/pull/42",
            "Bumps requests to its published security fix.",
        )

    assert sent is False


@pytest.mark.asyncio
async def test_send_ask_notification_returns_false_when_configuration_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("RESEND_API_KEY", raising=False)
    monkeypatch.delenv("NOTIFY_EMAIL_FROM", raising=False)

    with patch("app.notify.email.resend.Emails.send") as send:
        sent = await send_ask_notification(
            ["maintainer@example.com"],
            "CVE-2024-1234",
            "requests",
            "2.31.0",
            "2.32.0",
            0.7,
            False,
            "https://github.com/acme/project/pull/42",
            "Bumps requests to its published security fix.",
        )

    assert sent is False
    send.assert_not_called()
