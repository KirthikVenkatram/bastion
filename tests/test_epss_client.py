"""Tests for the EPSS API client."""
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.enrich.epss_client import EPSS_URL, fetch_epss_scores


def mock_client(response: MagicMock) -> MagicMock:
    client = MagicMock()
    client.get = AsyncMock(return_value=response)
    client_context = MagicMock()
    client_context.__aenter__ = AsyncMock(return_value=client)
    client_context.__aexit__ = AsyncMock(return_value=None)
    return client_context


@pytest.fixture
def complete_response() -> MagicMock:
    response = MagicMock()
    response.json.return_value = {
        "data": [
            {"cve": "CVE-2024-1234", "epss": "0.45231", "percentile": "0.89012"},
            {"cve": "CVE-2024-5678", "epss": "0.10000", "percentile": "0.50000"},
        ]
    }
    return response


@pytest.fixture
def partial_response() -> MagicMock:
    response = MagicMock()
    response.json.return_value = {
        "data": [
            {"cve": "CVE-2024-1234", "epss": "0.45231", "percentile": "0.89012"}
        ]
    }
    return response


@pytest.mark.asyncio
async def test_fetch_epss_scores_returns_all_scores(complete_response: MagicMock) -> None:
    client_context = mock_client(complete_response)

    with patch("app.enrich.epss_client.httpx.AsyncClient", return_value=client_context):
        scores = await fetch_epss_scores(["CVE-2024-1234", "CVE-2024-5678"])

    assert scores == {"CVE-2024-1234": 0.45231, "CVE-2024-5678": 0.1}
    client_context.__aenter__.return_value.get.assert_awaited_once_with(
        EPSS_URL, params={"cve": "CVE-2024-1234,CVE-2024-5678"}
    )


@pytest.mark.asyncio
async def test_fetch_epss_scores_omits_cves_missing_from_response(
    partial_response: MagicMock,
) -> None:
    client_context = mock_client(partial_response)

    with patch("app.enrich.epss_client.httpx.AsyncClient", return_value=client_context):
        scores = await fetch_epss_scores(["CVE-2024-1234", "CVE-2024-9999"])

    assert scores == {"CVE-2024-1234": 0.45231}


@pytest.mark.asyncio
async def test_fetch_epss_scores_does_not_request_for_empty_input() -> None:
    with patch("app.enrich.epss_client.httpx.AsyncClient") as async_client:
        scores = await fetch_epss_scores([])

    assert scores == {}
    async_client.assert_not_called()


@pytest.mark.asyncio
async def test_fetch_epss_scores_keeps_completed_batches_after_timeout() -> None:
    response = MagicMock()
    response.json.return_value = {
        "data": [{"cve": "CVE-2024-0000", "epss": "0.45231"}]
    }
    client_context = mock_client(response)
    client_context.__aenter__.return_value.get.side_effect = [
        response,
        httpx.TimeoutException("EPSS request timed out"),
    ]
    cve_ids = [f"CVE-2024-{number:04d}" for number in range(101)]

    with patch("app.enrich.epss_client.httpx.AsyncClient", return_value=client_context):
        scores = await fetch_epss_scores(cve_ids)

    assert scores == {"CVE-2024-0000": 0.45231}
    assert client_context.__aenter__.return_value.get.await_count == 2
