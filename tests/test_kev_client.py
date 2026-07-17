"""Tests for the CISA KEV catalog client."""
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.enrich import kev_client


def mock_client(response: MagicMock | Exception) -> MagicMock:
    client = MagicMock()
    client.get = AsyncMock()
    client.get.side_effect = response if isinstance(response, Exception) else None
    if not isinstance(response, Exception):
        client.get.return_value = response
    client_context = MagicMock()
    client_context.__aenter__ = AsyncMock(return_value=client)
    client_context.__aexit__ = AsyncMock(return_value=None)
    return client_context


@pytest.fixture(autouse=True)
def clear_kev_cache() -> None:
    kev_client._catalog_cache = None
    kev_client._catalog_fetched_at = 0.0


@pytest.fixture
def kev_response() -> MagicMock:
    response = MagicMock()
    response.json.return_value = {
        "vulnerabilities": [
            {"cveID": "CVE-2024-1234"},
            {"cveID": "CVE-2023-5678"},
        ]
    }
    return response


@pytest.mark.asyncio
async def test_fetch_kev_catalog_returns_cve_ids(kev_response: MagicMock) -> None:
    client_context = mock_client(kev_response)

    with patch("app.enrich.kev_client.httpx.AsyncClient", return_value=client_context):
        catalog = await kev_client.fetch_kev_catalog()

    assert catalog == {"CVE-2024-1234", "CVE-2023-5678"}
    client_context.__aenter__.return_value.get.assert_awaited_once_with(
        kev_client.KEV_CATALOG_URL
    )


def test_is_in_kev_is_case_insensitive() -> None:
    catalog = {"CVE-2024-1234"}

    assert kev_client.is_in_kev("cve-2024-1234", catalog)
    assert not kev_client.is_in_kev("CVE-2024-9999", catalog)


@pytest.mark.asyncio
async def test_fetch_kev_catalog_returns_empty_set_on_timeout() -> None:
    client_context = mock_client(httpx.TimeoutException("KEV request timed out"))

    with patch("app.enrich.kev_client.httpx.AsyncClient", return_value=client_context):
        catalog = await kev_client.fetch_kev_catalog()

    assert catalog == set()


@pytest.mark.asyncio
async def test_fetch_kev_catalog_reuses_cache_within_ttl(kev_response: MagicMock) -> None:
    client_context = mock_client(kev_response)

    with (
        patch("app.enrich.kev_client.httpx.AsyncClient", return_value=client_context),
        patch("app.enrich.kev_client.time.time", return_value=1000.0),
    ):
        first_catalog = await kev_client.fetch_kev_catalog()
        second_catalog = await kev_client.fetch_kev_catalog()

    assert first_catalog == second_catalog
    client_context.__aenter__.return_value.get.assert_awaited_once()
