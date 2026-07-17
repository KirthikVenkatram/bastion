"""Tests for the OSV API client."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.enrich.osv_client import (
    OSV_BATCH_QUERY_URL,
    OSV_QUERY_URL,
    fetch_osv_vulnerabilities,
)


def mock_client(response: MagicMock) -> MagicMock:
    client = MagicMock()
    client.post = AsyncMock(return_value=response)
    client.get = AsyncMock()
    client_context = MagicMock()
    client_context.__aenter__ = AsyncMock(return_value=client)
    client_context.__aexit__ = AsyncMock(return_value=None)
    return client_context


@pytest.fixture
def known_vulnerability_response() -> MagicMock:
    response = MagicMock()
    response.json.return_value = {
        "vulns": [
            {
                "id": "GHSA-example-1234",
                "aliases": ["CVE-2024-1234"],
                "summary": "A critical example vulnerability.",
                "severity": [{"type": "CVSS_V3", "score": "9.8"}],
                "affected": [
                    {"ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.0.1"}]}]}
                ],
            }
        ]
    }
    return response


@pytest.fixture
def clean_package_response() -> MagicMock:
    response = MagicMock()
    response.json.return_value = {"vulns": []}
    return response


@pytest.fixture
def unfixed_vulnerability_response() -> MagicMock:
    response = MagicMock()
    response.json.return_value = {
        "vulns": [
            {
                "id": "GHSA-unfixed-1234",
                "aliases": [],
                "summary": "An unfixed vulnerability.",
                "affected": [{"ranges": [{"events": [{"introduced": "1.0.0"}]}]}],
            }
        ]
    }
    return response


@pytest.mark.asyncio
async def test_fetch_osv_vulnerabilities_returns_cve_and_fix_version(
    known_vulnerability_response: MagicMock,
) -> None:
    client_context = mock_client(known_vulnerability_response)
    dependency = {"package": "example", "current_version": "2.0.0", "ecosystem": "PyPI"}

    with patch("app.enrich.osv_client.httpx.AsyncClient", return_value=client_context):
        findings = await fetch_osv_vulnerabilities([dependency])

    assert findings == [
        {
            "cve_id": "CVE-2024-1234",
            "package": "example",
            "current_version": "2.0.0",
            "fixed_version": "2.0.1",
            "summary": "A critical example vulnerability.",
            "severity": "critical",
        }
    ]
    client_context.__aenter__.return_value.post.assert_awaited_once_with(
        OSV_QUERY_URL,
        json={
            "version": "2.0.0",
            "package": {"name": "example", "ecosystem": "PyPI"},
        },
    )


@pytest.mark.asyncio
async def test_fetch_osv_vulnerabilities_skips_clean_packages(
    clean_package_response: MagicMock,
) -> None:
    client_context = mock_client(clean_package_response)

    with patch("app.enrich.osv_client.httpx.AsyncClient", return_value=client_context):
        findings = await fetch_osv_vulnerabilities(
            [{"package": "clean-package", "current_version": "1.0.0", "ecosystem": "npm"}]
        )

    assert findings == []


@pytest.mark.asyncio
async def test_fetch_osv_vulnerabilities_keeps_unfixed_vulnerability(
    unfixed_vulnerability_response: MagicMock,
) -> None:
    client_context = mock_client(unfixed_vulnerability_response)

    with patch("app.enrich.osv_client.httpx.AsyncClient", return_value=client_context):
        findings = await fetch_osv_vulnerabilities(
            [{"package": "unfixed", "current_version": "1.0.0", "ecosystem": "PyPI"}]
        )

    assert findings[0]["cve_id"] == "GHSA-unfixed-1234"
    assert findings[0]["fixed_version"] is None
    assert findings[0]["severity"] == "medium"


@pytest.mark.asyncio
async def test_fetch_osv_vulnerabilities_uses_batch_endpoint_for_more_than_five() -> None:
    batch_response = MagicMock()
    batch_response.json.return_value = {
        "results": [{"vulns": [{"id": "GHSA-example-1234"}]}] + [{} for _ in range(5)]
    }
    detail_response = MagicMock()
    detail_response.json.return_value = {
        "id": "GHSA-example-1234",
        "aliases": ["CVE-2024-1234"],
        "summary": "A high severity vulnerability.",
        "severity": [{"type": "CVSS_V3", "score": "7.5"}],
        "affected": [{"ranges": [{"events": [{"fixed": "2.0.1"}]}]}],
    }
    client_context = mock_client(batch_response)
    client_context.__aenter__.return_value.get.return_value = detail_response
    dependencies = [
        {"package": f"package-{number}", "current_version": "1.0.0", "ecosystem": "npm"}
        for number in range(6)
    ]

    with patch("app.enrich.osv_client.httpx.AsyncClient", return_value=client_context):
        findings = await fetch_osv_vulnerabilities(dependencies)

    assert findings[0]["cve_id"] == "CVE-2024-1234"
    client_context.__aenter__.return_value.post.assert_awaited_once()
    assert client_context.__aenter__.return_value.post.await_args.args[0] == OSV_BATCH_QUERY_URL
    client_context.__aenter__.return_value.get.assert_awaited_once_with(
        "https://api.osv.dev/v1/vulns/GHSA-example-1234"
    )
