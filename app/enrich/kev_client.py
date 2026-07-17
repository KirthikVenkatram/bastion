"""Client for CISA's Known Exploited Vulnerabilities catalog."""
from __future__ import annotations

import asyncio
import logging
import time

import httpx

KEV_CATALOG_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
CACHE_TTL_SECONDS = 3600

logger = logging.getLogger(__name__)

_catalog_cache: set[str] | None = None
_catalog_fetched_at = 0.0
_cache_lock = asyncio.Lock()


def _is_cache_fresh(now: float) -> bool:
    return (
        _catalog_cache is not None
        and now - _catalog_fetched_at < CACHE_TTL_SECONDS
    )


async def fetch_kev_catalog() -> set[str]:
    """Fetch the KEV catalog, reusing a process-wide cache for one hour."""
    global _catalog_cache, _catalog_fetched_at

    cached_catalog = _catalog_cache
    if _is_cache_fresh(time.time()) and cached_catalog is not None:
        return cached_catalog

    async with _cache_lock:
        cached_catalog = _catalog_cache
        if _is_cache_fresh(time.time()) and cached_catalog is not None:
            return cached_catalog

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(KEV_CATALOG_URL)
                response.raise_for_status()
        except httpx.HTTPError as error:
            logger.warning("Unable to fetch CISA KEV catalog: %s", error)
            return set()

        catalog = {
            vulnerability["cveID"]
            for vulnerability in response.json().get("vulnerabilities", [])
            if "cveID" in vulnerability
        }
        _catalog_cache = catalog
        _catalog_fetched_at = time.time()
        return catalog


def is_in_kev(cve_id: str, catalog: set[str]) -> bool:
    """Return whether a CVE ID appears in a KEV catalog, case-insensitively."""
    return cve_id.upper() in {catalog_id.upper() for catalog_id in catalog}
