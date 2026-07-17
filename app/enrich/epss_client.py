"""Client for retrieving Exploit Prediction Scoring System (EPSS) scores."""
from __future__ import annotations

import logging
from collections.abc import Iterator

import httpx

EPSS_URL = "https://api.first.org/data/v1/epss"
EPSS_BATCH_SIZE = 100

logger = logging.getLogger(__name__)


def _batches(cve_ids: list[str]) -> Iterator[list[str]]:
    """Yield CVE IDs in batches accepted by the EPSS API."""
    for start in range(0, len(cve_ids), EPSS_BATCH_SIZE):
        yield cve_ids[start:start + EPSS_BATCH_SIZE]


async def fetch_epss_scores(cve_ids: list[str]) -> dict[str, float]:
    """Return ``{cve_id: epss_score}`` for CVEs with EPSS data available."""
    if not cve_ids:
        return {}

    scores: dict[str, float] = {}
    async with httpx.AsyncClient(timeout=10.0) as client:
        for batch in _batches(cve_ids):
            try:
                response = await client.get(EPSS_URL, params={"cve": ",".join(batch)})
                response.raise_for_status()
            except httpx.HTTPError as error:
                logger.warning("Unable to fetch EPSS scores for CVE batch: %s", error)
                continue

            for item in response.json().get("data", []):
                scores[item["cve"]] = float(item["epss"])

    return scores
