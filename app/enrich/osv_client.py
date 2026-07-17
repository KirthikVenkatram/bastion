"""Client for resolving dependency vulnerabilities through OSV.dev."""
from __future__ import annotations

import logging
import math
from collections.abc import Iterable
from typing import Any

import httpx

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_BATCH_QUERY_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULNERABILITY_URL = "https://api.osv.dev/v1/vulns"
BATCH_THRESHOLD = 5

logger = logging.getLogger(__name__)


def _query(dependency: dict[str, str]) -> dict[str, Any]:
    return {
        "version": dependency["current_version"],
        "package": {
            "name": dependency["package"],
            "ecosystem": dependency["ecosystem"],
        },
    }


def _fixed_version(vulnerability: dict[str, Any]) -> str | None:
    for affected in vulnerability.get("affected", []):
        for version_range in affected.get("ranges", []):
            for event in version_range.get("events", []):
                fixed = event.get("fixed")
                if fixed:
                    return fixed
    return None


def _cve_id(vulnerability: dict[str, Any]) -> str:
    return next(
        (alias for alias in vulnerability.get("aliases", []) if alias.startswith("CVE-")),
        vulnerability["id"],
    )


def _round_up(value: float) -> float:
    return math.ceil(value * 10 - 0.000001) / 10


def _cvss_v3_score(vector: str) -> float | None:
    """Calculate a CVSS v3 base score from an OSV CVSS vector."""
    if not vector.startswith("CVSS:3."):
        return None

    metrics = dict(part.split(":", 1) for part in vector.split("/")[1:] if ":" in part)
    try:
        attack_vector = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[metrics["AV"]]
        attack_complexity = {"L": 0.77, "H": 0.44}[metrics["AC"]]
        user_interaction = {"N": 0.85, "R": 0.62}[metrics["UI"]]
        scope = metrics["S"]
        privileges_required = {
            "U": {"N": 0.85, "L": 0.62, "H": 0.27},
            "C": {"N": 0.85, "L": 0.68, "H": 0.5},
        }[scope][metrics["PR"]]
        impact_weights = {"H": 0.56, "L": 0.22, "N": 0.0}
        confidentiality = impact_weights[metrics["C"]]
        integrity = impact_weights[metrics["I"]]
        availability = impact_weights[metrics["A"]]
    except (KeyError, ValueError):
        return None

    impact_subscore = 1 - (1 - confidentiality) * (1 - integrity) * (1 - availability)
    if impact_subscore <= 0:
        return 0.0

    impact = (
        6.42 * impact_subscore
        if scope == "U"
        else 7.52 * (impact_subscore - 0.029) - 3.25 * (impact_subscore - 0.02) ** 15
    )
    exploitability = 8.22 * attack_vector * attack_complexity * privileges_required * user_interaction
    score = (
        min(impact + exploitability, 10)
        if scope == "U"
        else min(1.08 * (impact + exploitability), 10)
    )
    return _round_up(score)


def _severity(vulnerability: dict[str, Any]) -> str:
    scores: list[float] = []
    for severity in vulnerability.get("severity", []):
        raw_score = severity.get("score", "")
        try:
            scores.append(float(raw_score))
        except (TypeError, ValueError):
            vector_score = _cvss_v3_score(raw_score)
            if vector_score is not None:
                scores.append(vector_score)

    if not scores:
        return "medium"

    score = max(scores)
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _findings(
    dependency: dict[str, str], vulnerabilities: Iterable[dict[str, Any]]
) -> list[dict[str, str | None]]:
    return [
        {
            "cve_id": _cve_id(vulnerability),
            "package": dependency["package"],
            "current_version": dependency["current_version"],
            "fixed_version": _fixed_version(vulnerability),
            "summary": vulnerability.get("summary", ""),
            "severity": _severity(vulnerability),
        }
        for vulnerability in vulnerabilities
    ]


async def _fetch_vulnerability(
    client: httpx.AsyncClient, vulnerability_id: str
) -> dict[str, Any] | None:
    try:
        response = await client.get(f"{OSV_VULNERABILITY_URL}/{vulnerability_id}")
        response.raise_for_status()
    except httpx.HTTPError as error:
        logger.warning("Unable to fetch OSV vulnerability %s: %s", vulnerability_id, error)
        return None
    return response.json()


async def _fetch_batched_findings(
    client: httpx.AsyncClient, dependencies: list[dict[str, str]]
) -> list[dict[str, str | None]]:
    try:
        response = await client.post(
            OSV_BATCH_QUERY_URL,
            json={"queries": [_query(dependency) for dependency in dependencies]},
        )
        response.raise_for_status()
    except httpx.HTTPError as error:
        logger.warning("Unable to query OSV for dependency batch: %s", error)
        return []

    findings: list[dict[str, str | None]] = []
    for dependency, result in zip(dependencies, response.json().get("results", [])):
        vulnerability_ids = [
            vulnerability["id"] for vulnerability in result.get("vulns", [])
        ]
        details = []
        for vulnerability_id in vulnerability_ids:
            vulnerability = await _fetch_vulnerability(client, vulnerability_id)
            if vulnerability is None:
                details = []
                break
            details.append(vulnerability)
        findings.extend(_findings(dependency, details))
    return findings


async def fetch_osv_vulnerabilities(
    dependencies: list[dict[str, str]],
) -> list[dict[str, str | None]]:
    """Resolve dependencies to OSV findings, including published fix versions."""
    if not dependencies:
        return []

    async with httpx.AsyncClient(timeout=10.0) as client:
        if len(dependencies) > BATCH_THRESHOLD:
            return await _fetch_batched_findings(client, dependencies)

        findings: list[dict[str, str | None]] = []
        for dependency in dependencies:
            try:
                response = await client.post(OSV_QUERY_URL, json=_query(dependency))
                response.raise_for_status()
            except httpx.HTTPError as error:
                logger.warning("Unable to query OSV for %s: %s", dependency["package"], error)
                continue
            findings.extend(_findings(dependency, response.json().get("vulns", [])))
    return findings


resolve_vulnerabilities = fetch_osv_vulnerabilities
fetch_vulnerabilities = fetch_osv_vulnerabilities
