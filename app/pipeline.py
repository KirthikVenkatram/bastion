"""
Bastion pipeline orchestrator.

Flow: scan -> resolve CVEs -> enrich (EPSS + KEV) -> propose fix (GPT-5.6)
      -> gate.rego decision -> act (auto-merge / ask / block)

Each stage is implemented in its own module under app/ and is independently
testable. This file only wires them together — no business logic here.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.enrich.epss_client import fetch_epss_scores
from app.enrich.kev_client import fetch_kev_catalog, is_in_kev
from app.enrich.osv_client import fetch_osv_vulnerabilities
from app.github_app.actions import get_installation_client, merge_pr, open_issue, open_pr
from app.propose.gpt_fix import propose_fix

try:
    from app.scanner.manifest import scan_manifests
except ModuleNotFoundError:
    scan_manifests = None

POLICY_PATH = Path(__file__).parent.parent / "policy" / "gate.rego"

logger = logging.getLogger(__name__)


@dataclass
class Finding:
    cve_id: str
    package: str
    current_version: str
    fixed_version: str | None
    bump_type: str
    epss_score: float
    in_kev: bool
    severity: str


def evaluate_gate(finding: Finding) -> dict:
    """Shell out to OPA to get the auto/ask/block decision. Never decide in Python."""
    result = subprocess.run(
        ["opa", "eval", "-I", "-d", str(POLICY_PATH), "data.gate",
         "--format", "json"],
        input=json.dumps(finding.__dict__),
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout)["result"][0]["expressions"][0]["value"]


def classify_bump(current_version: str, fixed_version: str | None) -> str:
    """Classify a semantic-version change, defaulting unsafe input to major."""
    if fixed_version is None:
        return "major"

    def parse(version: str) -> tuple[int, int, int] | None:
        normalized = version.removeprefix("v").split("+", 1)[0].split("-", 1)[0]
        parts = normalized.split(".")
        if len(parts) != 3 or not all(part.isdigit() for part in parts):
            return None
        return int(parts[0]), int(parts[1]), int(parts[2])

    current = parse(current_version)
    fixed = parse(fixed_version)
    if current is None or fixed is None:
        return "major"
    if fixed[0] != current[0]:
        return "major"
    if fixed[1] != current[1]:
        return "minor"
    return "patch"


def _result(finding: dict[str, Any], decision: str, reason: str) -> dict[str, Any]:
    return {
        "cve_id": finding["cve_id"],
        "package": finding["package"],
        "decision": decision,
        "reason": reason,
        "pr_number": None,
        "issue_number": None,
    }


async def _notify_ask(
    finding: dict[str, Any],
    repo_full_name: str,
    pr_number: int,
    proposal: dict[str, str],
) -> None:
    """Send an ask notification when the optional notifier is available."""
    try:
        from app.notify import email
    except ImportError:
        # TODO: Wire the notification call once app.notify.email exists.
        return

    notify = getattr(email, "send_ask_notification", None)
    if notify is None:
        logger.warning("Ask notification module has no send_ask_notification function")
        return
    recipient = os.getenv("NOTIFY_EMAIL_TO")
    if not recipient:
        # TODO: Obtain the recipient from repository notification preferences.
        logger.warning("Ask notification skipped because NOTIFY_EMAIL_TO is unset")
        return
    await notify(
        recipient,
        finding["cve_id"],
        finding["package"],
        finding["current_version"],
        proposal["target_version"],
        finding["epss_score"],
        finding["in_kev"],
        f"https://github.com/{repo_full_name}/pull/{pr_number}",
        proposal["rationale"],
    )


async def run_pipeline(repo_full_name: str, installation_id: int) -> list[dict[str, Any]]:
    """Scan, enrich, propose, gate, and act on dependency vulnerabilities."""
    if scan_manifests is None:
        logger.error("Manifest scanner is not available")
        return []

    try:
        dependencies = scan_manifests(repo_full_name)
        vulnerabilities = await fetch_osv_vulnerabilities(dependencies)
        epss_scores, kev_catalog = await asyncio.gather(
            fetch_epss_scores([vulnerability["cve_id"] for vulnerability in vulnerabilities]),
            fetch_kev_catalog(),
        )
    except Exception as error:
        logger.error("Pipeline discovery and enrichment failed: %s", error)
        return []

    client = None
    results: list[dict[str, Any]] = []
    for vulnerability in vulnerabilities:
        try:
            enriched = {
                **vulnerability,
                "epss_score": epss_scores.get(vulnerability["cve_id"], 0.0),
                "in_kev": is_in_kev(vulnerability["cve_id"], kev_catalog),
            }
            proposal = await propose_fix(enriched)
            if proposal is None:
                result = _result(enriched, "block", "no confident fix available")
                if client is None:
                    client = get_installation_client(installation_id)
                result["issue_number"] = open_issue(
                    client,
                    repo_full_name,
                    enriched["cve_id"],
                    enriched["package"],
                    result["reason"],
                )
                results.append(result)
                continue

            gate_finding = Finding(
                cve_id=enriched["cve_id"],
                package=enriched["package"],
                current_version=enriched["current_version"],
                fixed_version=proposal["target_version"],
                bump_type=classify_bump(
                    enriched["current_version"], proposal["target_version"]
                ),
                epss_score=enriched["epss_score"],
                in_kev=enriched["in_kev"],
                severity=enriched["severity"],
            )
            gate_result = evaluate_gate(gate_finding)
            result = _result(enriched, gate_result["decision"], gate_result["reason"])
            if client is None:
                client = get_installation_client(installation_id)

            if result["decision"] in {"auto", "ask"}:
                result["pr_number"] = open_pr(
                    client,
                    repo_full_name,
                    enriched["package"],
                    enriched["current_version"],
                    proposal["target_version"],
                    proposal["diff"],
                    proposal["rationale"],
                )
                if result["decision"] == "auto":
                    merge_pr(client, repo_full_name, result["pr_number"])
                else:
                    await _notify_ask(
                        enriched,
                        repo_full_name,
                        result["pr_number"],
                        proposal,
                    )
            elif result["decision"] == "block":
                result["issue_number"] = open_issue(
                    client,
                    repo_full_name,
                    enriched["cve_id"],
                    enriched["package"],
                    result["reason"],
                )
            else:
                raise ValueError(f"Unknown gate decision: {result['decision']}")
            results.append(result)
        except Exception as error:
            logger.exception(
                "Pipeline failed while processing %s in %s",
                vulnerability["cve_id"],
                vulnerability["package"],
            )
            failed = _result(vulnerability, "error", "finding processing failed")
            failed["error"] = str(error)
            results.append(failed)
    return results
