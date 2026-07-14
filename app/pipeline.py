"""
Bastion pipeline orchestrator.

Flow: scan -> resolve CVEs -> enrich (EPSS + KEV) -> propose fix (GPT-5.6)
      -> gate.rego decision -> act (auto-merge / ask / block)

Each stage is implemented in its own module under app/ and is independently
testable. This file only wires them together — no business logic here.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

POLICY_PATH = Path(__file__).parent.parent / "policy" / "gate.rego"


@dataclass
class Finding:
    cve_id: str
    package: str
    current_version: str
    fixed_version: str
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


def run_pipeline(repo_full_name: str, installation_id: int) -> None:
    """
    Entry point called by the webhook handler on push/install events.

    TODO (Codex tasks, one per module):
      1. app/scanner/manifest.py   -> list[Finding] candidates (pre-CVE)
      2. app/enrich/osv_client.py  -> resolve candidates to real CVEs
      3. app/enrich/epss_client.py + kev_client.py -> fill epss_score/in_kev
      4. app/propose/gpt_fix.py    -> generate the actual patch diff
      5. evaluate_gate(finding)    -> already implemented above
      6. app/github_app/actions.py -> act on the decision (PR/merge/issue)
      7. app/notify/email.py       -> send email for "ask" decisions
    """
    raise NotImplementedError("wire up stages 1-7 above")
