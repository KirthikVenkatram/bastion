"""
Tests for policy/gate.rego — run via `opa eval` per case.
Mirrors the auto/ask/block test pattern used in CODEX.

Requires the opa binary on PATH (installed via Codex environment setup script,
or `brew install opa` / manual download locally).
"""
import json
import subprocess
from pathlib import Path

POLICY_PATH = Path(__file__).parent.parent / "policy" / "gate.rego"


def eval_gate(input_data: dict) -> dict:
    result = subprocess.run(
        [
            "opa", "eval",
            "-I",
            "-d", str(POLICY_PATH),
            "data.gate",
            "--format", "json",
        ],
        input=json.dumps(input_data),
        capture_output=True,
        text=True,
        check=True,
    )
    parsed = json.loads(result.stdout)
    return parsed["result"][0]["expressions"][0]["value"]


def base_input(**overrides) -> dict:
    defaults = {
        "cve_id": "CVE-2024-00000",
        "package": "example-pkg",
        "current_version": "1.0.0",
        "fixed_version": "1.0.1",
        "bump_type": "patch",
        "epss_score": 0.1,
        "in_kev": False,
        "severity": "medium",
    }
    defaults.update(overrides)
    return defaults


def test_auto_when_kev_and_high_epss_and_patch():
    out = eval_gate(base_input(bump_type="patch", in_kev=True, epss_score=0.8))
    assert out["decision"] == "auto"


def test_block_when_major_bump_even_with_kev():
    out = eval_gate(base_input(bump_type="major", in_kev=True, epss_score=0.9))
    assert out["decision"] == "block"


def test_block_when_low_signal_minor_bump():
    out = eval_gate(
        base_input(bump_type="minor", in_kev=False, epss_score=0.05, severity="low")
    )
    assert out["decision"] == "block"


def test_ask_when_moderate_signal():
    out = eval_gate(
        base_input(bump_type="patch", in_kev=False, epss_score=0.3, severity="high")
    )
    assert out["decision"] == "ask"


def test_ask_when_kev_but_epss_below_threshold():
    out = eval_gate(base_input(bump_type="patch", in_kev=True, epss_score=0.2))
    assert out["decision"] == "ask"


def test_auto_never_fires_on_minor_bump():
    out = eval_gate(base_input(bump_type="minor", in_kev=True, epss_score=0.95))
    assert out["decision"] != "auto"
