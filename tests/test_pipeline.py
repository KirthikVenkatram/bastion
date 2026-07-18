"""Tests for the end-to-end remediation pipeline."""
from contextlib import ExitStack
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app import pipeline


@pytest.fixture
def dependency() -> dict[str, str]:
    return {"package": "requests", "current_version": "2.31.0", "ecosystem": "PyPI"}


@pytest.fixture
def vulnerability() -> dict[str, object]:
    return {
        "cve_id": "CVE-2024-1234",
        "package": "requests",
        "current_version": "2.31.0",
        "fixed_version": "2.32.0",
        "summary": "A vulnerability in requests.",
        "severity": "high",
    }


@pytest.fixture
def proposal() -> dict[str, str]:
    return {
        "package": "requests",
        "current_version": "2.31.0",
        "target_version": "2.32.0",
        "diff": "--- a/requirements.txt\n+++ b/requirements.txt\n@@ -1 +1 @@\n-requests==2.31.0\n+requests==2.32.0\n",
        "rationale": "Bumps requests to the published security fix.",
        "confidence": "high",
    }


def pipeline_mocks(
    dependency: dict[str, str], vulnerability: dict[str, object], proposal: dict[str, str]
):
    return (
        patch("app.pipeline.scan_manifests", return_value=[dependency]),
        patch("app.pipeline.fetch_osv_vulnerabilities", new=AsyncMock(return_value=[vulnerability])),
        patch("app.pipeline.fetch_epss_scores", new=AsyncMock(return_value={"CVE-2024-1234": 0.7})),
        patch("app.pipeline.fetch_kev_catalog", new=AsyncMock(return_value={"CVE-2024-1234"})),
        patch("app.pipeline.propose_fix", new=AsyncMock(return_value=proposal)),
        patch("app.pipeline.get_installation_client", return_value=MagicMock()),
        patch("app.pipeline.open_pr", return_value=42),
        patch("app.pipeline.merge_pr"),
        patch("app.pipeline.open_issue", return_value=84),
    )


async def run_with_mocks(
    mocks: list, gate_result: dict | None
) -> tuple[list[dict], MagicMock, list[MagicMock]]:
    with ExitStack() as stack:
        installed_mocks = [stack.enter_context(mock) for mock in mocks]
        evaluate_gate = stack.enter_context(
            patch("app.pipeline.evaluate_gate", return_value=gate_result)
        )
        results = await pipeline.run_pipeline("acme/project", 1)
    return results, evaluate_gate, installed_mocks


@pytest.mark.asyncio
async def test_run_pipeline_auto_merges(
    dependency: dict[str, str], vulnerability: dict[str, object], proposal: dict[str, str]
) -> None:
    results, _, installed_mocks = await run_with_mocks(
        list(pipeline_mocks(dependency, vulnerability, proposal)),
        {"decision": "auto", "reason": "safe"},
    )

    assert results == [{"cve_id": "CVE-2024-1234", "package": "requests", "decision": "auto", "reason": "safe", "pr_number": 42, "issue_number": None}]
    installed_mocks[7].assert_called_once()


@pytest.mark.asyncio
async def test_run_pipeline_ask_opens_but_does_not_merge(
    dependency: dict[str, str], vulnerability: dict[str, object], proposal: dict[str, str]
) -> None:
    results, _, installed_mocks = await run_with_mocks(
        list(pipeline_mocks(dependency, vulnerability, proposal)),
        {"decision": "ask", "reason": "review"},
    )

    assert results[0]["decision"] == "ask"
    assert results[0]["pr_number"] == 42
    installed_mocks[7].assert_not_called()


@pytest.mark.asyncio
async def test_run_pipeline_block_opens_issue(
    dependency: dict[str, str], vulnerability: dict[str, object], proposal: dict[str, str]
) -> None:
    results, _, installed_mocks = await run_with_mocks(
        list(pipeline_mocks(dependency, vulnerability, proposal)),
        {"decision": "block", "reason": "major bump"},
    )

    assert results[0]["decision"] == "block"
    assert results[0]["issue_number"] == 84
    installed_mocks[8].assert_called_once()


@pytest.mark.asyncio
async def test_run_pipeline_blocks_when_model_has_no_confident_fix(
    dependency: dict[str, str], vulnerability: dict[str, object], proposal: dict[str, str]
) -> None:
    mocks = list(pipeline_mocks(dependency, vulnerability, proposal))
    mocks[4] = patch("app.pipeline.propose_fix", new=AsyncMock(return_value=None))
    results, evaluate_gate, _ = await run_with_mocks(mocks, None)

    assert results[0]["decision"] == "block"
    assert results[0]["reason"] == "no confident fix available"
    assert results[0]["issue_number"] == 84
    evaluate_gate.assert_not_called()


@pytest.mark.asyncio
async def test_run_pipeline_continues_after_one_finding_fails(
    dependency: dict[str, str], vulnerability: dict[str, object], proposal: dict[str, str]
) -> None:
    second_vulnerability = {**vulnerability, "cve_id": "CVE-2024-5678", "package": "urllib3"}
    mocks = list(pipeline_mocks(dependency, vulnerability, proposal))
    mocks[1] = patch(
        "app.pipeline.fetch_osv_vulnerabilities",
        new=AsyncMock(return_value=[vulnerability, second_vulnerability]),
    )
    mocks[6] = patch("app.pipeline.open_pr", side_effect=[RuntimeError("GitHub unavailable"), 43])
    results, _, installed_mocks = await run_with_mocks(
        mocks, {"decision": "auto", "reason": "safe"}
    )

    assert results[0]["decision"] == "error"
    assert results[0]["error"] == "GitHub unavailable"
    assert results[1]["decision"] == "auto"
    assert results[1]["pr_number"] == 43
    installed_mocks[7].assert_called_once()


@pytest.mark.parametrize(
    ("current_version", "fixed_version", "expected"),
    [
        ("1.2.3", "1.2.4", "patch"),
        ("1.2.3", "1.3.0", "minor"),
        ("1.2.3", "2.0.0", "major"),
        ("invalid", "2.0.0", "major"),
        ("1.2.3", None, "major"),
    ],
)
def test_classify_bump(
    current_version: str, fixed_version: str | None, expected: str
) -> None:
    assert pipeline.classify_bump(current_version, fixed_version) == expected
