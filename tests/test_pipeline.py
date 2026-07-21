"""Tests for the end-to-end remediation pipeline."""
from contextlib import ExitStack
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest

from app import pipeline


class NotFoundError(Exception):
    """Minimal Contents API 404 error used by the mock repository."""

    status = 404


@pytest.fixture
def github_client() -> MagicMock:
    client = MagicMock()
    package_manifest = MagicMock()
    package_manifest.decoded_content = b'{"dependencies": {"requests": "2.31.0"}}'

    def get_contents(path: str) -> MagicMock:
        if path == "package.json":
            return package_manifest
        raise NotFoundError()

    client.get_repo.return_value.get_contents.side_effect = get_contents
    return client


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
    github_client: MagicMock, vulnerability: dict[str, object], proposal: dict[str, str]
):
    return (
        patch("app.pipeline.get_installation_client", return_value=github_client),
        patch("app.pipeline.find_existing_bastion_item", return_value=None),
        patch("app.pipeline.fetch_osv_vulnerabilities", new=AsyncMock(return_value=[vulnerability])),
        patch("app.pipeline.fetch_epss_scores", new=AsyncMock(return_value={"CVE-2024-1234": 0.7})),
        patch("app.pipeline.fetch_kev_catalog", new=AsyncMock(return_value={"CVE-2024-1234"})),
        patch("app.pipeline.propose_fix", new=AsyncMock(return_value=proposal)),
        patch("app.pipeline._notify_ask", new=AsyncMock()),
        patch("app.pipeline.open_pr", return_value=42),
        patch("app.pipeline.merge_pr"),
        patch("app.pipeline.open_issue", return_value=84),
    )


async def run_with_mocks(
    mocks: list, gate_result: dict | list[dict] | None
) -> tuple[list[dict], MagicMock, list[MagicMock]]:
    with ExitStack() as stack:
        installed_mocks = [stack.enter_context(mock) for mock in mocks]
        gate_patch = (
            patch("app.pipeline.evaluate_gate", side_effect=gate_result)
            if isinstance(gate_result, list)
            else patch("app.pipeline.evaluate_gate", return_value=gate_result)
        )
        evaluate_gate = stack.enter_context(gate_patch)
        results = await pipeline.run_pipeline("acme/project", 1)
    return results, evaluate_gate, installed_mocks


@pytest.mark.asyncio
async def test_run_pipeline_auto_merges(
    github_client: MagicMock, vulnerability: dict[str, object], proposal: dict[str, str]
) -> None:
    results, _, installed_mocks = await run_with_mocks(
        list(pipeline_mocks(github_client, vulnerability, proposal)),
        {"decision": "auto", "reason": "safe"},
    )

    assert results == [{"cve_id": "CVE-2024-1234", "package": "requests", "decision": "auto", "reason": "safe", "pr_number": 42, "issue_number": None, "duplicate_of": None}]
    assert github_client.get_repo.return_value.get_contents.call_args_list == [
        call("package.json"),
        call("requirements.txt"),
        call("pyproject.toml"),
    ]
    installed_mocks[8].assert_called_once()


@pytest.mark.asyncio
async def test_run_pipeline_ask_opens_but_does_not_merge(
    github_client: MagicMock, vulnerability: dict[str, object], proposal: dict[str, str]
) -> None:
    results, _, installed_mocks = await run_with_mocks(
        list(pipeline_mocks(github_client, vulnerability, proposal)),
        {"decision": "ask", "reason": "review"},
    )

    assert results[0]["decision"] == "ask"
    assert results[0]["pr_number"] == 42
    installed_mocks[8].assert_not_called()


@pytest.mark.asyncio
async def test_run_pipeline_block_opens_issue(
    github_client: MagicMock, vulnerability: dict[str, object], proposal: dict[str, str]
) -> None:
    results, _, installed_mocks = await run_with_mocks(
        list(pipeline_mocks(github_client, vulnerability, proposal)),
        {"decision": "block", "reason": "major bump"},
    )

    assert results[0]["decision"] == "block"
    assert results[0]["issue_number"] == 84
    installed_mocks[9].assert_called_once()


@pytest.mark.asyncio
async def test_run_pipeline_blocks_when_model_has_no_confident_fix(
    github_client: MagicMock, vulnerability: dict[str, object], proposal: dict[str, str]
) -> None:
    mocks = list(pipeline_mocks(github_client, vulnerability, proposal))
    mocks[5] = patch("app.pipeline.propose_fix", new=AsyncMock(return_value=None))
    results, evaluate_gate, _ = await run_with_mocks(mocks, None)

    assert results[0]["decision"] == "block"
    assert results[0]["reason"] == "no confident fix available"
    assert results[0]["issue_number"] == 84
    evaluate_gate.assert_not_called()


@pytest.mark.asyncio
async def test_run_pipeline_continues_after_one_finding_fails(
    github_client: MagicMock, vulnerability: dict[str, object], proposal: dict[str, str]
) -> None:
    second_vulnerability = {**vulnerability, "cve_id": "CVE-2024-5678", "package": "urllib3"}
    mocks = list(pipeline_mocks(github_client, vulnerability, proposal))
    mocks[2] = patch(
        "app.pipeline.fetch_osv_vulnerabilities",
        new=AsyncMock(return_value=[vulnerability, second_vulnerability]),
    )
    mocks[7] = patch("app.pipeline.open_pr", side_effect=[RuntimeError("GitHub unavailable"), 43])
    results, _, installed_mocks = await run_with_mocks(
        mocks, {"decision": "auto", "reason": "safe"}
    )

    assert results[0]["decision"] == "error"
    assert results[0]["error"] == "GitHub unavailable"
    assert results[1]["decision"] == "auto"
    assert results[1]["pr_number"] == 43
    installed_mocks[8].assert_called_once()


@pytest.mark.asyncio
async def test_run_pipeline_skips_existing_bastion_item(
    github_client: MagicMock, vulnerability: dict[str, object], proposal: dict[str, str]
) -> None:
    mocks = list(pipeline_mocks(github_client, vulnerability, proposal))
    mocks[1] = patch("app.pipeline.find_existing_bastion_item", return_value=77)

    results, evaluate_gate, installed_mocks = await run_with_mocks(
        mocks, {"decision": "auto", "reason": "safe"}
    )

    assert results == [{"cve_id": "CVE-2024-1234", "package": "requests", "decision": "duplicate", "reason": "already tracked by Bastion", "pr_number": None, "issue_number": None, "duplicate_of": 77}]
    evaluate_gate.assert_not_called()
    installed_mocks[5].assert_not_awaited()
    installed_mocks[7].assert_not_called()
    installed_mocks[9].assert_not_called()


@pytest.mark.asyncio
async def test_run_pipeline_consolidates_auto_findings_for_one_package(
    github_client: MagicMock, vulnerability: dict[str, object], proposal: dict[str, str]
) -> None:
    higher_vulnerability = {**vulnerability, "cve_id": "CVE-2024-5678", "fixed_version": "2.33.0"}
    higher_proposal = {
        **proposal,
        "target_version": "2.33.0",
        "diff": proposal["diff"].replace("2.32.0", "2.33.0"),
        "rationale": "Bumps requests to a higher published security fix.",
    }
    mocks = list(pipeline_mocks(github_client, vulnerability, proposal))
    mocks[2] = patch(
        "app.pipeline.fetch_osv_vulnerabilities",
        new=AsyncMock(return_value=[vulnerability, higher_vulnerability]),
    )
    mocks[5] = patch(
        "app.pipeline.propose_fix",
        new=AsyncMock(side_effect=[proposal, higher_proposal]),
    )
    results, _, installed_mocks = await run_with_mocks(
        mocks,
        [{"decision": "auto", "reason": "safe"}, {"decision": "auto", "reason": "safe"}],
    )

    assert installed_mocks[7].call_count == 1
    assert installed_mocks[7].call_args.args[5] == "2.33.0"
    assert "CVE-2024-1234" in installed_mocks[7].call_args.args[7]
    assert "CVE-2024-5678" in installed_mocks[7].call_args.args[7]
    assert [result["pr_number"] for result in results] == [42, 42]
    assert results[0]["consolidated_with"] == ["CVE-2024-5678"]
    assert results[1]["consolidated_with"] == ["CVE-2024-1234"]
    installed_mocks[8].assert_called_once()


@pytest.mark.asyncio
async def test_run_pipeline_consolidates_auto_and_ask_as_ask(
    github_client: MagicMock, vulnerability: dict[str, object], proposal: dict[str, str]
) -> None:
    second_vulnerability = {**vulnerability, "cve_id": "CVE-2024-5678"}
    mocks = list(pipeline_mocks(github_client, vulnerability, proposal))
    mocks[2] = patch(
        "app.pipeline.fetch_osv_vulnerabilities",
        new=AsyncMock(return_value=[vulnerability, second_vulnerability]),
    )
    mocks[5] = patch("app.pipeline.propose_fix", new=AsyncMock(side_effect=[proposal, proposal]))
    results, _, installed_mocks = await run_with_mocks(
        mocks,
        [{"decision": "auto", "reason": "safe"}, {"decision": "ask", "reason": "review"}],
    )

    assert [result["decision"] for result in results] == ["ask", "ask"]
    installed_mocks[7].assert_called_once()
    installed_mocks[8].assert_not_called()
    installed_mocks[6].assert_awaited_once()


@pytest.mark.asyncio
async def test_run_pipeline_keeps_block_finding_separate_from_consolidated_pr(
    github_client: MagicMock, vulnerability: dict[str, object], proposal: dict[str, str]
) -> None:
    block_vulnerability = {**vulnerability, "cve_id": "CVE-2024-5678"}
    mocks = list(pipeline_mocks(github_client, vulnerability, proposal))
    mocks[2] = patch(
        "app.pipeline.fetch_osv_vulnerabilities",
        new=AsyncMock(return_value=[vulnerability, block_vulnerability]),
    )
    mocks[5] = patch("app.pipeline.propose_fix", new=AsyncMock(side_effect=[proposal, proposal]))
    results, _, installed_mocks = await run_with_mocks(
        mocks,
        [{"decision": "auto", "reason": "safe"}, {"decision": "block", "reason": "major bump"}],
    )

    assert results[0]["pr_number"] == 42
    assert results[1]["decision"] == "block"
    assert results[1]["issue_number"] == 84
    installed_mocks[7].assert_called_once()
    installed_mocks[9].assert_called_once()


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
