"""Tests for GPT dependency-fix proposals."""
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.propose.gpt_fix import MODEL, propose_fix


@pytest.fixture
def finding() -> dict:
    return {
        "cve_id": "CVE-2024-1234",
        "package": "requests",
        "current_version": "2.31.0",
        "fixed_version": "2.32.0",
        "summary": "A vulnerability in requests.",
        "severity": "high",
        "epss_score": 0.7,
        "in_kev": True,
        "ecosystem": "PyPI",
    }


@pytest.fixture
def patch_proposal() -> dict[str, str]:
    return {
        "package": "requests",
        "current_version": "2.31.0",
        "target_version": "2.32.0",
        "diff": (
            "--- a/requirements.txt\n"
            "+++ b/requirements.txt\n"
            "@@ -1 +1 @@\n"
            "-requests==2.31.0\n"
            "+requests==2.32.0\n"
        ),
        "rationale": "Bumps requests to the published security fix.",
        "confidence": "high",
    }


def mock_openai_client(content: str | Exception) -> MagicMock:
    client = MagicMock()
    client.chat.completions.create = AsyncMock()
    if isinstance(content, Exception):
        client.chat.completions.create.side_effect = content
    else:
        completion = MagicMock()
        completion.choices[0].message.content = content
        client.chat.completions.create.return_value = completion
    return client


@pytest.mark.asyncio
async def test_propose_fix_returns_clean_patch_version_fix(
    finding: dict, patch_proposal: dict[str, str]
) -> None:
    client = mock_openai_client(json.dumps(patch_proposal))

    with patch("app.propose.gpt_fix.AsyncOpenAI", return_value=client):
        proposal = await propose_fix(finding)

    assert proposal == patch_proposal
    client.chat.completions.create.assert_awaited_once()
    assert client.chat.completions.create.await_args.kwargs["model"] == MODEL


@pytest.mark.asyncio
async def test_propose_fix_rejects_low_confidence_response(
    finding: dict, patch_proposal: dict[str, str]
) -> None:
    patch_proposal["confidence"] = "low"
    client = mock_openai_client(json.dumps(patch_proposal))

    with patch("app.propose.gpt_fix.AsyncOpenAI", return_value=client):
        proposal = await propose_fix(finding)

    assert proposal is None


@pytest.mark.asyncio
async def test_propose_fix_returns_none_when_openai_call_fails(finding: dict) -> None:
    client = mock_openai_client(RuntimeError("OpenAI API unavailable"))

    with patch("app.propose.gpt_fix.AsyncOpenAI", return_value=client):
        proposal = await propose_fix(finding)

    assert proposal is None
