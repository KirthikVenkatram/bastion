"""Tests for GPT dependency-fix proposals."""
import json
from unittest.mock import MagicMock, patch

import pytest

from app.propose.gpt_fix import GROQ_BASE_URL, MODEL, propose_fix


@pytest.fixture(autouse=True)
def groq_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GROQ_API_KEY", "groq-api-key")


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


def mock_groq_client(content: str | Exception) -> MagicMock:
    client = MagicMock()
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
    client = mock_groq_client(json.dumps(patch_proposal))

    with patch("app.propose.gpt_fix.openai.OpenAI", return_value=client) as openai_client:
        proposal = await propose_fix(finding)

    assert proposal == patch_proposal
    openai_client.assert_called_once_with(
        api_key="groq-api-key", base_url=GROQ_BASE_URL
    )
    client.chat.completions.create.assert_called_once()
    assert client.chat.completions.create.call_args.kwargs["model"] == MODEL


@pytest.mark.asyncio
async def test_propose_fix_rejects_low_confidence_response(
    finding: dict, patch_proposal: dict[str, str]
) -> None:
    patch_proposal["confidence"] = "low"
    client = mock_groq_client(json.dumps(patch_proposal))

    with patch("app.propose.gpt_fix.openai.OpenAI", return_value=client):
        proposal = await propose_fix(finding)

    assert proposal is None


@pytest.mark.asyncio
async def test_propose_fix_returns_none_when_openai_call_fails(finding: dict) -> None:
    client = mock_groq_client(RuntimeError("Groq API unavailable"))

    with patch("app.propose.gpt_fix.openai.OpenAI", return_value=client):
        proposal = await propose_fix(finding)

    assert proposal is None


@pytest.mark.asyncio
async def test_propose_fix_retries_without_structured_output_when_unsupported(
    finding: dict, patch_proposal: dict[str, str]
) -> None:
    client = mock_groq_client(json.dumps(patch_proposal))
    client.chat.completions.create.side_effect = [
        RuntimeError("response_format is not supported"),
        client.chat.completions.create.return_value,
    ]

    with patch("app.propose.gpt_fix.openai.OpenAI", return_value=client):
        proposal = await propose_fix(finding)

    assert proposal == patch_proposal
    assert client.chat.completions.create.call_count == 2
    first_call, fallback_call = client.chat.completions.create.call_args_list
    assert first_call.kwargs["response_format"]
    assert "response_format" not in fallback_call.kwargs
