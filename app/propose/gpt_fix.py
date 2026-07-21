"""Generate tightly scoped dependency-fix proposals with a hosted GPT model."""
from __future__ import annotations

import json
import logging
import os
from typing import Any

import openai

MODEL = "openai/gpt-oss-120b"
GROQ_BASE_URL = "https://api.groq.com/openai/v1"
MANIFEST_FILENAMES = {"package.json", "requirements.txt", "pyproject.toml"}

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You propose dependency-security patches for a GitHub App.
Only change the one affected dependency supplied by the user. Do not suggest
refactors, source-code changes, lockfile edits, or any other dependency changes.
Produce a minimal standard unified diff that changes exactly one dependency line
in one manifest file: package.json, requirements.txt, or pyproject.toml. The
removed line must contain the current version and the added line the target
version. Write a one- or two-sentence rationale suitable for a PR description.
Return only the requested JSON object. If there is no safe target version, set
confidence to low and leave target_version and diff empty.
"""

PROPOSAL_SCHEMA: dict[str, Any] = {
    "type": "json_schema",
    "json_schema": {
        "name": "dependency_patch_proposal",
        "strict": True,
        "schema": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "package",
                "current_version",
                "target_version",
                "diff",
                "rationale",
                "confidence",
            ],
            "properties": {
                "package": {"type": "string"},
                "current_version": {"type": "string"},
                "target_version": {"type": "string"},
                "diff": {"type": "string"},
                "rationale": {"type": "string"},
                "confidence": {"enum": ["high", "medium", "low"]},
            },
        },
    },
}


def _is_single_manifest_line_diff(
    diff: str, package: str, current_version: str, target_version: str
) -> bool:
    lines = diff.splitlines()
    if len(lines) < 5 or not lines[0].startswith("--- ") or not lines[1].startswith("+++ "):
        return False

    old_path = lines[0][4:].removeprefix("a/")
    new_path = lines[1][4:].removeprefix("b/")
    if old_path != new_path or old_path not in MANIFEST_FILENAMES:
        return False

    removed_lines = [line for line in lines if line.startswith("-") and not line.startswith("---")]
    added_lines = [line for line in lines if line.startswith("+") and not line.startswith("+++")]
    return (
        len(removed_lines) == 1
        and len(added_lines) == 1
        and package in removed_lines[0]
        and package in added_lines[0]
        and current_version in removed_lines[0]
        and target_version in added_lines[0]
    )


def _validated_proposal(
    proposal: dict[str, Any], finding: dict[str, Any]
) -> dict[str, str] | None:
    required_fields = {
        "package",
        "current_version",
        "target_version",
        "diff",
        "rationale",
        "confidence",
    }
    if set(proposal) != required_fields:
        return None

    package = proposal["package"]
    current_version = proposal["current_version"]
    target_version = proposal["target_version"]
    diff = proposal["diff"]
    rationale = proposal["rationale"]
    confidence = proposal["confidence"]
    if (
        not all(isinstance(value, str) for value in proposal.values())
        or package != finding["package"]
        or current_version != finding["current_version"]
        or confidence not in {"high", "medium"}
        or not target_version
        or not rationale
        or not _is_single_manifest_line_diff(diff, package, current_version, target_version)
    ):
        return None

    return {
        "package": package,
        "current_version": current_version,
        "target_version": target_version,
        "diff": diff,
        "rationale": rationale,
        "confidence": confidence,
    }


async def propose_fix(finding: dict[str, Any]) -> dict[str, str] | None:
    """Return a validated manifest-only patch proposal, or ``None`` if unsafe."""
    try:
        client = openai.OpenAI(
            api_key=os.environ["GROQ_API_KEY"], base_url=GROQ_BASE_URL
        )
        request = {
            "model": MODEL,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(finding)},
            ],
            "timeout": 30.0,
        }
        try:
            completion = client.chat.completions.create(
                **request, response_format=PROPOSAL_SCHEMA
            )
        except Exception as error:
            if "response_format" not in str(error).lower():
                raise
            completion = client.chat.completions.create(**request)
        content = completion.choices[0].message.content
        if content is None:
            raise ValueError("Model returned an empty patch proposal")
        proposal = json.loads(content)
    except Exception as error:
        logger.warning("Unable to generate dependency fix proposal: %s", error)
        return None

    if not isinstance(proposal, dict):
        logger.warning("Model returned a non-object dependency fix proposal")
        return None

    validated = _validated_proposal(proposal, finding)
    if validated is None:
        logger.warning("Model returned an unsafe or malformed dependency fix proposal")
    return validated
