"""Dependency manifest parsing for repository roots."""
from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path
from typing import Any

Dependency = dict[str, str]

_REQUIREMENT_PATTERN = re.compile(
    r"^\s*([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*==\s*([^\s;#]+)"
)


def scan_manifests(repo_root: str | Path) -> list[Dependency]:
    """Parse supported dependency manifests in a repo root."""
    root = Path(repo_root)
    dependencies: list[Dependency] = []
    dependencies.extend(_parse_package_json(_read_text(root / "package.json")))
    dependencies.extend(_parse_requirements_txt(_read_text(root / "requirements.txt")))
    dependencies.extend(_parse_pyproject_toml(_read_text(root / "pyproject.toml")))
    return dependencies


def _parse_package_json(content: str) -> list[Dependency]:
    data = _read_json(content)
    if not isinstance(data, dict):
        return []

    dependencies: list[Dependency] = []
    for section in ("dependencies", "devDependencies"):
        entries = data.get(section)
        if not isinstance(entries, dict):
            continue
        for package, version in entries.items():
            if isinstance(package, str) and isinstance(version, str):
                dependencies.append(
                    {"package": package, "current_version": _normalize_npm_version(version)}
                )
    return dependencies


def _parse_requirements_txt(content: str) -> list[Dependency]:
    dependencies: list[Dependency] = []
    for line in content.splitlines():
        match = _REQUIREMENT_PATTERN.match(line)
        if match is None:
            continue
        dependencies.append(
            {"package": match.group(1), "current_version": match.group(2)}
        )
    return dependencies


def _parse_pyproject_toml(content: str) -> list[Dependency]:
    data = _read_toml(content)
    if not isinstance(data, dict):
        return []

    project = data.get("project")
    if not isinstance(project, dict):
        return []

    dependencies: list[Dependency] = []
    for requirement in project.get("dependencies", []):
        parsed = _parse_pep508_pin(requirement)
        if parsed is not None:
            dependencies.append(parsed)

    optional_dependencies = project.get("optional-dependencies", {})
    if isinstance(optional_dependencies, dict):
        for group in optional_dependencies.values():
            if not isinstance(group, list):
                continue
            for requirement in group:
                parsed = _parse_pep508_pin(requirement)
                if parsed is not None:
                    dependencies.append(parsed)

    return dependencies


def _parse_pep508_pin(requirement: Any) -> Dependency | None:
    if not isinstance(requirement, str):
        return None
    match = _REQUIREMENT_PATTERN.match(requirement)
    if match is None:
        return None
    return {"package": match.group(1), "current_version": match.group(2)}


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def _read_json(content: str) -> Any | None:
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        return None


def _read_toml(content: str) -> dict[str, Any] | None:
    try:
        return tomllib.loads(content)
    except tomllib.TOMLDecodeError:
        return None


def _normalize_npm_version(version: str) -> str:
    return version.strip().lstrip("^~=")
