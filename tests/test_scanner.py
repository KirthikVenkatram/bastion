from __future__ import annotations

from pathlib import Path

from app.scanner.manifest import scan_manifests

FIXTURES = Path(__file__).parent / "fixtures"


def test_scans_package_json_dependencies() -> None:
    assert scan_manifests(FIXTURES / "package_repo") == [
        {"package": "react", "current_version": "18.2.0"},
        {"package": "vite", "current_version": "5.0.0"},
        {"package": "typescript", "current_version": "5.4.5"},
    ]


def test_scans_requirements_txt_pinned_dependencies() -> None:
    assert scan_manifests(FIXTURES / "requirements_repo") == [
        {"package": "fastapi", "current_version": "0.115.0"},
        {"package": "uvicorn", "current_version": "0.32.0"},
    ]


def test_scans_pyproject_toml_pinned_dependencies() -> None:
    assert scan_manifests(FIXTURES / "pyproject_repo") == [
        {"package": "httpx", "current_version": "0.27.2"},
        {"package": "pytest-asyncio", "current_version": "0.24.0"},
    ]


def test_missing_and_malformed_manifests_return_empty_list() -> None:
    assert scan_manifests(FIXTURES / "malformed_repo") == []
    assert scan_manifests(FIXTURES / "missing_repo") == []
