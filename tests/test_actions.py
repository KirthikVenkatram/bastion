"""Tests for GitHub App remediation actions."""
from unittest.mock import MagicMock

import pytest
from github import GithubException

from app.github_app.actions import (
    DISCLOSURE_FOOTER,
    find_existing_bastion_item,
    merge_pr,
    open_issue,
    open_pr,
)


@pytest.fixture
def client_and_repo() -> tuple[MagicMock, MagicMock]:
    client = MagicMock()
    repo = client.get_repo.return_value
    repo.default_branch = "main"
    repo.get_branch.return_value.commit.sha = "base-sha"
    manifest = repo.get_contents.return_value
    manifest.decoded_content = b"requests==2.31.0\n"
    manifest.sha = "manifest-sha"
    return client, repo


@pytest.fixture
def requirements_diff() -> str:
    return (
        "--- a/requirements.txt\n"
        "+++ b/requirements.txt\n"
        "@@ -1 +1 @@\n"
        "-requests==2.31.0\n"
        "+requests==2.32.0\n"
    )


def test_open_pr_creates_branch_updates_manifest_and_opens_pr(
    client_and_repo: tuple[MagicMock, MagicMock], requirements_diff: str
) -> None:
    client, repo = client_and_repo
    repo.create_pull.return_value.number = 42

    pr_number = open_pr(
        client,
        "acme/project",
        "CVE-2024-1234",
        "requests",
        "2.31.0",
        "2.32.0",
        requirements_diff,
        "Bumps requests to its fixed version.",
    )

    assert pr_number == 42
    repo.create_git_ref.assert_called_once_with(
        ref="refs/heads/bastion/requests-2.32.0-cve20241234", sha="base-sha"
    )
    repo.update_file.assert_called_once_with(
        "requirements.txt",
        "Bastion: bump requests to 2.32.0",
        "requests==2.32.0\n",
        sha="manifest-sha",
        branch="bastion/requests-2.32.0-cve20241234",
    )


def test_open_pr_uses_distinct_branches_for_distinct_cves(
    client_and_repo: tuple[MagicMock, MagicMock], requirements_diff: str
) -> None:
    client, repo = client_and_repo
    repo.create_pull.return_value.number = 42

    open_pr(
        client,
        "acme/project",
        "CVE-2024-1234",
        "requests",
        "2.31.0",
        "2.32.0",
        requirements_diff,
        "Bumps requests to its fixed version.",
    )
    open_pr(
        client,
        "acme/project",
        "CVE-2024-5678",
        "requests",
        "2.31.0",
        "2.32.0",
        requirements_diff,
        "Bumps requests to its fixed version.",
    )

    assert repo.create_git_ref.call_args_list[0].kwargs["ref"] != (
        repo.create_git_ref.call_args_list[1].kwargs["ref"]
    )


def test_open_pr_reuses_existing_branch_when_ref_already_exists(
    client_and_repo: tuple[MagicMock, MagicMock], requirements_diff: str
) -> None:
    client, repo = client_and_repo
    repo.create_pull.return_value.number = 42
    repo.create_git_ref.side_effect = GithubException(
        422, {"message": "Reference already exists"}, {}
    )
    base_branch = MagicMock()
    base_branch.commit.sha = "base-sha"
    existing_branch = MagicMock()
    existing_branch.commit.sha = "existing-sha"
    repo.get_branch.side_effect = lambda name: (
        base_branch if name == "main" else existing_branch
    )

    pr_number = open_pr(
        client,
        "acme/project",
        "CVE-2024-1234",
        "requests",
        "2.31.0",
        "2.32.0",
        requirements_diff,
        "Bumps requests to its fixed version.",
    )

    assert pr_number == 42
    repo.get_branch.assert_any_call("bastion/requests-2.32.0-cve20241234")
    assert repo.update_file.call_args.kwargs["branch"] == (
        "bastion/requests-2.32.0-cve20241234"
    )
    assert repo.create_pull.call_args.kwargs["body"] == (
        "Bumps requests to its fixed version."
        + DISCLOSURE_FOOTER
        + "\n\n<!-- bastion-tracking: CVE-2024-1234:requests -->"
    )


def test_merge_pr_uses_squash_merge(client_and_repo: tuple[MagicMock, MagicMock]) -> None:
    client, repo = client_and_repo
    repo.get_pull.return_value.merge.return_value.merged = True

    merge_pr(client, "acme/project", 42)

    repo.get_pull.return_value.merge.assert_called_once_with(merge_method="squash")


def test_merge_pr_logs_rejected_merge(client_and_repo: tuple[MagicMock, MagicMock]) -> None:
    client, repo = client_and_repo
    repo.get_pull.return_value.merge.return_value.merged = False
    repo.get_pull.return_value.merge.return_value.message = "Required checks are pending"

    merge_pr(client, "acme/project", 42)

    repo.get_pull.return_value.merge.assert_called_once_with(merge_method="squash")


def test_open_issue_creates_blocking_issue(client_and_repo: tuple[MagicMock, MagicMock]) -> None:
    client, repo = client_and_repo
    repo.create_issue.return_value.number = 84

    issue_number = open_issue(
        client,
        "acme/project",
        "CVE-2024-1234",
        "requests",
        "No fixed version is available.",
    )

    assert issue_number == 84
    repo.create_issue.assert_called_once_with(
        title="Bastion: CVE-2024-1234 in requests — not auto-remediated",
        body=(
            "No fixed version is available."
            "\n\n<!-- bastion-tracking: CVE-2024-1234:requests -->"
        ),
    )


def test_find_existing_bastion_item_matches_open_issue(
    client_and_repo: tuple[MagicMock, MagicMock],
) -> None:
    client, repo = client_and_repo
    issue = MagicMock()
    issue.number = 84
    issue.body = "Details\n\n<!-- bastion-tracking: CVE-2024-1234:requests -->"
    repo.get_issues.return_value = [issue]
    repo.get_pulls.return_value = []

    existing_number = find_existing_bastion_item(
        client, "acme/project", "CVE-2024-1234", "requests"
    )

    assert existing_number == 84
    repo.get_pulls.assert_not_called()


def test_find_existing_bastion_item_matches_open_pull_request(
    client_and_repo: tuple[MagicMock, MagicMock],
) -> None:
    client, repo = client_and_repo
    pull_request = MagicMock()
    pull_request.number = 42
    pull_request.body = "<!-- bastion-tracking: CVE-2024-1234:requests -->"
    repo.get_issues.return_value = []
    repo.get_pulls.return_value = [pull_request]

    existing_number = find_existing_bastion_item(
        client, "acme/project", "CVE-2024-1234", "requests"
    )

    assert existing_number == 42
