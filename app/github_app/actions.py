"""GitHub App authentication and remediation actions."""
from __future__ import annotations

import logging
import os
from pathlib import Path, PurePosixPath
from typing import NoReturn

from github import Github, GithubException, GithubIntegration

logger = logging.getLogger(__name__)

MANIFEST_FILENAMES = {"package.json", "requirements.txt", "pyproject.toml"}
DISCLOSURE_FOOTER = "\n\n---\nThis PR was opened automatically by Bastion."


class BastionActionError(Exception):
    """Raised when a GitHub action cannot be completed."""


def _raise_action_error(action: str, error: Exception) -> NoReturn:
    logger.error("GitHub %s failed: %s", action, error)
    raise BastionActionError(f"GitHub {action} failed") from error


def _tracking_marker(cve_id: str, package: str) -> str:
    return f"<!-- bastion-tracking: {cve_id}:{package} -->"


def find_existing_bastion_item(
    client: Github, repo_full_name: str, cve_id: str | None, package: str
) -> int | None:
    """Return the number of an open issue or PR already tracking a finding or package."""
    marker = _tracking_marker(cve_id, package) if cve_id is not None else f":{package} -->"
    try:
        repository = client.get_repo(repo_full_name)
        for item in repository.get_issues(state="open"):
            if marker in (item.body or ""):
                return item.number
        for pull_request in repository.get_pulls(state="open"):
            if marker in (pull_request.body or ""):
                return pull_request.number
    except GithubException as error:
        _raise_action_error("duplicate tracking lookup", error)
    return None


def get_installation_client(installation_id: int) -> Github:
    """Return a PyGithub client authenticated for one App installation."""
    try:
        app_id = os.environ["GITHUB_APP_ID"]
        private_key_path = os.environ["GITHUB_APP_PRIVATE_KEY_PATH"]
        private_key = Path(private_key_path).read_text()
        integration = GithubIntegration(app_id, private_key)
        access_token = integration.get_access_token(installation_id)
        return Github(login_or_token=access_token.token)
    except (GithubException, KeyError, OSError, ValueError) as error:
        _raise_action_error("installation authentication", error)


def _manifest_path(diff: str) -> str:
    lines = diff.splitlines()
    if len(lines) < 2 or not lines[0].startswith("--- ") or not lines[1].startswith("+++ "):
        raise ValueError("Diff does not have standard unified-diff file headers")

    old_path = lines[0][4:].removeprefix("a/")
    new_path = lines[1][4:].removeprefix("b/")
    if old_path != new_path or PurePosixPath(old_path).name not in MANIFEST_FILENAMES:
        raise ValueError("Diff does not target a supported manifest file")
    return old_path


def _changed_lines(diff: str) -> tuple[str, str]:
    removed = [line[1:] for line in diff.splitlines() if line.startswith("-") and not line.startswith("---")]
    added = [line[1:] for line in diff.splitlines() if line.startswith("+") and not line.startswith("+++")]
    if len(removed) != 1 or len(added) != 1:
        raise ValueError("Diff must change exactly one manifest line")
    return removed[0], added[0]


def _apply_diff(current_content: str, diff: str) -> str:
    old_line, new_line = _changed_lines(diff)
    lines = current_content.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if line.rstrip("\r\n") != old_line:
            continue
        line_ending = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else ""
        lines[index] = f"{new_line}{line_ending}"
        return "".join(lines)
    raise ValueError("Current manifest content no longer contains the diff's old line")


def _get_current_manifest(repo: object, path: str, branch: str) -> tuple[str, object]:
    try:
        return path, repo.get_contents(path, ref=branch)
    except GithubException:
        branch_ref = repo.get_branch(branch)
        tree = repo.get_git_tree(branch_ref.commit.sha, recursive=True)
        matching_paths = [
            entry.path
            for entry in tree.tree
            if entry.type == "blob" and PurePosixPath(entry.path).name == PurePosixPath(path).name
        ]
        if len(matching_paths) != 1:
            raise ValueError(f"Could not locate a current manifest for {path}")
        return matching_paths[0], repo.get_contents(matching_paths[0], ref=branch)


def _branch_name(package: str, target_version: str, cve_id: str) -> str:
    cve_suffix = cve_id.lower().replace("-", "")
    return f"bastion/{package}-{target_version}-{cve_suffix}"


def _is_existing_reference_error(error: GithubException) -> bool:
    return error.status == 422 and "reference already exists" in str(error).lower()


def _is_existing_pull_request_error(error: GithubException) -> bool:
    return error.status == 422 and "pull request already exists" in str(error).lower()


def _find_open_pull_request_for_branch(repo: object, branch_name: str) -> int | None:
    for pull_request in repo.get_pulls(state="open"):
        if pull_request.head.ref == branch_name:
            return pull_request.number
    return None


def open_pr(
    client: Github,
    repo_full_name: str,
    cve_id: str,
    package: str,
    current_version: str,
    target_version: str,
    diff: str,
    rationale: str,
) -> int:
    """Apply a one-dependency manifest diff on a new branch and open a PR."""
    try:
        repo = client.get_repo(repo_full_name)
        default_branch = repo.default_branch
        branch_name = _branch_name(package, target_version, cve_id)
        base_branch = repo.get_branch(default_branch)
        reused_branch = False
        try:
            repo.create_git_ref(ref=f"refs/heads/{branch_name}", sha=base_branch.commit.sha)
        except GithubException as error:
            if not _is_existing_reference_error(error):
                raise
            reused_branch = True
            existing_branch = repo.get_branch(branch_name)
            logger.warning(
                "Reusing existing Bastion branch %s at %s",
                branch_name,
                existing_branch.commit.sha,
            )

        manifest_path = _manifest_path(diff)
        manifest_path, manifest = _get_current_manifest(repo, manifest_path, branch_name)
        manifest_content = manifest.decoded_content.decode("utf-8")
        if reused_branch and target_version in manifest_content:
            logger.warning(
                "Reused Bastion branch %s already contains version %s",
                branch_name,
                target_version,
            )
        else:
            updated_content = _apply_diff(manifest_content, diff)
            repo.update_file(
                manifest_path,
                f"Bastion: bump {package} to {target_version}",
                updated_content,
                sha=manifest.sha,
                branch=branch_name,
            )
        title = f"Bastion: bump {package} {current_version} -> {target_version}"
        try:
            pull_request = repo.create_pull(
                title=title,
                body=f"{rationale}{DISCLOSURE_FOOTER}\n\n{_tracking_marker(cve_id, package)}",
                head=branch_name,
                base=default_branch,
            )
            return pull_request.number
        except GithubException as error:
            if not _is_existing_pull_request_error(error):
                raise
            existing_pull_request = _find_open_pull_request_for_branch(repo, branch_name)
            if existing_pull_request is None:
                raise
            logger.warning(
                "Reusing existing pull request #%s for branch %s",
                existing_pull_request,
                branch_name,
            )
            return existing_pull_request
    except (GithubException, UnicodeDecodeError, ValueError) as error:
        _raise_action_error("pull request creation", error)


def _is_branch_protection_rejection(error: GithubException) -> bool:
    return error.status in {405, 409, 422}


def merge_pr(client: Github, repo_full_name: str, pr_number: int) -> None:
    """Attempt a squash merge, leaving protected or failing PRs unmerged."""
    try:
        pull_request = client.get_repo(repo_full_name).get_pull(pr_number)
        result = pull_request.merge(merge_method="squash")
    except GithubException as error:
        if _is_branch_protection_rejection(error):
            logger.warning("GitHub rejected merge of PR #%s: %s", pr_number, error)
            return
        _raise_action_error("pull request merge", error)

    if not result.merged:
        logger.warning("GitHub did not merge PR #%s: %s", pr_number, result.message)


def open_issue(
    client: Github, repo_full_name: str, cve_id: str, package: str, reason: str
) -> int:
    """Open an issue for a vulnerability that Bastion cannot remediate."""
    try:
        issue = client.get_repo(repo_full_name).create_issue(
            title=f"Bastion: {cve_id} in {package} — not auto-remediated",
            body=f"{reason}\n\n{_tracking_marker(cve_id, package)}",
        )
        return issue.number
    except GithubException as error:
        _raise_action_error("issue creation", error)
