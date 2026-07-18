"""GitHub App webhook entrypoint."""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request

from app.pipeline import run_pipeline

app = FastAPI()
logger = logging.getLogger(__name__)


def _signature_is_valid(body: bytes, signature: str | None) -> bool:
    """Return whether a GitHub SHA-256 webhook signature matches the body."""
    secret = os.getenv("GITHUB_WEBHOOK_SECRET")
    if not secret or not signature or not signature.startswith("sha256="):
        return False
    expected = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature.removeprefix("sha256="), expected)


@app.post("/webhook")
async def handle_webhook(request: Request, background_tasks: BackgroundTasks) -> dict[str, str]:
    """Verify and acknowledge GitHub webhooks, scheduling push scans asynchronously."""
    body = await request.body()
    signature = request.headers.get("X-Hub-Signature-256")
    if not _signature_is_valid(body, signature):
        logger.warning("Rejected GitHub webhook with invalid or missing signature")
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        logger.warning("Rejected GitHub webhook with malformed JSON payload")
        raise HTTPException(status_code=400, detail="Malformed JSON payload") from None

    event = request.headers.get("X-GitHub-Event")
    if event == "installation" and payload.get("action") == "created":
        installation_id = payload.get("installation", {}).get("id")
        logger.info("Received installation-created event for installation %s", installation_id)
        return {"status": "accepted"}

    if event == "push":
        repository = payload.get("repository")
        installation = payload.get("installation")
        if not isinstance(repository, dict) or not isinstance(installation, dict):
            logger.warning("Ignoring push webhook missing repository or installation")
            return {"status": "accepted"}
        repo_full_name = repository.get("full_name")
        installation_id = installation.get("id")
        if not isinstance(repo_full_name, str) or not isinstance(installation_id, int):
            logger.warning("Ignoring push webhook with invalid repository or installation")
            return {"status": "accepted"}
        background_tasks.add_task(run_pipeline, repo_full_name, installation_id)
        return {"status": "accepted"}

    logger.info("Ignoring unsupported GitHub webhook event: %s", event)
    return {"status": "accepted"}


@app.get("/health")
async def health() -> dict[str, str]:
    """Return the service health status for the deployment platform."""
    return {"status": "ok"}
