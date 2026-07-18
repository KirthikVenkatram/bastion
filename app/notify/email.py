"""Email notifications for findings requiring human approval."""
from __future__ import annotations

import asyncio
import logging
import os

import resend

logger = logging.getLogger(__name__)


def _email_body(
    cve_id: str,
    package: str,
    current_version: str,
    target_version: str,
    epss_score: float,
    in_kev: bool,
    pr_url: str,
    rationale: str,
) -> str:
    kev_status = (
        "actively exploited (listed in CISA's known-exploited catalog)"
        if in_kev
        else "not currently in CISA's known-exploited catalog"
    )
    return (
        f"Bastion opened a security-fix PR that needs your approval.\n\n"
        f"CVE: {cve_id}\n"
        f"Package: {package}\n"
        f"Version bump: {current_version} -> {target_version}\n"
        f"EPSS exploit probability: {epss_score:.2%}\n"
        f"CISA KEV status: {kev_status}\n\n"
        f"Rationale: {rationale}\n\n"
        f"Review the pull request: {pr_url}\n"
    )


async def send_ask_notification(
    to_email: str,
    cve_id: str,
    package: str,
    current_version: str,
    target_version: str,
    epss_score: float,
    in_kev: bool,
    pr_url: str,
    rationale: str,
) -> bool:
    """Send a best-effort notification for a fix requiring manual approval."""
    api_key = os.getenv("RESEND_API_KEY")
    sender = os.getenv("NOTIFY_EMAIL_FROM")
    if not api_key or not sender:
        logger.error(
            "Cannot send ask notification: RESEND_API_KEY and NOTIFY_EMAIL_FROM are required"
        )
        return False

    resend.api_key = api_key
    message = {
        "from": sender,
        "to": [to_email],
        "subject": f"Bastion: {cve_id} in {package} needs your approval",
        "text": _email_body(
            cve_id,
            package,
            current_version,
            target_version,
            epss_score,
            in_kev,
            pr_url,
            rationale,
        ),
    }
    try:
        await asyncio.to_thread(resend.Emails.send, message)
    except Exception as error:
        logger.warning("Unable to send Bastion ask notification: %s", error)
        return False
    return True
