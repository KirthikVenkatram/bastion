# AGENTS.md — instructions for Codex working in this repo

## What Bastion is
A GitHub App that scans a repo's dependency manifest, resolves known CVEs,
enriches them with EPSS exploit-probability scores and CISA KEV membership,
has GPT-5.6 propose a real patch, and passes the proposal through an OPA/Rego
policy (`policy/gate.rego`) that decides: auto-merge, ask (PR + email), or
block (issue only, no code change).

## The core contract — do not violate this
`policy/gate.rego` is the autonomy boundary. It is the single source of truth
for whether a fix gets applied automatically. Application code (`app/`) must
never bypass it, hardcode a decision, or duplicate its logic in Python. If
`app/pipeline.py` needs a decision, it calls into OPA via subprocess — see
`tests/test_gate.py` for the exact invocation pattern.

The gate.rego input contract (do not change without updating both the policy
and every caller):
```
{
  "cve_id": str, "package": str, "current_version": str, "fixed_version": str,
  "bump_type": "patch" | "minor" | "major",
  "epss_score": float (0-1), "in_kev": bool,
  "severity": "low" | "medium" | "high" | "critical"
}
```
Output: `{"decision": "auto" | "ask" | "block", "reason": str}`

## Conventions
- Python 3.11+, type hints on all function signatures.
- One module = one external concern (`enrich/osv_client.py` only talks to
  OSV.dev, `enrich/epss_client.py` only talks to EPSS, etc.) — no cross-calls
  between clients.
- Real API calls only. No mocked/stubbed enrichment data outside of `tests/`.
- Keep comments concise and only where logic isn't self-evident from naming —
  no restating what the code already says.

## Testing
Run `pytest` from repo root before considering any task complete. Gate policy
tests require the `opa` binary — installed via the environment setup script.
If you add a new module, add a corresponding `tests/test_<module>.py`.

## Secrets
Never hardcode API keys, tokens, or webhook secrets in source. Read from
environment variables only (see `.env.example` for the expected names).
