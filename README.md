# Bastion

Exploitability-driven, policy-gated autonomous CVE remediation for any GitHub
repo — built with OpenAI Codex and GPT-5.6 for OpenAI Build Week.

## What it does

1. Install the Bastion GitHub App on any repo (Python or Node).
2. On push, Bastion scans the manifest, resolves dependencies to known CVEs
   via [OSV.dev](https://osv.dev), and enriches each finding with an
   [EPSS](https://www.first.org/epss/) exploit-probability score and
   [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
   membership check.
3. GPT-5.6 proposes a real patch (dependency version bump).
4. An OPA/Rego policy (`policy/gate.rego`) — not the LLM — decides the
   outcome:
   - **auto** — patch-level fix, in CISA KEV, high EPSS: opens and merges
     the PR automatically.
   - **ask** — real risk signal but not high-confidence enough: opens a PR
     and emails the maintainer for approval.
   - **block** — major version bump, or low-signal finding: opens an issue
     with reasoning only, no code change.

The autonomy boundary is owned by explicit, auditable policy — the LLM
proposes, OPA disposes.

## Why this design

Every step in this pipeline hits a real, live API — no mocked or cached
data. Judges can install the app on a repo we did not pre-seed and watch it
work against real CVEs.

## Setup (for judges / local testing)

```bash
git clone <this-repo>
cd bastion
cp .env.example .env   # fill in your own keys — see below
pip install -r requirements.txt

# OPA binary required for policy evaluation
curl -L -o /usr/local/bin/opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
chmod +x /usr/local/bin/opa

pytest                 # run the test suite, including gate.rego coverage
uvicorn app.github_app.webhook:app --reload
```

Required keys in `.env`: GitHub App credentials, `OPENAI_API_KEY`,
`RESEND_API_KEY`. See `.env.example` for the full list — no keys are needed
for OSV.dev, EPSS, or CISA KEV (all public, no-auth endpoints).

### Testing against your own repo

1. Install the Bastion GitHub App (link in submission) on any Python or
   Node repo with an outdated dependency.
2. Push a commit, or wait for the scheduled scan.
3. Watch Bastion open a PR, an issue, or auto-merge, depending on the
   exploitability signal — check `policy/gate.rego` for the exact rules.

## Architecture

```
GitHub App install → scan manifest → resolve CVEs (OSV.dev)
  → enrich (EPSS + CISA KEV) → GPT-5.6 proposes fix
  → gate.rego decides → auto-merge / ask (PR + email) / block (issue)
```

## Built with Codex

Core pipeline scaffolding, GitHub App integration, and test suite built via
OpenAI Codex cloud tasks. `policy/gate.rego` — the autonomy-boundary logic —
was hand-authored as the project's core IP; Codex built the application
plumbing around it. Codex session ID for the primary build task:
`<fill in before submission>`.

## License

MIT
