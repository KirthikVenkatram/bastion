package gate

import rego.v1

# Input contract (produced by app/pipeline.py before calling this policy):
# {
#   "cve_id": "CVE-2024-XXXXX",
#   "package": "requests",
#   "current_version": "2.25.0",
#   "fixed_version": "2.31.0",
#   "bump_type": "patch" | "minor" | "major",
#   "epss_score": 0.0-1.0,
#   "in_kev": true | false,
#   "severity": "low" | "medium" | "high" | "critical"
# }
#
# Output: {"decision": "auto" | "ask" | "block", "reason": "..."}

default decision := "ask"

# --- BLOCK: never touch major version bumps automatically, ever ---
decision := "block" if {
	input.bump_type == "major"
}

reason := "major version bump requires manual review — behavioral breakage risk" if {
	input.bump_type == "major"
}

# --- AUTO: high-confidence exploit signal + low blast-radius fix ---
# Both EPSS and KEV must agree this is a real, active threat, AND the fix
# itself must be low-risk (patch-level bump only). This is the core
# autonomy boundary: exploitability drives urgency, but only a safe fix
# earns the right to be automatic.
decision := "auto" if {
	input.bump_type == "patch"
	input.in_kev == true
	input.epss_score >= 0.5
}

reason := sprintf("patch-level fix for CVE in CISA KEV with EPSS %.2f — auto-merged", [input.epss_score]) if {
	input.bump_type == "patch"
	input.in_kev == true
	input.epss_score >= 0.5
}

# --- BLOCK: low-signal minor bumps aren't worth an automatic PR at all ---
decision := "block" if {
	input.bump_type == "minor"
	input.in_kev == false
	input.epss_score < 0.1
	input.severity in {"low", "medium"}
}

reason := "low exploitability, low severity, minor bump — not worth automated action" if {
	input.bump_type == "minor"
	input.in_kev == false
	input.epss_score < 0.1
	input.severity in {"low", "medium"}
}

# --- ASK: everything else — real risk signal, but not enough confidence
#     (or too large a change) to act without a human ---
reason := "risk signal present but insufficient confidence for auto-merge — human review requested" if {
	decision == "ask"
}
