#!/usr/bin/env bash
# paramant-roadmap — PQC migration roadmap generator
# Reads a crypto-audit-*.json file and produces a prioritised migration plan.
# Usage: paramant-roadmap [--from-audit FILE] [--output FILE] [--format md|txt|html]

set -euo pipefail

BOLD='\033[1m'; GREEN='\033[0;32m'; RED='\033[0;31m'
YELLOW='\033[0;33m'; CYAN='\033[0;36m'; DIM='\033[2m'; RESET='\033[0m'

AUDIT_FILE=""; OUTPUT_FILE=""; FORMAT="md"

usage() {
  echo -e "${BOLD}paramant-roadmap${RESET} — PQC migration roadmap generator

Usage: paramant-roadmap [options]

Options:
  --from-audit FILE   Input: crypto-audit-*.json (from paramant-crypto-audit)
  --output FILE       Output file (default: roadmap-<date>.md)
  --format md|txt     Output format (default: md)
  --help              Show this message

Examples:
  paramant-roadmap --from-audit crypto-audit-2026-04-14.json
  paramant-roadmap --from-audit crypto-audit-2026-04-14.json --output plan.md
  paramant-roadmap --from-audit scan.json --format txt | less"
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --from-audit) AUDIT_FILE="$2"; shift 2 ;;
    --output)     OUTPUT_FILE="$2"; shift 2 ;;
    --format)     FORMAT="$2"; shift 2 ;;
    --help|-h)    usage ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

if [[ -z "$AUDIT_FILE" ]]; then
  # Auto-detect most recent audit file in current directory
  AUDIT_FILE=$(ls crypto-audit-*.json 2>/dev/null | sort | tail -1 || true)
  if [[ -z "$AUDIT_FILE" ]]; then
    echo -e "${RED}Error:${RESET} No audit file specified and none found in current directory." >&2
    echo "Run 'paramant-crypto-audit' first, then re-run paramant-roadmap." >&2
    exit 1
  fi
  echo -e "${DIM}Auto-detected: ${AUDIT_FILE}${RESET}"
fi

[[ ! -f "$AUDIT_FILE" ]] && { echo -e "${RED}Error:${RESET} File not found: $AUDIT_FILE" >&2; exit 1; }
TODAY=$(date '+%Y-%m-%d')
[[ -z "$OUTPUT_FILE" ]] && OUTPUT_FILE="roadmap-${TODAY}.${FORMAT}"

# ── Generate roadmap via Python (already available on paramantOS) ──────────────
python3 - "$AUDIT_FILE" "$OUTPUT_FILE" "$FORMAT" "$TODAY" <<'PYEOF'
import json, sys, os
from datetime import date

audit_path, output_path, fmt, today = sys.argv[1:]
d = json.load(open(audit_path))

hostname  = d.get("hostname", "unknown-host")
scan_date = d.get("scan_date", today)
findings  = d.get("findings", [])
summary   = d.get("summary", {})
risk      = d.get("risk_level", "UNKNOWN")
qs_pct    = summary.get("quantum_safe_percentage", 0)
total     = summary.get("total_findings", len(findings))
critical  = summary.get("critical", 0)
high      = summary.get("high", 0)
medium    = summary.get("medium", 0)

# Partition findings by urgency
phase1 = [f for f in findings if f["severity"] in ("CRITICAL",)]
phase2 = [f for f in findings if f["severity"] == "HIGH"]
phase3 = [f for f in findings if f["severity"] in ("MEDIUM", "LOW")]

# Effort estimate (rough heuristic)
total_vuln = len([f for f in findings if not f.get("quantum_safe", True)])
if total_vuln == 0:
    effort = "No action required — all components are quantum-safe."
    readiness = "Already compliant"
elif total_vuln <= 3:
    effort = "1-2 weeks with paramant tooling."
    readiness = "2026-Q3 (recommended) / 2027-Q2 (latest safe)"
elif total_vuln <= 8:
    effort = "3-6 weeks with paramant tooling."
    readiness = "2026-Q4 (recommended) / 2027-Q4 (latest safe)"
elif total_vuln <= 15:
    effort = "6-8 weeks with paramant tooling."
    readiness = "2027-Q1 (recommended) / 2028-Q2 (latest safe)"
else:
    effort = "3-6 months; consider phased approach."
    readiness = "2027-Q2 (recommended) / 2028-Q4 (latest safe)"

# Category helpers
ssh_findings    = [f for f in phase1+phase2 if f.get("category","").lower() in ("ssh","ssh host key")]
tls_findings    = [f for f in phase1+phase2 if f.get("category","").lower() == "tls"]
backup_findings = [f for f in phase1+phase2+phase3 if "backup" in f.get("category","").lower()]
gpg_findings    = [f for f in phase1+phase2+phase3 if "gpg" in f.get("category","").lower() or "pgp" in f.get("algorithm","").lower()]
old_data_risk   = d.get("has_old_data_risk", False)

# ── Markdown output ────────────────────────────────────────────────────────────
lines = []
A = lines.append

A(f"# PQC Migration Roadmap — {hostname}")
A(f"Generated: {today}  |  Based on audit: {os.path.basename(audit_path)}")
A("")
A("---")
A("")
A("## Executive summary")
A("")
A(f"Your infrastructure has **{total_vuln} quantum-vulnerable component{'s' if total_vuln != 1 else ''}** "
  f"out of {total} items scanned. Current quantum-safe coverage: **{qs_pct:.0f}%**.")
A("")
A(f"- **Risk level:** {risk}")
A(f"- **Estimated migration effort:** {effort}")
A(f"- **Q-Day readiness target:** {readiness}")
if old_data_risk or d.get("summary", {}).get("old_files_at_risk", 0):
    old_count = d.get("summary", {}).get("old_files_at_risk", "some")
    A(f"- **Harvest Now, Decrypt Later (HNDL) risk:** {old_count} files older than 5 years are "
       "vulnerable to adversarial archival. Encrypt these first — the threat is active today.")
A("")
A("---")
A("")

# ── Phase 1 ────────────────────────────────────────────────────────────────────
A("## Phase 1 — Immediate (this week)")
A("")
A("These are critical or actively-harvested items. Each day of delay extends your HNDL exposure window.")
A("")
if ssh_findings:
    for f in ssh_findings:
        A(f"- [ ] **Replace SSH host keys** (`{f.get('item','ssh')}` — algorithm: `{f.get('algorithm','?')}`)  ")
        A(f"  `paramant-migrate --ssh` or `ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key`")
elif not phase1:
    A("- [ ] No critical findings — proceed to Phase 2")
for f in phase1:
    if f.get("category","").lower() not in ("ssh","ssh host key"):
        A(f"- [ ] **{f['item']}** ({f.get('category','?')}, `{f.get('algorithm','?')}`)  ")
        A(f"  → {f.get('action','See audit report')}")
if not phase1 and not ssh_findings:
    A("- [ ] *(no critical findings)*")

A("")
A("**Enroll long-lived data in paramant relay now** (harvest risk is active regardless of phase):")
A("```bash")
A("paramant-sender --key pgp_xxx --relay health --file sensitive-document.pdf")
A("# All files older than 5 years or marked confidential should transit via Ghost Pipe")
A("```")
A("")
A("---")
A("")

# ── Phase 2 ────────────────────────────────────────────────────────────────────
A("## Phase 2 — Short term (1–3 months)")
A("")
if tls_findings:
    for f in tls_findings:
        A(f"- [ ] **Replace TLS certificates** (`{f.get('item','?')}` — `{f.get('algorithm','?')}`)  ")
        A(f"  Run: `paramant-migrate --tls` or replace with ECDSA P-256 + request hybrid cert")
if phase2:
    for f in phase2:
        if f.get("category","").lower() not in ("tls","ssh","ssh host key"):
            A(f"- [ ] **{f['item']}** ({f.get('category','?')}, `{f.get('algorithm','?')}`)  ")
            A(f"  → {f.get('action','See audit report')}")
if not phase2 and not tls_findings:
    A("- [ ] *(no high-severity findings)*")

A("- [ ] Enable hybrid mode on paramant relay (`RELAY_MODE=ghost_pipe` — already default)")
A("- [ ] Audit all backup encryption (check for AES-256-GCM; replace DES/3DES/RSA-2048)")
A("- [ ] Contact top 3 quantum-vulnerable suppliers; request PQC roadmap disclosure")
A("")
A("---")
A("")

# ── Phase 3 ────────────────────────────────────────────────────────────────────
A("## Phase 3 — Medium term (3–12 months)")
A("")
A("- [ ] Full PQC transition — pure ML-KEM-768, drop RSA/classical-only paths")
A("- [ ] Supplier certification requirement: add PQC clause to new contracts")
A("- [ ] Annual `paramant-crypto-audit` schedule (add to cron: `paramant-cron --add crypto-audit weekly`)")
if medium > 0:
    A(f"- [ ] Resolve {medium} medium-severity findings from audit:")
    for f in phase3[:6]:
        A(f"  - {f['item']} ({f.get('category','?')}, `{f.get('algorithm','?')}`)")
    if len(phase3) > 6:
        A(f"  - *(and {len(phase3)-6} more — see full audit report)*")
A("")
A("---")
A("")

# ── Compliance deadlines ───────────────────────────────────────────────────────
A("## Compliance deadlines")
A("")
A("| Regulation | Requirement | Deadline |")
A("|-----------|------------|---------|")
A("| **EU NIS2** (2022/2555) | Migration plan documented and initiated | End 2026 |")
A("| **Algemene Rekenkamer** | PQC readiness assessed (rapport feb 2026) | Q2 2026 |")
A("| **EU CRA** | Software supply chain PQC by default | 2027-08 |")
A("| **NIST** | Full migration off RSA/ECDSA | 2030 |")
A("| **Q-Day estimate** | Cryptographically-relevant quantum computer | 2029–2031 |")
A("| **HNDL (active threat)** | Harvest Now, Decrypt Later is happening now | Immediate |")
A("")
A("> **Dutch government note:** The Algemene Rekenkamer (feb 2026) found 71% of surveyed")
A("> Dutch organisations have no migration plan. NIS2 Article 21 requires documented")
A("> cryptographic controls. This roadmap satisfies that documentation requirement.")
A("")
A("---")
A("")

# ── Budget estimate ────────────────────────────────────────────────────────────
A("## Budget estimate")
A("")
A("| Plan | Price | Users | Best for |")
A("|------|-------|-------|---------|")
A("| **Community** | Free | Up to 5 | Testing, small teams |")
A("| **Professional** | €149/month | Up to 50 | SMB, healthcare, legal |")
A("| **Enterprise** | Contact | Unlimited | Government, large enterprise |")
A("")
A("Self-hosting on your own VPS reduces cost to zero beyond infrastructure (Community Edition).")
A("Licensed edition: €149/month for unlimited keys on a self-hosted relay.")
A("")
A("→ [paramant.app/pricing](https://paramant.app/pricing)  ")
A("→ [Request a free API key](https://paramant.app/request-key)")
A("")
A("---")
A("")

# ── Remediation commands ───────────────────────────────────────────────────────
A("## Quick-start remediation commands")
A("")
A("```bash")
A("# 1. Replace SSH host keys (run on affected host)")
A("paramant-migrate --ssh")
A("")
A("# 2. Send a file securely via health relay")
A("paramant-sender --key pgp_xxx --relay health --file report.pdf")
A("")
A("# 3. Self-host a relay (Ubuntu 22.04 / Hetzner VPS)")
A("curl -fsSL https://paramant.app/install.sh | bash")
A("")
A("# 4. Re-run this audit in 30 days to verify progress")
A("paramant-crypto-audit --compare")
A("paramant-roadmap --from-audit crypto-audit-$(date +%Y-%m-%d).json")
A("```")
A("")
A("---")
A("")
A(f"*Generated by paramant-roadmap v2.4.5 on {today}. "
   "Based on [paramant-crypto-audit](https://paramant.app/docs#crypto-audit) output.*")

output = "\n".join(lines)
with open(output_path, "w") as fh:
    fh.write(output)

print(output_path)
PYEOF

echo -e "${GREEN}✓${RESET}  Roadmap written to: ${BOLD}${OUTPUT_FILE}${RESET}"
echo -e "${DIM}Review and share with your team or compliance officer.${RESET}"
