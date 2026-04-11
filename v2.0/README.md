# GH-VulnScan v2.0

Production-grade GitHub repository vulnerability scanner built entirely on open-source tooling.
Suitable for enterprise security pipelines, CI/CD gates, and penetration testing engagements.

---

## What it scans

| Category | Tools | What's detected |
|---|---|---|
| **Dependencies / CVEs** | Trivy, Grype, OSV-Scanner, pip-audit, npm audit, cargo-audit | Known CVEs across Python, Node, Rust, Ruby, Go, Java, PHP |
| **Secrets** | Gitleaks, Trivy | API keys, tokens, passwords in code and git history |
| **SAST** | Semgrep (OWASP Top 10, CWE Top 25), Bandit, Regex heuristics | SQL injection, XSS, command injection, deserialization, weak crypto |
| **IaC misconfigs** | Trivy, Checkov | Terraform, Kubernetes, Dockerfiles, GitHub Actions, Helm |
| **Config issues** | Regex heuristics | `.env` secrets, exposed ports, overly broad permissions |

---

## Output formats

- **JSON** — machine-readable, CI/CD compatible, normalized schema
- **SARIF 2.1.0** — uploads directly to GitHub Code Scanning, VS Code, and most SIEMs
- **HTML** — self-contained dashboard for human review

---

## Quick start

```bash
# 1. Install Python dependencies
pip install -r requirements.txt

# 2. Install binary tools (Linux/macOS)
chmod +x install_tools.sh && sudo ./install_tools.sh

# 3. Check what's available
python3 gh_vulnscan.py --list-tools

# 4. Run a scan
python3 gh_vulnscan.py https://github.com/org/repo

# 5. Scan a private repo
python3 gh_vulnscan.py https://github.com/org/private-repo --token ghp_xxx

# 6. Only report HIGH and above (CI/CD gate)
python3 gh_vulnscan.py https://github.com/org/repo --severity high

# 7. SARIF only (for GitHub Code Scanning upload)
python3 gh_vulnscan.py https://github.com/org/repo --format sarif
```

---

## CI/CD integration (GitHub Actions)

```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on: [push, pull_request]

jobs:
  vulnscan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write  # Required for SARIF upload
    steps:
      - uses: actions/checkout@v4

      - name: Install tools
        run: |
          pip install -r requirements.txt
          curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
          curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

      - name: Run GH-VulnScan
        run: |
          python3 gh_vulnscan.py ${{ github.server_url }}/${{ github.repository }} \
            --token ${{ secrets.GITHUB_TOKEN }} \
            --severity medium \
            --format sarif json

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: scan_results/report.sarif
        if: always()

      - name: Upload HTML report
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: scan_results/report.html
        if: always()
```

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No findings at or above severity floor |
| `1` | Findings found (use as CI gate) |
| `2` | Scanner error (repo unreachable, git not installed, etc.) |

---

## Tool coverage matrix

All tools are open-source with permissive licenses.

| Tool | License | What it covers |
|---|---|---|
| [Trivy](https://trivy.dev) | Apache 2.0 | CVEs, secrets, IaC misconfigs, licenses |
| [Grype](https://github.com/anchore/grype) | Apache 2.0 | CVEs via SBOM |
| [OSV-Scanner](https://github.com/google/osv-scanner) | Apache 2.0 | Cross-ecosystem advisories (Google) |
| [Semgrep](https://semgrep.dev) | LGPL 2.1 | Multi-language SAST, OWASP, CWE |
| [Bandit](https://bandit.readthedocs.io) | Apache 2.0 | Python-specific SAST |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | MIT | Secrets in code + git history |
| [Checkov](https://checkov.io) | Apache 2.0 | IaC misconfigurations |
| [pip-audit](https://github.com/pypa/pip-audit) | Apache 2.0 | Python advisories (PyPI/OSV) |
| npm audit | npm (built-in) | Node.js advisories |
| cargo-audit | MIT/Apache 2.0 | Rust advisories |

---

## Architecture

```
GHVulnScan (orchestrator)
├── RepoFetcher          — git clone → ZIP fallback → branch detection
├── Scanners (parallel)
│   ├── TrivyScanner      — CVEs + secrets + IaC (primary)
│   ├── GrypeScanner      — SBOM-aware CVEs (secondary)
│   ├── OSVScanner        — Google advisory database
│   ├── SemgrepScanner    — SAST (OWASP + CWE rulesets)
│   ├── BanditScanner     — Python SAST
│   ├── GitleaksScanner   — Secrets + git history
│   ├── CheckovScanner    — IaC misconfigs
│   ├── PipAuditScanner   — Python advisories
│   ├── NpmAuditScanner   — Node advisories
│   ├── CargoAuditScanner — Rust advisories
│   └── RegexHeuristic    — Fallback pattern scanner
├── deduplicate()         — fingerprint-based dedup
└── Reporters
    ├── JSON (normalized schema)
    ├── SARIF 2.1.0
    └── HTML dashboard
```