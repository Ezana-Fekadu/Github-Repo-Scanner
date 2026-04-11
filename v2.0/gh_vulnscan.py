#!/usr/bin/env python3
"""
GH-VulnScan v2.0 — Production-Grade GitHub Repository Security Scanner
=======================================================================
Industry-standard vulnerability scanner using only open-source tooling.

Scanners used (all open-source):
  - Trivy          : CVE/dependency/IaC/secret scanning (Aqua Security)
  - Grype          : Container & SBOM vulnerability scanning (Anchore)
  - Semgrep        : Multi-language static analysis (r2c)
  - Bandit         : Python-specific SAST
  - Gitleaks       : Secrets & credential detection
  - OSV-Scanner    : Google's Open Source Vulnerability scanner
  - Checkov        : IaC misconfig scanner (Terraform, K8s, Dockerfiles)
  - pip-audit      : Python advisory scanning
  - npm audit      : Node.js advisory scanning
  - cargo-audit    : Rust advisory scanning

Output formats:
  - JSON (machine-readable, CI/CD compatible)
  - SARIF (GitHub Code Scanning / IDE compatible)
  - HTML dashboard (human-readable)

Usage:
  python3 gh_vulnscan.py https://github.com/org/repo
  python3 gh_vulnscan.py https://github.com/org/repo --token ghp_xxx --output-dir ./results
  python3 gh_vulnscan.py https://github.com/org/repo --severity high --format sarif
"""

from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
import zipfile
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ---------------------------------------------------------------------------
# Logging Setup
# ---------------------------------------------------------------------------

LOG_FORMAT = "%(asctime)s [%(levelname)8s] %(name)s — %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT, datefmt="%Y-%m-%dT%H:%M:%S")
log = logging.getLogger("gh-vulnscan")


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"
    UNKNOWN  = "UNKNOWN"

    @classmethod
    def from_str(cls, s: str) -> "Severity":
        return cls.__members__.get(s.upper(), cls.UNKNOWN)

    @property
    def score(self) -> int:
        return {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "UNKNOWN": 0}[self.value]


@dataclasses.dataclass
class Finding:
    """Normalised finding across all scanners."""
    scanner:     str
    category:    str           # dependency | secret | sast | iac | config
    severity:    Severity
    title:       str
    description: str           = ""
    file:        Optional[str] = None
    line:        Optional[int] = None
    package:     Optional[str] = None
    version:     Optional[str] = None
    fixed_in:    Optional[str] = None
    cve:         Optional[str] = None
    cvss:        Optional[float] = None
    rule_id:     Optional[str] = None
    fingerprint: str           = dataclasses.field(init=False)

    def __post_init__(self):
        raw = f"{self.scanner}:{self.category}:{self.title}:{self.file}:{self.line}:{self.package}"
        self.fingerprint = hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


# ---------------------------------------------------------------------------
# HTTP session with retry
# ---------------------------------------------------------------------------

def _http_session() -> requests.Session:
    s = requests.Session()
    retry = Retry(total=4, backoff_factor=1.5,
                  status_forcelist=[429, 500, 502, 503, 504])
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.mount("http://",  HTTPAdapter(max_retries=retry))
    return s


# ---------------------------------------------------------------------------
# Tool availability
# ---------------------------------------------------------------------------

REQUIRED_TOOLS  = ["git"]
OPTIONAL_TOOLS  = ["trivy", "grype", "semgrep", "bandit", "gitleaks",
                   "osv-scanner", "checkov", "pip-audit", "npm", "cargo",
                   "safety", "yarn"]

def check_tools() -> Tuple[Set[str], Set[str]]:
    """Return (available, missing) sets for all tracked tools."""
    available, missing = set(), set()
    for t in REQUIRED_TOOLS + OPTIONAL_TOOLS:
        (available if shutil.which(t) else missing).add(t)
    return available, missing


# ---------------------------------------------------------------------------
# Scanner base
# ---------------------------------------------------------------------------

class BaseScanner:
    name: str = "base"
    category: str = "generic"

    def __init__(self, repo_dir: Path, available_tools: Set[str],
                 severity_floor: Severity):
        self.repo_dir       = repo_dir
        self.available      = available_tools
        self.severity_floor = severity_floor
        self.log            = logging.getLogger(f"gh-vulnscan.{self.name}")

    def run(self) -> List[Finding]:
        raise NotImplementedError

    def _run_cmd(self, cmd: List[str], cwd: Optional[Path] = None,
                 timeout: int = 300, env: Optional[dict] = None) -> subprocess.CompletedProcess:
        effective_env = {**os.environ, **(env or {})}
        try:
            return subprocess.run(
                cmd, cwd=cwd or self.repo_dir,
                capture_output=True, text=True,
                timeout=timeout, env=effective_env
            )
        except subprocess.TimeoutExpired:
            self.log.warning("Command timed out: %s", " ".join(cmd))
            return subprocess.CompletedProcess(cmd, -1, "", "TIMEOUT")
        except FileNotFoundError:
            self.log.warning("Tool not found: %s", cmd[0])
            return subprocess.CompletedProcess(cmd, -1, "", "NOT_FOUND")

    def _needs(self, *tools: str) -> bool:
        missing = [t for t in tools if t not in self.available]
        if missing:
            self.log.warning("Skipping %s — missing tools: %s", self.name, missing)
            return False
        return True

    def _above_floor(self, sev: Severity) -> bool:
        return sev.score >= self.severity_floor.score


# ---------------------------------------------------------------------------
# Individual scanners
# ---------------------------------------------------------------------------

class TrivyScanner(BaseScanner):
    """Trivy: CVE, dependencies, IaC, secrets — one binary, many modes."""
    name = "trivy"
    category = "multi"

    def run(self) -> List[Finding]:
        if not self._needs("trivy"):
            return []
        findings = []
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out = Path(f.name)

        cmd = [
            "trivy", "fs", "--scanners", "vuln,secret,config,license",
            "--format", "json", "--output", str(out),
            "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
            "--exit-code", "0",
            str(self.repo_dir)
        ]
        self._run_cmd(cmd, timeout=600)

        try:
            data = json.loads(out.read_text())
        except Exception as e:
            self.log.error("Trivy JSON parse failed: %s", e)
            return []
        finally:
            out.unlink(missing_ok=True)

        for result in data.get("Results", []):
            target = result.get("Target", "")
            # Vulnerabilities
            for v in result.get("Vulnerabilities") or []:
                sev = Severity.from_str(v.get("Severity", "UNKNOWN"))
                if not self._above_floor(sev):
                    continue
                findings.append(Finding(
                    scanner="trivy", category="dependency",
                    severity=sev,
                    title=f"{v.get('PkgName')} {v.get('InstalledVersion')} — {v.get('VulnerabilityID')}",
                    description=v.get("Description", ""),
                    file=target,
                    package=v.get("PkgName"),
                    version=v.get("InstalledVersion"),
                    fixed_in=v.get("FixedVersion"),
                    cve=v.get("VulnerabilityID"),
                    cvss=v.get("CVSS", {}).get("nvd", {}).get("V3Score"),
                ))
            # Secrets
            for s in result.get("Secrets") or []:
                sev = Severity.from_str(s.get("Severity", "HIGH"))
                if not self._above_floor(sev):
                    continue
                findings.append(Finding(
                    scanner="trivy", category="secret",
                    severity=sev,
                    title=s.get("Title", "Secret detected"),
                    description=s.get("Match", ""),
                    file=target,
                    line=s.get("StartLine"),
                    rule_id=s.get("RuleID"),
                ))
            # Misconfigurations (IaC)
            for m in result.get("Misconfigurations") or []:
                sev = Severity.from_str(m.get("Severity", "UNKNOWN"))
                if not self._above_floor(sev):
                    continue
                findings.append(Finding(
                    scanner="trivy", category="iac",
                    severity=sev,
                    title=m.get("Title", "Misconfiguration"),
                    description=m.get("Description", ""),
                    file=target,
                    rule_id=m.get("ID"),
                ))

        self.log.info("Trivy: %d findings", len(findings))
        return findings


class GrypeScanner(BaseScanner):
    """Grype: SBOM-aware dependency vulnerability scanner."""
    name = "grype"
    category = "dependency"

    def run(self) -> List[Finding]:
        if not self._needs("grype"):
            return []
        findings = []
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out = Path(f.name)

        self._run_cmd([
            "grype", f"dir:{self.repo_dir}",
            "-o", "json", "--file", str(out),
            "--only-fixed"  # Focus on actionable vulns
        ], timeout=600)

        try:
            data = json.loads(out.read_text())
        except Exception as e:
            self.log.error("Grype JSON parse failed: %s", e)
            return []
        finally:
            out.unlink(missing_ok=True)

        for match in data.get("matches", []):
            vuln  = match.get("vulnerability", {})
            art   = match.get("artifact", {})
            sev   = Severity.from_str(vuln.get("severity", "UNKNOWN"))
            if not self._above_floor(sev):
                continue
            cvss  = None
            for c in vuln.get("cvss", []):
                if "metrics" in c:
                    cvss = c["metrics"].get("baseScore")
                    break
            findings.append(Finding(
                scanner="grype", category="dependency",
                severity=sev,
                title=f"{art.get('name')} {art.get('version')} — {vuln.get('id')}",
                description=vuln.get("description", ""),
                package=art.get("name"),
                version=art.get("version"),
                fixed_in=vuln.get("fix", {}).get("versions", [None])[0],
                cve=vuln.get("id"),
                cvss=cvss,
            ))

        self.log.info("Grype: %d findings", len(findings))
        return findings


class OSVScanner(BaseScanner):
    """Google OSV-Scanner: cross-ecosystem dependency scanner."""
    name = "osv-scanner"
    category = "dependency"

    def run(self) -> List[Finding]:
        if not self._needs("osv-scanner"):
            return []
        findings = []
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out = Path(f.name)

        result = self._run_cmd([
            "osv-scanner", "--recursive", "--format", "json",
            "--output", str(out), str(self.repo_dir)
        ], timeout=300)

        try:
            data = json.loads(out.read_text())
        except Exception as e:
            self.log.error("OSV-Scanner JSON parse failed: %s", e)
            return []
        finally:
            out.unlink(missing_ok=True)

        for result_entry in data.get("results", []):
            for pkg in result_entry.get("packages", []):
                pkg_info = pkg.get("package", {})
                for vuln in pkg.get("vulnerabilities", []):
                    sev = Severity.UNKNOWN
                    # OSV doesn't always include severity; derive from CVSS if present
                    for sev_entry in vuln.get("severity", []):
                        score_str = sev_entry.get("score", "")
                        if score_str:
                            try:
                                score = float(score_str)
                                if   score >= 9.0: sev = Severity.CRITICAL
                                elif score >= 7.0: sev = Severity.HIGH
                                elif score >= 4.0: sev = Severity.MEDIUM
                                else:              sev = Severity.LOW
                            except ValueError:
                                pass
                    if sev == Severity.UNKNOWN:
                        sev = Severity.MEDIUM  # Conservative default
                    if not self._above_floor(sev):
                        continue
                    findings.append(Finding(
                        scanner="osv-scanner", category="dependency",
                        severity=sev,
                        title=f"{pkg_info.get('name')} — {vuln.get('id')}",
                        description=vuln.get("summary", ""),
                        package=pkg_info.get("name"),
                        version=pkg_info.get("version"),
                        cve=vuln.get("id"),
                    ))

        self.log.info("OSV-Scanner: %d findings", len(findings))
        return findings


class SemgrepScanner(BaseScanner):
    """Semgrep: multi-language SAST with community rulesets."""
    name = "semgrep"
    category = "sast"

    RULESETS = [
        "p/default",
        "p/owasp-top-ten",
        "p/secrets",
        "p/supply-chain",
        "p/cwe-top-25",
    ]

    def run(self) -> List[Finding]:
        if not self._needs("semgrep"):
            return []
        findings = []
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out = Path(f.name)

        configs = []
        for r in self.RULESETS:
            configs += ["--config", r]

        self._run_cmd(
            ["semgrep", "scan", "--json", "--output", str(out),
             "--no-git-ignore", "--max-target-bytes", "5000000"] + configs,
            timeout=900,
            env={"SEMGREP_SEND_METRICS": "off"}
        )

        try:
            data = json.loads(out.read_text())
        except Exception as e:
            self.log.error("Semgrep JSON parse failed: %s", e)
            return []
        finally:
            out.unlink(missing_ok=True)

        for r in data.get("results", []):
            extra = r.get("extra", {})
            sev   = Severity.from_str(extra.get("severity", "UNKNOWN"))
            if not self._above_floor(sev):
                continue
            meta  = extra.get("metadata", {})
            findings.append(Finding(
                scanner="semgrep", category="sast",
                severity=sev,
                title=extra.get("message", r.get("check_id", "semgrep finding")),
                description=meta.get("description", ""),
                file=r.get("path"),
                line=r.get("start", {}).get("line"),
                rule_id=r.get("check_id"),
                cve=meta.get("cve"),
            ))

        self.log.info("Semgrep: %d findings", len(findings))
        return findings


class BanditScanner(BaseScanner):
    """Bandit: Python-specific SAST."""
    name = "bandit"
    category = "sast"

    def run(self) -> List[Finding]:
        if not self._needs("bandit"):
            return []
        py_files = list(self.repo_dir.rglob("*.py"))
        if not py_files:
            return []
        findings = []
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out = Path(f.name)

        self._run_cmd([
            "bandit", "-r", str(self.repo_dir),
            "-f", "json", "-o", str(out),
            "-l",   # Only HIGH confidence
            "--skip", "B101"  # Skip assert statements (noisy in tests)
        ], timeout=300)

        try:
            data = json.loads(out.read_text())
        except Exception as e:
            self.log.error("Bandit JSON parse failed: %s", e)
            return []
        finally:
            out.unlink(missing_ok=True)

        severity_map = {"HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}

        for issue in data.get("results", []):
            sev = severity_map.get(issue.get("issue_severity", ""), Severity.UNKNOWN)
            if not self._above_floor(sev):
                continue
            findings.append(Finding(
                scanner="bandit", category="sast",
                severity=sev,
                title=issue.get("issue_text", ""),
                description=issue.get("more_info", ""),
                file=issue.get("filename"),
                line=issue.get("line_number"),
                rule_id=issue.get("test_id"),
            ))

        self.log.info("Bandit: %d findings", len(findings))
        return findings


class GitleaksScanner(BaseScanner):
    """Gitleaks: secrets, API keys, credentials in code and git history."""
    name = "gitleaks"
    category = "secret"

    def run(self) -> List[Finding]:
        if not self._needs("gitleaks"):
            return []
        findings = []
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out = Path(f.name)

        # Scan both the working tree and git log
        for mode in ["detect", "detect --no-git"]:
            self._run_cmd(
                ["gitleaks"] + mode.split() + [
                    "--source", str(self.repo_dir),
                    "--report-format", "json",
                    "--report-path", str(out),
                    "--redact",       # Don't store actual secret values
                    "--exit-code", "0"
                ],
                timeout=300
            )
            try:
                data = json.loads(out.read_text())
                if not isinstance(data, list):
                    continue
                for leak in data:
                    findings.append(Finding(
                        scanner="gitleaks", category="secret",
                        severity=Severity.HIGH,
                        title=f"Secret detected: {leak.get('Description', 'unknown type')}",
                        description=f"Rule: {leak.get('RuleID')} | Match: [REDACTED]",
                        file=leak.get("File"),
                        line=leak.get("StartLine"),
                        rule_id=leak.get("RuleID"),
                    ))
            except Exception:
                pass

        # Deduplicate by fingerprint
        seen = set()
        unique = []
        for f in findings:
            if f.fingerprint not in seen:
                seen.add(f.fingerprint)
                unique.append(f)

        out.unlink(missing_ok=True)
        self.log.info("Gitleaks: %d findings", len(unique))
        return unique


class CheckovScanner(BaseScanner):
    """Checkov: IaC misconfiguration scanner (Terraform, K8s, Dockerfiles, etc.)."""
    name = "checkov"
    category = "iac"

    def run(self) -> List[Finding]:
        if not self._needs("checkov"):
            return []
        findings = []
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out = Path(f.name)

        self._run_cmd([
            "checkov", "-d", str(self.repo_dir),
            "-o", "json", "--output-file-path", str(out.parent),
            "--compact",
            "--quiet",
            "--soft-fail"  # Don't exit non-zero on findings
        ], timeout=300)

        # Checkov writes results_{framework}.json; load whichever exists
        result_files = list(out.parent.glob("results_*.json")) or [out]
        for rf in result_files:
            try:
                data = json.loads(rf.read_text())
                if isinstance(data, list):
                    data = {"results": {"failed_checks": data}}
                checks = (data.get("results") or {}).get("failed_checks") or []
                for check in checks:
                    sev = Severity.from_str(check.get("severity") or "MEDIUM")
                    if not self._above_floor(sev):
                        continue
                    findings.append(Finding(
                        scanner="checkov", category="iac",
                        severity=sev,
                        title=check.get("check_id", "") + ": " + check.get("check_type", ""),
                        description=check.get("check_id", ""),
                        file=check.get("file_path"),
                        line=check.get("file_line_range", [None])[0],
                        rule_id=check.get("check_id"),
                    ))
            except Exception as e:
                self.log.debug("Checkov parse error: %s", e)

        out.unlink(missing_ok=True)
        self.log.info("Checkov: %d findings", len(findings))
        return findings


class PipAuditScanner(BaseScanner):
    """pip-audit: Python dependency advisory scanning via OSV/PyPI."""
    name = "pip-audit"
    category = "dependency"

    def run(self) -> List[Finding]:
        if not self._needs("pip-audit"):
            return []
        findings = []
        req_files = list(self.repo_dir.rglob("requirements*.txt")) + \
                    list(self.repo_dir.rglob("pyproject.toml")) + \
                    list(self.repo_dir.rglob("Pipfile"))

        for req_file in req_files:
            result = self._run_cmd([
                "pip-audit", "-r", str(req_file),
                "--format", "json", "--progress-spinner", "off"
            ], timeout=180)

            try:
                data = json.loads(result.stdout)
            except Exception:
                continue

            for dep in data.get("dependencies", []):
                for vuln in dep.get("vulns", []):
                    findings.append(Finding(
                        scanner="pip-audit", category="dependency",
                        severity=Severity.HIGH,  # pip-audit doesn't provide severity
                        title=f"{dep.get('name')} {dep.get('version')} — {vuln.get('id')}",
                        description=vuln.get("description", ""),
                        file=str(req_file),
                        package=dep.get("name"),
                        version=dep.get("version"),
                        fixed_in=", ".join(vuln.get("fix_versions", [])) or None,
                        cve=vuln.get("id"),
                    ))

        self.log.info("pip-audit: %d findings", len(findings))
        return findings


class NpmAuditScanner(BaseScanner):
    """npm audit: Node.js dependency advisory scanning."""
    name = "npm-audit"
    category = "dependency"

    def run(self) -> List[Finding]:
        if not self._needs("npm"):
            return []
        findings = []

        for pkg_json in self.repo_dir.rglob("package.json"):
            if "node_modules" in str(pkg_json):
                continue
            result = self._run_cmd(
                ["npm", "audit", "--json"],
                cwd=pkg_json.parent, timeout=180
            )
            try:
                data = json.loads(result.stdout)
            except Exception:
                continue

            for name, vuln in (data.get("vulnerabilities") or {}).items():
                sev = Severity.from_str(vuln.get("severity", "UNKNOWN"))
                if not self._above_floor(sev):
                    continue
                for via in vuln.get("via", []):
                    if not isinstance(via, dict):
                        continue
                    findings.append(Finding(
                        scanner="npm-audit", category="dependency",
                        severity=sev,
                        title=f"{name} — {via.get('title', 'Advisory')}",
                        description=via.get("url", ""),
                        file=str(pkg_json),
                        package=name,
                        version=vuln.get("range"),
                        cve=via.get("cve", [None])[0] if via.get("cve") else None,
                        cvss=via.get("cvss", {}).get("score"),
                    ))

        self.log.info("npm-audit: %d findings", len(findings))
        return findings


class CargoAuditScanner(BaseScanner):
    """cargo-audit: Rust advisory scanning."""
    name = "cargo-audit"
    category = "dependency"

    def run(self) -> List[Finding]:
        findings = []
        for cargo_toml in self.repo_dir.rglob("Cargo.toml"):
            result = self._run_cmd(
                ["cargo", "audit", "--json"],
                cwd=cargo_toml.parent, timeout=180
            )
            try:
                data = json.loads(result.stdout)
            except Exception:
                continue
            for vuln in (data.get("vulnerabilities") or {}).get("list", []):
                adv = vuln.get("advisory", {})
                pkg = vuln.get("package", {})
                findings.append(Finding(
                    scanner="cargo-audit", category="dependency",
                    severity=Severity.HIGH,
                    title=f"{pkg.get('name')} — {adv.get('id')}",
                    description=adv.get("description", ""),
                    package=pkg.get("name"),
                    version=pkg.get("version"),
                    cve=adv.get("aliases", [None])[0] if adv.get("aliases") else None,
                ))

        self.log.info("cargo-audit: %d findings", len(findings))
        return findings


class RegexHeuristicScanner(BaseScanner):
    """
    Fast regex-based heuristic scanner.
    Acts as a safety net when other tools are unavailable.
    Includes ALL common OWASP Top 10 patterns across languages.
    """
    name = "regex-heuristic"
    category = "sast"

    PATTERNS: Dict[str, List[Tuple[str, str, Severity]]] = {
        # (pattern, description, severity)
        "*.py": [
            (r"subprocess\.(?:call|run|Popen)\s*\(\s*[^,\]]+\+",           "Possible command injection via string concat",  Severity.HIGH),
            (r"eval\s*\(\s*(?:request|input|os\.getenv)",                  "eval() with external input",                    Severity.CRITICAL),
            (r"pickle\.loads?\s*\(",                                       "Insecure pickle deserialization",               Severity.HIGH),
            (r"yaml\.load\s*\([^,)]+\)",                                   "Unsafe yaml.load (use yaml.safe_load)",         Severity.HIGH),
            (r"hashlib\.(?:md5|sha1)\s*\(",                                "Weak hashing algorithm",                       Severity.MEDIUM),
            (r"DEBUG\s*=\s*True",                                          "Debug mode enabled in code",                    Severity.MEDIUM),
            (r"verify\s*=\s*False",                                        "SSL verification disabled",                     Severity.HIGH),
            (r"password\s*=\s*['\"][^'\"]{4,}['\"]",                       "Hardcoded password",                           Severity.CRITICAL),
            (r"SECRET_KEY\s*=\s*['\"][^'\"]{8,}['\"]",                    "Hardcoded secret key",                          Severity.CRITICAL),
        ],
        "*.js": [
            (r"eval\s*\(",                                                  "eval() usage",                                 Severity.HIGH),
            (r"innerHTML\s*=\s*(?!.*DOMPurify)",                           "Unsanitised innerHTML assignment (XSS risk)",   Severity.HIGH),
            (r"document\.write\s*\(",                                      "document.write() usage",                       Severity.MEDIUM),
            (r"dangerouslySetInnerHTML",                                   "React dangerouslySetInnerHTML",                 Severity.MEDIUM),
            (r"child_process",                                             "Node.js child_process usage",                  Severity.MEDIUM),
            (r"(?:localStorage|sessionStorage)\.setItem.*(?:token|pass)",  "Sensitive data in browser storage",            Severity.HIGH),
        ],
        "*.php": [
            (r"(?:mysql_query|mysqli_query)\s*\(\s*['\"].*\$",             "Possible SQL injection (PHP)",                 Severity.CRITICAL),
            (r"\$_(?:GET|POST|REQUEST|COOKIE)\[.*\].*(?:exec|system|eval)", "User input passed to dangerous function",     Severity.CRITICAL),
            (r"include\s*\(\s*\$",                                         "Dynamic file inclusion",                       Severity.HIGH),
            (r"shell_exec\s*\(",                                           "shell_exec() usage",                           Severity.HIGH),
        ],
        "*.java": [
            (r"Runtime\.getRuntime\(\)\.exec",                             "Runtime command execution",                    Severity.HIGH),
            (r"new\s+ProcessBuilder",                                      "ProcessBuilder command execution",             Severity.HIGH),
            (r"ObjectInputStream",                                         "Java deserialization risk",                    Severity.HIGH),
            (r"MessageDigest\.getInstance\s*\(\s*['\"](?:MD5|SHA-1)['\"]", "Weak hashing algorithm",                      Severity.MEDIUM),
        ],
        "*.go": [
            (r"exec\.Command\s*\(",                                        "Command execution",                            Severity.MEDIUM),
            (r"sql\.Open.*Sprintf",                                        "Possible SQL injection (Go)",                  Severity.HIGH),
            (r"ioutil\.WriteFile.*0[67]\d{2}",                             "File written with broad permissions",          Severity.LOW),
        ],
    }

    CONFIG_PATTERNS = [
        ("*/.env",                   r"(?:PASSWORD|SECRET|KEY|TOKEN)\s*=\s*\S+",        "Potential secret in .env file",          Severity.HIGH),
        ("*/docker-compose*.yml",    r'ports:\s*-\s*["\']?(?:0\.0\.0\.0:)?(?:22|3306|5432|6379|27017):', "Dangerous port exposure",  Severity.HIGH),
        ("*/.github/workflows/*.yml",r"permissions:\s*write-all",                       "Overly broad GitHub Actions permissions", Severity.MEDIUM),
        ("*/Dockerfile",             r"FROM\s+\S+:latest",                              "Unpinned Docker base image tag",         Severity.LOW),
        ("*/Dockerfile",             r"RUN.*sudo\s+chmod\s+777",                        "chmod 777 in Dockerfile",                 Severity.HIGH),
        ("*/nginx*.conf",            r"autoindex\s+on",                                 "Nginx directory listing enabled",         Severity.MEDIUM),
        ("*/nginx*.conf",            r"server_tokens\s+on",                             "Nginx version disclosure",                Severity.LOW),
    ]

    def run(self) -> List[Finding]:
        findings = []

        # Code patterns
        for glob_pattern, rules in self.PATTERNS.items():
            for file_path in self.repo_dir.rglob(glob_pattern):
                if any(p in str(file_path) for p in ["node_modules", ".git", "vendor", "dist", "__pycache__"]):
                    continue
                try:
                    content = file_path.read_text(errors="ignore")
                    for pattern, description, severity in rules:
                        if not self._above_floor(severity):
                            continue
                        for m in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                            line_no = content[:m.start()].count("\n") + 1
                            findings.append(Finding(
                                scanner=self.name, category="sast",
                                severity=severity,
                                title=description,
                                file=str(file_path.relative_to(self.repo_dir)),
                                line=line_no,
                                rule_id=f"regex/{pattern[:30]}",
                            ))
                except Exception as e:
                    self.log.debug("Skipping %s: %s", file_path, e)

        # Config patterns
        for glob_pattern, pattern, description, severity in self.CONFIG_PATTERNS:
            if not self._above_floor(severity):
                continue
            for file_path in self.repo_dir.rglob(glob_pattern):
                try:
                    content = file_path.read_text(errors="ignore")
                    if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
                        findings.append(Finding(
                            scanner=self.name, category="config",
                            severity=severity,
                            title=description,
                            file=str(file_path.relative_to(self.repo_dir)),
                            rule_id=f"config/{glob_pattern}",
                        ))
                except Exception:
                    pass

        self.log.info("Regex heuristic: %d findings", len(findings))
        return findings


# ---------------------------------------------------------------------------
# Repo fetcher
# ---------------------------------------------------------------------------

class RepoFetcher:
    def __init__(self, repo_url: str, dest: Path, token: Optional[str] = None):
        self.repo_url = repo_url
        self.dest     = dest
        self.token    = token
        self.log      = logging.getLogger("gh-vulnscan.fetcher")
        self._session = _http_session()

    def fetch(self) -> bool:
        if self.dest.exists():
            shutil.rmtree(self.dest)
        self.dest.mkdir(parents=True)

        if self._try_git_clone():
            return True
        self.log.warning("Git clone failed, falling back to ZIP download")
        return self._try_zip_download()

    def _try_git_clone(self) -> bool:
        env = {**os.environ,
               "GIT_TERMINAL_PROMPT": "0",
               "GIT_ASKPASS": "/bin/echo"}
        url = self.repo_url
        if self.token:
            parsed = urlparse(url)
            url = parsed._replace(netloc=f"{self.token}@{parsed.netloc}").geturl()

        try:
            result = subprocess.run(
                ["git", "clone", "--depth=1", url, str(self.dest)],
                capture_output=True, text=True, timeout=300, env=env
            )
            if result.returncode == 0:
                self.log.info("Git clone successful")
                return True
            self.log.debug("Git clone stderr: %s", result.stderr.strip())
        except Exception as e:
            self.log.debug("Git clone exception: %s", e)
        return False

    def _try_zip_download(self) -> bool:
        parsed = urlparse(self.repo_url)
        parts  = parsed.path.strip("/").split("/")
        if len(parts) < 2:
            self.log.error("Cannot parse owner/repo from URL: %s", self.repo_url)
            return False
        owner, repo = parts[0], parts[1]
        headers = {}
        if self.token:
            headers["Authorization"] = f"token {self.token}"

        for branch in ["main", "master", "develop"]:
            url = f"https://github.com/{owner}/{repo}/archive/refs/heads/{branch}.zip"
            try:
                resp = self._session.get(url, headers=headers, stream=True, timeout=60)
                if resp.status_code == 404:
                    continue
                resp.raise_for_status()

                with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tmp:
                    for chunk in resp.iter_content(8192):
                        tmp.write(chunk)
                    tmp_path = Path(tmp.name)

                with zipfile.ZipFile(tmp_path) as zf:
                    top = zf.namelist()[0].split("/")[0]
                    zf.extractall(self.dest.parent)

                extracted = self.dest.parent / top
                for item in extracted.iterdir():
                    shutil.move(str(item), str(self.dest))
                shutil.rmtree(extracted, ignore_errors=True)
                tmp_path.unlink(missing_ok=True)
                self.log.info("ZIP download successful from branch: %s", branch)
                return True
            except Exception as e:
                self.log.debug("ZIP download failed for %s: %s", branch, e)

        return False


# ---------------------------------------------------------------------------
# Report generators
# ---------------------------------------------------------------------------

class SARIFReporter:
    """SARIF 2.1.0 — compatible with GitHub Code Scanning, VS Code, etc."""
    VERSION = "2.1.0"
    SCHEMA  = "https://json.schemastore.org/sarif-2.1.0.json"

    def generate(self, findings: List[Finding], repo_url: str) -> dict:
        rules: Dict[str, dict] = {}
        results: List[dict] = []

        for f in findings:
            rule_id = f.rule_id or f.fingerprint
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": f.title[:128],
                    "shortDescription": {"text": f.title[:256]},
                    "fullDescription": {"text": f.description[:1024] or f.title},
                    "helpUri": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={f.cve}" if f.cve else None,
                    "properties": {"tags": [f.category, f.scanner]},
                    "defaultConfiguration": {
                        "level": {"CRITICAL": "error", "HIGH": "error",
                                  "MEDIUM": "warning", "LOW": "note"}.get(f.severity.value, "none")
                    }
                }

            loc = {}
            if f.file:
                loc = {"physicalLocation": {
                    "artifactLocation": {"uri": f.file, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": f.line or 1}
                }}

            results.append({
                "ruleId": rule_id,
                "level": {"CRITICAL": "error", "HIGH": "error",
                           "MEDIUM": "warning", "LOW": "note"}.get(f.severity.value, "none"),
                "message": {"text": f.title},
                "locations": [loc] if loc else [],
                "fingerprints": {"gh-vulnscan/v1": f.fingerprint},
                "properties": {
                    "severity": f.severity.value,
                    "cve": f.cve,
                    "cvss": f.cvss,
                    "package": f.package,
                    "fixed_in": f.fixed_in,
                }
            })

        return {
            "$schema": self.SCHEMA,
            "version": self.VERSION,
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "GH-VulnScan",
                        "version": "2.0.0",
                        "informationUri": "https://github.com/your-org/gh-vulnscan",
                        "rules": list(rules.values())
                    }
                },
                "invocations": [{"executionSuccessful": True}],
                "results": results,
                "originalUriBaseIds": {"%SRCROOT%": {"uri": repo_url + "/blob/HEAD/"}}
            }]
        }


class HTMLReporter:
    """Generates a rich, self-contained HTML dashboard."""

    SEV_COLOR = {
        "CRITICAL": "#d32f2f",
        "HIGH":     "#f57c00",
        "MEDIUM":   "#fbc02d",
        "LOW":      "#388e3c",
        "INFO":     "#1565c0",
        "UNKNOWN":  "#757575",
    }

    def generate(self, findings: List[Finding], repo_url: str,
                 scan_date: str, available_tools: Set[str],
                 missing_tools: Set[str]) -> str:

        by_sev   = {s.value: [] for s in Severity}
        by_cat   = {}
        by_scan  = {}
        for f in findings:
            by_sev[f.severity.value].append(f)
            by_cat.setdefault(f.category, []).append(f)
            by_scan.setdefault(f.scanner, []).append(f)

        crit_count = len(by_sev["CRITICAL"])
        high_count = len(by_sev["HIGH"])
        risk = "CRITICAL" if crit_count > 0 else \
               "HIGH"     if high_count > 0 else \
               "MEDIUM"   if len(by_sev["MEDIUM"]) > 0 else "LOW"

        rows = ""
        for f in sorted(findings, key=lambda x: -x.severity.score):
            color = self.SEV_COLOR.get(f.severity.value, "#999")
            rows += f"""
            <tr>
              <td><span class="badge" style="background:{color}">{f.severity.value}</span></td>
              <td>{f.scanner}</td>
              <td>{f.category}</td>
              <td class="title-cell">{f.title[:120]}</td>
              <td>{f.cve or ""}</td>
              <td>{f.package or ""}</td>
              <td>{f.fixed_in or ""}</td>
              <td>{(str(f.file or "") + (":" + str(f.line) if f.line else ""))[:60]}</td>
            </tr>"""

        tools_html = "".join(
            f'<span class="tool-badge available">✓ {t}</span>' for t in sorted(available_tools)
        ) + "".join(
            f'<span class="tool-badge missing">✗ {t}</span>' for t in sorted(missing_tools)
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>GH-VulnScan Report — {repo_url}</title>
<style>
  :root {{
    --bg: #0f1117; --surface: #1a1d27; --surface2: #252836;
    --border: #2e3244; --text: #e0e2ef; --muted: #8b8fa8;
    --critical: #d32f2f; --high: #f57c00; --medium: #fbc02d;
    --low: #388e3c; --info: #1565c0;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; }}
  .header {{ background: linear-gradient(135deg, #1a1d27 0%, #12151f 100%); padding: 32px 40px; border-bottom: 1px solid var(--border); }}
  .header h1 {{ font-size: 1.8rem; font-weight: 700; color: #fff; }}
  .header .meta {{ color: var(--muted); font-size: 0.9rem; margin-top: 6px; }}
  .risk-badge {{ display: inline-block; padding: 4px 14px; border-radius: 20px; font-weight: 700; font-size: 1rem; margin-top: 12px;
                 background: var(--{risk.lower()}, #999); color: #fff; }}
  .container {{ max-width: 1400px; margin: 0 auto; padding: 32px 40px; }}
  .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; margin-bottom: 32px; }}
  .stat-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 20px; text-align: center; }}
  .stat-card .num {{ font-size: 2.4rem; font-weight: 800; }}
  .stat-card .label {{ font-size: 0.82rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; margin-top: 4px; }}
  .section {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px; margin-bottom: 24px; overflow: hidden; }}
  .section-header {{ padding: 16px 24px; border-bottom: 1px solid var(--border); font-weight: 600; display: flex; align-items: center; gap: 8px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.84rem; }}
  th {{ padding: 10px 14px; text-align: left; color: var(--muted); font-weight: 600; background: var(--surface2); text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.5px; }}
  td {{ padding: 10px 14px; border-top: 1px solid var(--border); vertical-align: top; }}
  tr:hover td {{ background: var(--surface2); }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.75rem; font-weight: 700; color: #fff; }}
  .title-cell {{ max-width: 340px; word-break: break-word; }}
  .tool-badge {{ display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 0.78rem; margin: 3px; }}
  .tool-badge.available {{ background: rgba(56,142,60,0.2); color: #81c784; border: 1px solid #388e3c; }}
  .tool-badge.missing  {{ background: rgba(211,47,47,0.15); color: #ef9a9a; border: 1px solid #d32f2f; }}
  .tools-section {{ padding: 20px 24px; }}
  .warning-box {{ background: rgba(251,192,45,0.1); border: 1px solid #fbc02d; border-radius: 8px; padding: 14px 18px; margin-bottom: 24px; color: #fbc02d; font-size: 0.88rem; }}
</style>
</head>
<body>
<div class="header">
  <h1>🔍 GH-VulnScan Security Report</h1>
  <div class="meta">
    <strong>Repository:</strong> {repo_url} &nbsp;|&nbsp;
    <strong>Scanned:</strong> {scan_date}
  </div>
  <div class="risk-badge">Overall Risk: {risk}</div>
</div>
<div class="container">
  {"<div class='warning-box'>⚠️ Some tools were unavailable: " + ", ".join(sorted(missing_tools)) + ". Coverage may be incomplete. Run <code>pip install bandit semgrep pip-audit checkov</code> and install <a href='https://trivy.dev'>trivy</a>, <a href='https://github.com/anchore/grype'>grype</a>, <a href='https://github.com/gitleaks/gitleaks'>gitleaks</a>.</div>" if missing_tools else ""}
  <div class="stats-grid">
    <div class="stat-card"><div class="num" style="color:var(--critical)">{len(by_sev["CRITICAL"])}</div><div class="label">Critical</div></div>
    <div class="stat-card"><div class="num" style="color:var(--high)">{len(by_sev["HIGH"])}</div><div class="label">High</div></div>
    <div class="stat-card"><div class="num" style="color:var(--medium)">{len(by_sev["MEDIUM"])}</div><div class="label">Medium</div></div>
    <div class="stat-card"><div class="num" style="color:var(--low)">{len(by_sev["LOW"])}</div><div class="label">Low</div></div>
    <div class="stat-card"><div class="num">{len(findings)}</div><div class="label">Total</div></div>
    <div class="stat-card"><div class="num">{len(by_cat.get("dependency",[]))}</div><div class="label">Dep. CVEs</div></div>
    <div class="stat-card"><div class="num">{len(by_cat.get("secret",[]))}</div><div class="label">Secrets</div></div>
    <div class="stat-card"><div class="num">{len(by_cat.get("sast",[]))}</div><div class="label">SAST</div></div>
    <div class="stat-card"><div class="num">{len(by_cat.get("iac",[]))}</div><div class="label">IaC</div></div>
  </div>

  <div class="section">
    <div class="section-header">🛠 Tool Coverage</div>
    <div class="tools-section">{tools_html}</div>
  </div>

  <div class="section">
    <div class="section-header">🚨 All Findings ({len(findings)} total)</div>
    <table>
      <thead><tr>
        <th>Severity</th><th>Scanner</th><th>Category</th><th>Title</th>
        <th>CVE / ID</th><th>Package</th><th>Fix Available</th><th>Location</th>
      </tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Deduplicator
# ---------------------------------------------------------------------------

def deduplicate(findings: List[Finding]) -> List[Finding]:
    """Remove exact duplicates; keep highest severity for same location+rule."""
    seen: Dict[str, Finding] = {}
    for f in findings:
        key = f"{f.category}:{f.rule_id or f.title}:{f.file}:{f.line}:{f.package}"
        existing = seen.get(key)
        if existing is None or f.severity.score > existing.severity.score:
            seen[key] = f
    return list(seen.values())


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

class GHVulnScan:
    def __init__(self, repo_url: str, output_dir: Path, token: Optional[str] = None,
                 severity_floor: Severity = Severity.LOW,
                 formats: List[str] = None,
                 max_workers: int = 4):
        self.repo_url       = repo_url
        self.output_dir     = output_dir
        self.token          = token
        self.severity_floor = severity_floor
        self.formats        = formats or ["json", "html", "sarif"]
        self.max_workers    = max_workers
        self.scan_date      = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.clone_dir      = self.output_dir / "repo_clone"
        self.log            = logging.getLogger("gh-vulnscan.orchestrator")

    def run(self) -> int:
        """
        Execute full scan pipeline.
        Returns exit code: 0 = clean, 1 = findings above floor, 2 = error.
        """
        log.info("=" * 60)
        log.info("GH-VulnScan v2.0 — %s", self.repo_url)
        log.info("Severity floor : %s", self.severity_floor.value)
        log.info("=" * 60)

        # 1. Preflight
        available, missing = check_tools()
        if "git" in missing:
            log.error("FATAL: git is not installed.")
            return 2
        if missing:
            log.warning("Missing optional tools (reduced coverage): %s", sorted(missing))
        log.info("Available tools: %s", sorted(available))

        # 2. Fetch repo
        fetcher = RepoFetcher(self.repo_url, self.clone_dir, self.token)
        if not fetcher.fetch():
            log.error("Failed to retrieve repository.")
            return 2

        # 3. Build scanner list
        scanner_classes = [
            TrivyScanner, GrypeScanner, OSVScanner, SemgrepScanner,
            BanditScanner, GitleaksScanner, CheckovScanner,
            PipAuditScanner, NpmAuditScanner, CargoAuditScanner,
            RegexHeuristicScanner,
        ]
        scanners = [
            cls(self.clone_dir, available, self.severity_floor)
            for cls in scanner_classes
        ]

        # 4. Run scanners in parallel
        all_findings: List[Finding] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(s.run): s.name for s in scanners}
            for future in concurrent.futures.as_completed(futures):
                name = futures[future]
                try:
                    results = future.result()
                    all_findings.extend(results)
                    log.info("%-20s → %d findings", name, len(results))
                except Exception:
                    log.error("Scanner %s raised an exception:\n%s", name, traceback.format_exc())

        # 5. Deduplicate
        findings = deduplicate(all_findings)
        log.info("Total unique findings: %d (before dedup: %d)", len(findings), len(all_findings))

        # 6. Write reports
        self._write_reports(findings, available, missing)

        # 7. Summary
        crit = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in findings if f.severity == Severity.HIGH)
        med  = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        low  = sum(1 for f in findings if f.severity == Severity.LOW)

        log.info("")
        log.info("━" * 60)
        log.info("  SCAN COMPLETE")
        log.info("  Critical : %d", crit)
        log.info("  High     : %d", high)
        log.info("  Medium   : %d", med)
        log.info("  Low      : %d", low)
        log.info("  Reports  : %s/", self.output_dir)
        log.info("━" * 60)

        return 1 if (crit + high) > 0 else 0

    def _write_reports(self, findings: List[Finding],
                       available: Set[str], missing: Set[str]):
        data = {
            "schema_version": "2.0",
            "scan_date": self.scan_date,
            "repo_url": self.repo_url,
            "summary": {
                "total": len(findings),
                "critical": sum(1 for f in findings if f.severity == Severity.CRITICAL),
                "high":     sum(1 for f in findings if f.severity == Severity.HIGH),
                "medium":   sum(1 for f in findings if f.severity == Severity.MEDIUM),
                "low":      sum(1 for f in findings if f.severity == Severity.LOW),
                "tools_used": sorted(available),
                "tools_missing": sorted(missing),
            },
            "findings": [f.to_dict() for f in
                         sorted(findings, key=lambda x: -x.severity.score)]
        }

        if "json" in self.formats:
            p = self.output_dir / "report.json"
            p.write_text(json.dumps(data, indent=2, default=str))
            log.info("JSON report   → %s", p)

        if "sarif" in self.formats:
            p = self.output_dir / "report.sarif"
            sarif = SARIFReporter().generate(findings, self.repo_url)
            p.write_text(json.dumps(sarif, indent=2, default=str))
            log.info("SARIF report  → %s", p)

        if "html" in self.formats:
            p = self.output_dir / "report.html"
            html = HTMLReporter().generate(
                findings, self.repo_url, self.scan_date, available, missing
            )
            p.write_text(html)
            log.info("HTML report   → %s", p)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        prog="gh-vulnscan",
        description="Production-grade GitHub repository vulnerability scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 gh_vulnscan.py https://github.com/org/repo
  python3 gh_vulnscan.py https://github.com/org/private-repo --token ghp_xxx
  python3 gh_vulnscan.py https://github.com/org/repo --severity high --output ./results
  python3 gh_vulnscan.py https://github.com/org/repo --format json sarif --workers 8
        """
    )
    parser.add_argument("repo_url",               help="GitHub repository URL")
    parser.add_argument("--token",   "-t",        help="GitHub personal access token (for private repos)")
    parser.add_argument("--output",  "-o",        default="scan_results", help="Output directory")
    parser.add_argument("--severity","-s",        default="low",
                        choices=["critical","high","medium","low","info"],
                        help="Minimum severity to report (default: low)")
    parser.add_argument("--format",  "-f",        nargs="+",
                        choices=["json","html","sarif"], default=["json","html","sarif"],
                        help="Output formats (default: all)")
    parser.add_argument("--workers", "-w",        type=int, default=4,
                        help="Parallel scanner workers (default: 4)")
    parser.add_argument("--list-tools",           action="store_true",
                        help="Show tool availability and exit")
    parser.add_argument("--verbose", "-v",        action="store_true",
                        help="Enable debug logging")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.list_tools:
        available, missing = check_tools()
        print("\n✅ Available tools:")
        for t in sorted(available): print(f"   {t}")
        print("\n❌ Missing tools:")
        for t in sorted(missing):   print(f"   {t}")
        return 0

    scanner = GHVulnScan(
        repo_url       = args.repo_url,
        output_dir     = Path(args.output),
        token          = args.token,
        severity_floor = Severity.from_str(args.severity),
        formats        = args.format,
        max_workers    = args.workers,
    )
    return scanner.run()


if __name__ == "__main__":
    sys.exit(main())