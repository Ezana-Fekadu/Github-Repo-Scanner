#!/usr/bin/env python3
"""
GitHub Repo Vulnerability Scanner (GH-VulnScan)
A comprehensive scanning engine for identifying vulnerabilities, dependency issues,
missing patches, and security risks in GitHub repositories.

Authorized for penetration testing and security assessments.
"""

import os
import sys
import json
import yaml
import subprocess
import requests
import re
import zipfile
import tempfile
import shutil
from pathlib import Path
from urllib.parse import urlparse
from typing import Dict, List, Set, Tuple
import semver
from datetime import datetime, timedelta

# External tools (assumed installed or use pip requirements below)
# pip install requests PyYAML semver trufflehog semgrep safety bandit pip-audit npm-audit

class GitHubRepoScanner:
    def __init__(self, repo_url: str, output_dir: str = "scan_results"):
        self.repo_url = repo_url
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.clone_dir = self.output_dir / "repo_clone"
        self.results = {
            "scan_date": datetime.now().isoformat(),
            "repo_url": repo_url,
            "vulnerabilities": [],
            "dependency_issues": [],
            "secrets": [],
            "code_vulns": [],
            "config_issues": [],
            "summary": {}
        }
        
        # Common vulnerable patterns
        self.vuln_patterns = {
            "sql_injection": [
                r"exec\s*\(\s*request\.",
                r"execute\s*\(\s*request\.",
                r"\.query\s*\(\s*request\.",
                r"mysql_query\s*\(",
                r"pg_query\s*\("
            ],
            "xss": [
                r"document\.write\s*\(",
                r"innerHTML\s*=\s*",
                r"\.html\s*\(\s*[^)]*request",
                r"eval\s*\(",
                r"dangerouslySetInnerHTML"
            ],
            "no_rate_limit": [
                r"@app\.route\s*\(/api/",
                r"@bp\.route\s*\(/api/",
                r"flask_restful",
                r"fastapi\.\w+Api"
            ],
            "hardcoded_creds": [
                r"password\s*=\s*['\"][^'\"]{4,}",
                r"secret_key\s*=\s*['\"][^'\"]{10,}",
                r"AWS_ACCESS_KEY_ID\s*=\s*['\"][^'\"]{20,}",
                r"API_KEY\s*=\s*['\"][^'\"]{15,}"
            ],
            "command_injection": [
                r"os\.system\s*\(",
                r"subprocess\.Popen\s*\(",
                r"exec\s*\([^)]*input",
                r"eval\s*\([^)]*input"
            ]
        }

    def clone_repo(self) -> bool:
        """Clone the GitHub repository"""
        try:
            if self.clone_dir.exists():
                shutil.rmtree(self.clone_dir)
            
            repo_name = urlparse(self.repo_url).path.strip('/').split('/')[-1]
            cmd = ["git", "clone", "--depth=1", self.repo_url, str(self.clone_dir)]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                print(f"✅ Cloned repository successfully")
                return True
            else:
                print(f"❌ Failed to clone repo: {result.stderr}")
                return False
        except Exception as e:
            print(f"❌ Clone error: {e}")
            return False

    def scan_dependencies(self):
        """Scan all package managers for vulnerable dependencies"""
        dep_files = {
            "package.json": self._scan_npm,
            "package-lock.json": self._scan_npm,
            "yarn.lock": self._scan_yarn,
            "requirements.txt": self._scan_pip,
            "Pipfile": self._scan_pipenv,
            "Pipfile.lock": self._scan_pipenv,
            "pyproject.toml": self._scan_poetry,
            "Cargo.toml": self._scan_cargo,
            "composer.json": self._scan_composer,
            "Gemfile": self._scan_bundler
        }
        
        for pattern, scanner in dep_files.items():
            matches = list(self.clone_dir.rglob(pattern))
            for match in matches:
                scanner(match)

    def _scan_npm(self, file_path):
        """Scan npm/yarn dependencies"""
        try:
            subprocess.run([
                "npm", "audit", "--audit-level=high", 
                str(file_path.parent)
            ], cwd=self.clone_dir, capture_output=True)
            
            # Use npm-audit for detailed JSON output
            result = subprocess.run([
                "npm", "audit", "--json"
            ], cwd=self.clone_dir, capture_output=True, text=True)
            
            if result.returncode == 1:  # npm audit returns 1 when vulns found
                audit_data = json.loads(result.stdout)
                for vuln in audit_data.get("vulnerabilities", {}).values():
                    if vuln.get("severity") in ["high", "critical"]:
                        self.results["dependency_issues"].append({
                            "type": "npm_vulnerability",
                            "package": vuln.get("name"),
                            "version": vuln.get("version"),
                            "severity": vuln.get("severity"),
                            "fix_available": vuln.get("fixAvailable", False)
                        })
        except:
            pass

    def _scan_pip(self, file_path):
        """Scan Python dependencies"""
        try:
            # Safety check
            result = subprocess.run([
                "safety", "check", "-r", str(file_path)
            ], capture_output=True, text=True)
            
            if "VULNERABILITIES FOUND" in result.stdout:
                lines = result.stdout.split("\n")
                for line in lines:
                    if "VULNERABLE" in line:
                        parts = line.split()
                        pkg = parts[0]
                        self.results["dependency_issues"].append({
                            "type": "pip_vulnerability",
                            "package": pkg,
                            "tool": "safety"
                        })
            
            # pip-audit
            subprocess.run(["pip-audit", str(file_path)], capture_output=True)
        except:
            pass

    def _scan_cargo(self, file_path):
        """Scan Rust dependencies"""
        try:
            result = subprocess.run([
                "cargo", "audit"
            ], cwd=file_path.parent, capture_output=True, text=True)
            
            if result.returncode != 0:
                self.results["dependency_issues"].append({
                    "type": "cargo_vulnerability",
                    "file": str(file_path)
                })
        except:
            pass

    def scan_secrets(self):
        """Scan for secrets and API keys"""
        try:
            result = subprocess.run([
                "trufflehog", "filesystem", str(self.clone_dir)
            ], capture_output=True, text=True, timeout=600)
            
            if result.stdout.strip():
                for line in result.stdout.split("\n"):
                    if "LOW" not in line and "MEDIUM" not in line:  # Focus on HIGH/CRITICAL
                        self.results["secrets"].append({
                            "tool": "trufflehog",
                            "finding": line.strip()
                        })
        except Exception as e:
            print(f"Trufflehog scan failed: {e}")

    def scan_static_code(self):
        """Static code analysis for vulns"""
        # Bandit for Python
        py_files = list(self.clone_dir.rglob("*.py"))
        if py_files:
            result = subprocess.run([
                "bandit", "-r", str(self.clone_dir), "-f", "json", "-o", 
                str(self.output_dir / "bandit.json")
            ], capture_output=True)
            
            try:
                with open(self.output_dir / "bandit.json") as f:
                    data = json.load(f)
                    for issue in data.get("results", []):
                        if issue["issue_severity"] in ["HIGH", "MEDIUM"]:
                            self.results["code_vulns"].append({
                                "tool": "bandit",
                                "type": issue["issue_type"],
                                "severity": issue["issue_severity"],
                                "location": issue["location"]
                            })
            except:
                pass

        # Semgrep for multi-language
        try:
            subprocess.run([
                "semgrep", "scan", "--config=auto", 
                "--output=scan_results/semgrep.json",
                str(self.clone_dir)
            ], check=True)
            
            with open(self.output_dir / "semgrep.json") as f:
                data = json.load(f)
                for finding in data.get("results", []):
                    self.results["code_vulns"].append({
                        "tool": "semgrep",
                        "rule": finding["rule_id"],
                        "severity": finding["extra"]["severity"],
                        "location": finding["location"]
                    })
        except:
            pass

    def regex_pattern_scan(self):
        """Custom regex scanning for common vulns"""
        code_files = []
        for ext in ["*.py", "*.js", "*.php", "*.java", "*.rb", "*.go"]:
            code_files.extend(list(self.clone_dir.rglob(ext)))
        
        for file_path in code_files[:50]:  # Limit to prevent timeout
            try:
                with open(file_path, 'r', errors='ignore') as f:
                    content = f.read()
                    
                for vuln_type, patterns in self.vuln_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            self.results["vulnerabilities"].append({
                                "type": vuln_type,
                                "file": str(file_path),
                                "pattern_matched": pattern,
                                "confidence": "medium"
                            })
            except:
                continue

    def check_config_files(self):
        """Check dangerous configurations"""
        configs = {
            ".env": ["SECRET_KEY", "DATABASE_URL", "AWS_SECRET"],
            "docker-compose.yml": ["ports: - \"22:", "ports: - \"3306:"],
            ".github/workflows/*.yml": ["permissions: write-all"]
        }
        
        for pattern, keywords in configs.items():
            matches = list(self.clone_dir.rglob(pattern))
            for match in matches:
                try:
                    with open(match, 'r') as f:
                        content = f.read()
                    
                    for keyword in keywords:
                        if keyword in content:
                            self.results["config_issues"].append({
                                "type": "dangerous_config",
                                "file": str(match),
                                "issue": keyword
                            })
                except:
                    continue

    def generate_report(self):
        """Generate comprehensive report"""
        summary = {
            "total_vulns": len(self.results["vulnerabilities"]),
            "dep_issues": len(self.results["dependency_issues"]),
            "secrets_found": len(self.results["secrets"]),
            "code_vulns": len(self.results["code_vulns"]),
            "config_issues": len(self.results["config_issues"]),
            "risk_score": "LOW" if len(self.results["vulnerabilities"]) == 0 else "MEDIUM"
        }
        
        self.results["summary"] = summary
        
        report_path = self.output_dir / "comprehensive_report.json"
        with open(report_path, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        # HTML summary
        html_report = self._generate_html_report()
        with open(self.output_dir / "report.html", 'w') as f:
            f.write(html_report)
        
        print(f"✅ Full report generated: {report_path}")
        print(f"📊 Summary: {summary}")

    def _generate_html_report(self) -> str:
        """Generate HTML report"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head><title>GH-VulnScan Report</title>
        <style>
            body {{ font-family: Arial; margin: 40px; }}
            .critical {{ background: #ffebee; border-left: 5px solid #f44336; }}
            .high {{ background: #fff3e0; border-left: 5px solid #ff9800; }}
            .summary {{ background: #e3f2fd; padding: 20px; border-radius: 8px; }}
        </style>
        </head>
        <body>
            <h1>🚨 GH-VulnScan Report</h1>
            <p><strong>Repository:</strong> {self.repo_url}</p>
            <p><strong>Scan Date:</strong> {self.results['scan_date']}</p>
            
            <div class="summary">
                <h2>📊 Executive Summary</h2>
                <p><strong>Critical Issues:</strong> {self.results['summary'].get('total_vulns', 0)}</p>
                <p><strong>Dependency Issues:</strong> {self.results['summary'].get('dep_issues', 0)}</p>
                <p><strong>Secrets Exposed:</strong> {self.results['summary'].get('secrets_found', 0)}</p>
                <p><strong>Overall Risk:</strong> <span style="font-size: 1.5em;">{self.results['summary']['risk_score']}</span></p>
            </div>
            
            <h2>🔥 Critical Vulnerabilities</h2>
            <div class="critical">{len([v for v in self.results['vulnerabilities']])} found</div>
            
            <h2>📦 Dependency Issues</h2>
            <pre>{json.dumps(self.results['dependency_issues'], indent=2)}</pre>
        </body>
        </html>
        """
        return html

    def run_full_scan(self):
        """Execute complete vulnerability scan"""
        print(f"🔍 Starting comprehensive scan of {self.repo_url}")
        
        if not self.clone_repo():
            return False
        
        print("📦 Scanning dependencies...")
        self.scan_dependencies()
        
        print("🔑 Scanning for secrets...")
        self.scan_secrets()
        
        print("🐛 Static code analysis...")
        self.scan_static_code()
        
        print("🎯 Pattern-based vulnerability scan...")
        self.regex_pattern_scan()
        
        print("⚙️ Configuration analysis...")
        self.check_config_files()
        
        print("📋 Generating report...")
        self.generate_report()
        
        print("✅ Scan complete! Check scan_results/ directory")
        return True


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 gh-vulnscan.py <github-repo-url>")
        print("Example: python3 gh-vulnscan.py https://github.com/org/repo")
        sys.exit(1)
    
    scanner = GitHubRepoScanner(sys.argv[1])
    scanner.run_full_scan()


if __name__ == "__main__":
    main()
