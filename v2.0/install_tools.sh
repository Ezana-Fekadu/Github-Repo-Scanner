#!/usr/bin/env bash
# GH-VulnScan v2.0 — Tool Installation Script
# Installs all open-source scanning tools on Debian/Ubuntu/macOS
# Run: chmod +x install_tools.sh && ./install_tools.sh

set -euo pipefail

ARCH=$(uname -m)
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; }

# ──────────────────────────────────────────────
# Python tools (always installed via pip)
# ──────────────────────────────────────────────
info "Installing Python tools..."
pip install --upgrade pip --quiet
pip install bandit pip-audit safety semgrep checkov --quiet
info "Python tools installed: bandit, pip-audit, safety, semgrep, checkov"

# ──────────────────────────────────────────────
# Trivy (Aqua Security) — primary multi-scanner
# ──────────────────────────────────────────────
install_trivy() {
  if command -v trivy &>/dev/null; then
    warn "trivy already installed ($(trivy --version | head -1))"
    return
  fi
  info "Installing trivy..."
  if [[ "$OS" == "darwin" ]]; then
    brew install aquasecurity/trivy/trivy
  else
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
      | sh -s -- -b /usr/local/bin
  fi
  info "trivy installed: $(trivy --version | head -1)"
}

# ──────────────────────────────────────────────
# Grype (Anchore) — SBOM-aware CVE scanner
# ──────────────────────────────────────────────
install_grype() {
  if command -v grype &>/dev/null; then
    warn "grype already installed ($(grype version | head -1))"
    return
  fi
  info "Installing grype..."
  curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
    | sh -s -- -b /usr/local/bin
  info "grype installed: $(grype version | head -1)"
}

# ──────────────────────────────────────────────
# OSV-Scanner (Google) — dependency scanner
# ──────────────────────────────────────────────
install_osv_scanner() {
  if command -v osv-scanner &>/dev/null; then
    warn "osv-scanner already installed"
    return
  fi
  info "Installing osv-scanner..."
  if [[ "$OS" == "darwin" ]]; then
    brew install osv-scanner
  else
    LATEST=$(curl -s https://api.github.com/repos/google/osv-scanner/releases/latest \
              | grep '"tag_name"' | cut -d'"' -f4)
    BIN_URL="https://github.com/google/osv-scanner/releases/download/${LATEST}/osv-scanner_linux_amd64"
    [[ "$ARCH" == "arm64" || "$ARCH" == "aarch64" ]] && \
      BIN_URL="https://github.com/google/osv-scanner/releases/download/${LATEST}/osv-scanner_linux_arm64"
    curl -sSfL "$BIN_URL" -o /usr/local/bin/osv-scanner
    chmod +x /usr/local/bin/osv-scanner
  fi
  info "osv-scanner installed: $(osv-scanner --version 2>&1 | head -1)"
}

# ──────────────────────────────────────────────
# Gitleaks — secrets scanner
# ──────────────────────────────────────────────
install_gitleaks() {
  if command -v gitleaks &>/dev/null; then
    warn "gitleaks already installed ($(gitleaks version))"
    return
  fi
  info "Installing gitleaks..."
  if [[ "$OS" == "darwin" ]]; then
    brew install gitleaks
  else
    LATEST=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest \
              | grep '"tag_name"' | cut -d'"' -f4)
    VER="${LATEST#v}"
    TARBALL="gitleaks_${VER}_linux_x64.tar.gz"
    [[ "$ARCH" == "arm64" || "$ARCH" == "aarch64" ]] && TARBALL="gitleaks_${VER}_linux_arm64.tar.gz"
    curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/${LATEST}/${TARBALL}" \
      | tar -xz -C /usr/local/bin gitleaks
  fi
  info "gitleaks installed: $(gitleaks version)"
}

# ──────────────────────────────────────────────
# Run installs
# ──────────────────────────────────────────────
install_trivy
install_grype
install_osv_scanner
install_gitleaks

echo ""
info "All tools installed. Verifying..."
echo ""
TOOLS=(trivy grype osv-scanner gitleaks bandit semgrep pip-audit checkov)
for t in "${TOOLS[@]}"; do
  if command -v "$t" &>/dev/null; then
    echo -e "  ${GREEN}✓${NC} $t"
  else
    echo -e "  ${RED}✗${NC} $t (not found)"
  fi
done

echo ""
info "Run the scanner:"
echo "  python3 gh_vulnscan.py https://github.com/org/repo"
echo "  python3 gh_vulnscan.py --list-tools"