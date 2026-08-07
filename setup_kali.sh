#!/usr/bin/env bash
# ============================================================================
# setup_kali.sh — bootstrap recon2win on Kali Linux (Debian-based)
# ----------------------------------------------------------------------------
# What it does (idempotent — safe to re-run):
#   1. apt prerequisites (go, massdns, seclists, pipx, amass, …)
#   2. put $HOME/go/bin on PATH
#   3. `go install` the ProjectDiscovery + puredns tools
#   4. pipx-install the Python CLIs (PEP 668-safe: no system pip pollution)
#   5. update nuclei templates
#   6. create a .venv for recon2win's own deps (pyyaml, requests)
#   7. symlink Kali's SecLists into the path config.yml expects
#   8. run bootstrap.py (no args = verify only) to show what's installed
#
# Review before running — it uses `sudo apt` and `go install`.
# Run from the repo root:   bash setup_kali.sh
# ============================================================================
set -u

GOBIN="$HOME/go/bin"
log() { printf '\n\033[1;36m[*] %s\033[0m\n' "$*"; }
ok()  { printf '\033[1;32m    ✓ %s\033[0m\n' "$*"; }
warn(){ printf '\033[1;33m    ! %s\033[0m\n' "$*"; }

# ---------------------------------------------------------------------------
# 1. APT prerequisites
# ---------------------------------------------------------------------------
log "apt prerequisites"
sudo apt-get update -y
sudo apt-get install -y \
    golang-go massdns seclists git curl \
    python3-pip python3-venv pipx amass \
  || warn "some apt packages failed — continuing"

pipx ensurepath >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
# 2. Go PATH (persist + current shell)
# ---------------------------------------------------------------------------
log "PATH for go binaries"
if ! grep -qs 'go/bin' "$HOME/.bashrc"; then
    echo 'export PATH="$PATH:$HOME/go/bin"' >> "$HOME/.bashrc"
    ok "added \$HOME/go/bin to ~/.bashrc"
fi
export PATH="$PATH:$GOBIN:$HOME/.local/bin"

# ---------------------------------------------------------------------------
# 3. Go-based recon tools (ProjectDiscovery + puredns)
#    NOTE: urlfinder is a Go tool — the pip package of the same name is a
#    DIFFERENT project and will not accept the -list/-silent flags we use.
# ---------------------------------------------------------------------------
log "go install recon tools (first run downloads a lot — be patient)"
go_pkgs=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest"
    "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
    "github.com/d3mondev/puredns/v2@latest"
)
for pkg in "${go_pkgs[@]}"; do
    name="$(basename "${pkg%@*}")"
    if command -v "$name" >/dev/null 2>&1 || [ -x "$GOBIN/$name" ]; then
        ok "$name already installed"
    else
        log "  installing $name"
        go install -v "$pkg" && ok "$name" || warn "$name failed"
    fi
done

# ---------------------------------------------------------------------------
# 4. Python CLI tools via pipx (isolated, PEP 668-safe)
# ---------------------------------------------------------------------------
log "pipx recon tools"
for t in dirsearch waymore arjun xnLinkFinder; do
    if pipx list 2>/dev/null | grep -qi "$t"; then
        ok "$t already installed"
    else
        pipx install "$t" && ok "$t" || warn "$t failed (try: pipx install $t)"
    fi
done

# ---------------------------------------------------------------------------
# 5. nuclei templates
# ---------------------------------------------------------------------------
log "nuclei templates"
"$GOBIN/nuclei" -update-templates >/dev/null 2>&1 && ok "templates updated" \
    || warn "could not update nuclei templates (run 'nuclei -update-templates' later)"

# ---------------------------------------------------------------------------
# 6. recon2win Python deps in a venv (keeps system python clean)
# ---------------------------------------------------------------------------
log "python venv for recon2win"
if [ ! -d .venv ]; then
    python3 -m venv .venv && ok "created .venv"
fi
./.venv/bin/pip install -q --upgrade pip
./.venv/bin/pip install -q -r requirements.txt && ok "installed pyyaml + requests"

# ---------------------------------------------------------------------------
# 7. SecLists — symlink Kali's package into the path config.yml expects
#    (config.yml points at wordlists/SecLists/...). Falls back to a git clone.
# ---------------------------------------------------------------------------
log "wordlists (SecLists)"
mkdir -p wordlists
if [ -e wordlists/SecLists ]; then
    ok "wordlists/SecLists already present"
elif [ -d /usr/share/seclists ]; then
    ln -s /usr/share/seclists wordlists/SecLists
    ok "symlinked /usr/share/seclists -> wordlists/SecLists"
else
    warn "seclists not found; cloning (shallow)…"
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git wordlists/SecLists \
        && ok "cloned SecLists" || warn "SecLists clone failed"
fi

# ---------------------------------------------------------------------------
# 8. Verify
# ---------------------------------------------------------------------------
log "verifying toolchain"
./.venv/bin/python bootstrap.py || true

cat <<'EOF'

============================================================================
 Done. Open a NEW shell (or run: source ~/.bashrc) so $HOME/go/bin and the
 pipx bin dir are on PATH, then:

   source .venv/bin/activate
   python main.py -d example.com --dry-run        # preview
   python main.py -d example.com --config config.yml

 HackerOne target picker (optional):
   export H1_API_USERNAME=... H1_API_TOKEN=...     # or config.local.yml
   python main.py --h1-list
   python main.py --h1-program <handle>

 Notes:
   * puredns needs a resolvers list; see the puredns section in config.yml.
   * If a tool shows "not found", re-open your shell so PATH picks up
     $HOME/go/bin and ~/.local/bin (pipx).
============================================================================
EOF
