#!/usr/bin/env bash
# Sets up retk on Debian/Ubuntu (including WSL). Installs the system tools
# the pipelines call out to, plus a Python venv with the pip dependencies.
# Every tool here is optional at runtime — retk degrades gracefully and
# notes what's missing in its report — but installing all of this gets you
# the full experience.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$REPO_DIR/.venv"

echo "==> Installing system packages (apt)..."
sudo apt-get update -qq
sudo apt-get install -y \
    file binutils radare2 binwalk upx-ucl yara default-jre python3-venv python3-pip

echo "==> Creating venv at $VENV_DIR"
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --quiet --upgrade pip
"$VENV_DIR/bin/pip" install --quiet -r "$REPO_DIR/requirements.txt"

echo "==> Fetching capa's rule pack (needed for --malware capability extraction)"
CAPA_RULES_DIR="$REPO_DIR/.capa-rules"
if [ ! -d "$CAPA_RULES_DIR" ]; then
    CAPA_VER="$("$VENV_DIR/bin/pip" show flare-capa 2>/dev/null | awk '/^Version/{print $2}')"
    curl -sSL -o /tmp/capa-rules.zip \
        "https://github.com/mandiant/capa-rules/archive/refs/heads/master.zip" \
        && unzip -q /tmp/capa-rules.zip -d /tmp/capa-rules-extract \
        && mv /tmp/capa-rules-extract/capa-rules-master "$CAPA_RULES_DIR" \
        && rm -rf /tmp/capa-rules.zip /tmp/capa-rules-extract \
        || echo "    (capa-rules download failed — capa will still run if you pass -r <rules-dir> yourself)"
fi

cat <<EOF

==> Core install done. Optional extras (install manually if you want them):
    - jadx (Android Java decompiler):   https://github.com/skylot/jadx/releases
    - apktool (Android resource/smali): https://apktool.org/
    - Ghidra (deep binary decompiler):  https://github.com/NationalSecurityAgency/ghidra/releases
    - nasm/pwntools/angr etc. are NOT required by retk itself; they're for
      manual follow-up once retk's report points you at something interesting.

Activate the venv and run retk:
    source "$VENV_DIR/bin/activate"
    export CAPA_RULES_DIR="$CAPA_RULES_DIR"   # picked up automatically by --malware
    python retk_cli.py analyze /path/to/target

iOS note: full Mach-O decompilation needs macOS tooling (class-dump, otool)
and isn't available here on Linux/WSL — the ios pipeline still extracts
Info.plist metadata and strings, just at reduced fidelity. See README.md.
EOF
