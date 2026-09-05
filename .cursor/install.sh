#!/usr/bin/env bash
#
# Cloud Agent install step for the knowledge-work-plugins repository.
#
# This repo is primarily a file-based Claude plugin marketplace (markdown +
# JSON, no build step). This script prepares the small amount of tooling the
# dev workflow needs:
#   1. jq + curl  — used to validate marketplace/plugin JSON and probe MCP URLs
#   2. A Python 3.11 virtualenv (.venv) for the one component that ships
#      runnable code: the bio-research "instrument-data-to-allotrope" skill.
#
# The script is idempotent: it can run repeatedly against cached state.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

log() { printf '\n\033[1;34m==> %s\033[0m\n' "$1"; }

# --- 1. Core validation tooling (jq, curl) ---------------------------------
log "Ensuring jq and curl are installed"
missing=()
command -v jq   >/dev/null 2>&1 || missing+=(jq)
command -v curl >/dev/null 2>&1 || missing+=(curl)
if [[ ${#missing[@]} -gt 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then SUDO=sudo; else SUDO=""; fi
  $SUDO apt-get update -qq && $SUDO apt-get install -y -qq "${missing[@]}"
fi
echo "jq $(jq --version 2>/dev/null) / $(curl --version 2>/dev/null | head -1)"

# --- 2. Quick sanity check of the marketplace manifest ---------------------
log "Validating marketplace.json parses"
jq -e '.name and (.plugins|type=="array")' .claude-plugin/marketplace.json >/dev/null
echo "marketplace.json OK ($(jq '.plugins|length' .claude-plugin/marketplace.json) plugins)"

# --- 3. Python venv for the bio-research allotrope skill -------------------
# allotropy needs a native pandas wheel; pandas is not built from source here,
# so we use uv to provision a pinned Python 3.11 interpreter (pandas 2.2.x has
# no cp312 wheel) and a project-local virtualenv.
log "Setting up Python 3.11 virtualenv (.venv) for bio-research scripts"
export PATH="$HOME/.local/bin:$PATH"
if ! command -v uv >/dev/null 2>&1; then
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:$PATH"
fi

uv python install 3.11
if [[ ! -x .venv/bin/python ]]; then
  uv venv --python 3.11 .venv
fi
uv pip install --python .venv/bin/python \
  -r bio-research/skills/instrument-data-to-allotrope/requirements.txt

echo "Python: $(.venv/bin/python --version)"
.venv/bin/python -c "import pandas, allotropy, openpyxl, pdfplumber; print('deps OK — pandas', pandas.__version__)"

log "Install complete"
echo "Activate the Python env with:  source .venv/bin/activate"
