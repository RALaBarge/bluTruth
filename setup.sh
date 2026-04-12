#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VENV=".venv"

# --- Check for uv ---
if ! command -v uv &>/dev/null; then
    echo "uv not found. Installing..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.local/bin:$PATH"
fi

# --- Create venv ---
if [ ! -d "$VENV" ]; then
    echo "Creating virtualenv..."
    uv venv "$VENV"
fi

# --- Install deps ---
echo "Installing dependencies..."
uv pip install --python "$VENV/bin/python" pyyaml dbus-next aiohttp watchfiles

# --- Install blutruth in editable mode ---
uv pip install --python "$VENV/bin/python" -e .

echo ""
echo "Done. Usage:"
echo ""
echo "  source .venv/bin/activate"
echo "  blutruth status"
echo "  blutruth collect -v"
echo ""
echo "Or without activating:"
echo ""
echo "  .venv/bin/blutruth status"
echo "  .venv/bin/blutruth collect -v"
