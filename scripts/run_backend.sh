#!/usr/bin/env bash
# Launch the Yap Kokoro backend. Used by the app and for manual dev runs.
# Creates the venv + installs deps on first run, then serves.
set -euo pipefail
umask 077

# Keep the sidecar independent of user site-packages and imports from PYTHONPATH.
unset PYTHONPATH PYTHONHOME PYTHONSTARTUP
export PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND="$HERE/backend"
SUPPORT="$HOME/Library/Application Support/Yap"
VENV="${YAP_VENV:-${PARLEY_VENV:-$SUPPORT/venv}}"
PORT="${YAP_PORT:-${PARLEY_PORT:-8766}}"
MODELS_DIR="${YAP_MODELS_DIR:-${PARLEY_MODELS_DIR:-$SUPPORT/models}}"
mkdir -p "$SUPPORT"

# Call the venv's own python, never `activate` + bare `python`: activate hardcodes
# the path the venv was created at, so a venv moved by the Parley -> Yap rename
# put a dead directory first on PATH and `python` silently became whatever the
# shell found next (Anaconda, with no kokoro_onnx).
PY="$VENV/bin/python"
if [ ! -x "$PY" ]; then
  echo "[yap] creating venv..."
  if command -v uv >/dev/null 2>&1; then
    uv venv --python 3.12 "$VENV"
    uv pip install --require-hashes --only-binary=:all: --python "$PY" -r "$BACKEND/requirements.txt"
  else
    python3 -I -B -m venv "$VENV"
    "$PY" -I -B -m pip install --isolated --require-hashes --only-binary=:all: -r "$BACKEND/requirements.txt"
  fi
fi

export YAP_MODELS_DIR="$MODELS_DIR"
exec "$PY" -B -E -s "$BACKEND/server.py" --port "$PORT" --models-dir "$MODELS_DIR" \
     --provider "${YAP_PROVIDER:-${PARLEY_PROVIDER:-auto}}" "$@"
