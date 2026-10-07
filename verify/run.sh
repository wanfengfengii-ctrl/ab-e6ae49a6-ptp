#!/bin/sh
# One-shot verification: code tests, application build check, API smoke.
# The container exit code reports the outcome.
set -eu

echo "[verify] running code tests..."
python -m pytest tests -q

echo "[verify] checking application builds..."
python -m compileall -q app tests verify
python -c "
import app.main
paths = {getattr(route, 'path', None) for route in app.main.app.routes}
assert '/api/ptp/exchanges/audit' in paths, paths
assert '/health' in paths, paths
print('[verify] application imports and routes registered')
"

echo "[verify] running API smoke test..."
python -m verify.smoke

echo "[verify] all checks passed"
