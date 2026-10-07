#!/usr/bin/env sh
# One-off verification entrypoint used by the "verify" compose service.
# 1. application build/import check
# 2. code tests
# 3. end-to-end API smoke test against the running api service
set -eu

echo "==> [1/3] application build check (byte-compile + import)"
python -m compileall -q app
python -c "import app.main; print('import ok')"

echo "==> [2/3] code tests"
python -m pytest -q

echo "==> [3/3] API smoke test against ${API_BASE_URL:-http://api:8000}"
python scripts/smoke.py

echo "VERIFY_OK"
