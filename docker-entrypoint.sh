#!/bin/sh
set -eu

: "${DATABASE_URL:?DATABASE_URL must be set to the runtime app role}"

if [ "${SECUREVISION_DEMO_MODE:-false}" = "true" ]; then
    python -m backend.demo_seed
fi
exec uvicorn backend.main:app --host 0.0.0.0 --port 8000
