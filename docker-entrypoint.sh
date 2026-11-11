#!/bin/sh
set -eu

alembic upgrade head
if [ "${SECUREVISION_DEMO_MODE:-false}" = "true" ]; then
    python -m backend.demo_seed
fi
exec uvicorn backend.main:app --host 0.0.0.0 --port 8000
