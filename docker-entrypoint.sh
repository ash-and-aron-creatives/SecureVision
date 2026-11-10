#!/bin/sh
set -eu

python -m backend.demo_seed
exec uvicorn backend.main:app --host 0.0.0.0 --port 8000
