#!/usr/bin/env bash
set -euo pipefail
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
SERVE_FRONTEND=1 uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
