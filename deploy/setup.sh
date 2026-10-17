#!/usr/bin/env bash
# One-shot setup on a fresh Linux box (run from the project root):  bash deploy/setup.sh
set -euo pipefail
python3 --version
python3 -m venv venv
. venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt || { echo "Full install failed -> falling back to requirements-core.txt (CLI only)"; pip install -r requirements-core.txt; }
[ -f .env ] || cp .env.example .env
python data/generate_synthetic_data.py
python -m ai.model_training
python -m unittest discover -s tests -t . -v 2>&1 | tail -15
echo "Setup finished. Start the dashboard with:  streamlit run app.py --server.address 127.0.0.1 --server.port 8501"
