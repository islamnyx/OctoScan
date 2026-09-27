#!/usr/bin/env bash
# Single source of truth for the OctoScan console UI.
#
#   frontend/        = REAL source (React + Tailwind, octoscan-aura)
#   app/static/      = SERVED dir (FastAPI mounts /static; /assets is mapped
#                      to app/static/assets in app/main.py)
#
# The console shell (app/static/index.html) + app/static/assets/* are BUILD
# OUTPUT. Never hand-edit them. Legacy hand-written pages that the React
# router does not cover (scan.html, status.html) live in app/static/ too and
# are edited in place.
#
# Usage: ./build.sh   (from frontend/)
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -d node_modules ]; then
  echo " installing frontend deps (first run only)..."
  npm install
fi

npm run build   # tsc -b && vite build -> dist/

# Sync ONLY generated files into the served dir.
cp dist/index.html ../app/static/index.html
rm -rf ../app/static/assets
cp -r dist/assets ../app/static/assets

echo " synced: app/static/index.html + app/static/assets/"
echo " restart the API (./start.sh) and open http://127.0.0.1:8000"
