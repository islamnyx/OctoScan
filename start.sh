#!/usr/bin/env bash
# OctoScan one-click launcher: starts the ZAP daemon (authenticated) and the
# FastAPI app together. Reuses either one if it is already healthy.
#
# Usage:
#   ./start.sh              # start ZAP + app (foreground, Ctrl+C stops both)
#   ./start.sh --zap-only   # start only the ZAP daemon
#   ./start.sh --app-only   # start only the app (codebase scans work; web scans need ZAP)
#   ./start.sh --help       # this message
#
# Config comes from .env (see .env.example). A missing ZAP_API_KEY is
# generated once with openssl and appended to .env so the daemon and the
# app always share the same key.
set -uo pipefail

cd "$(dirname "$0")"

APP_ONLY=0
ZAP_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --app-only) APP_ONLY=1 ;;
    --zap-only) ZAP_ONLY=1 ;;
    -h|--help)
      sed -n '2,11p' "$0"
      exit 0 ;;
    *) echo "Unknown flag: $arg (try --help)" >&2; exit 1 ;;
  esac
done

# Load .env so KEY/ports/bins are shared with the app's own config.
if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
fi

APP_HOST="${APP_HOST:-127.0.0.1}"
APP_PORT="${APP_PORT:-8000}"
ZAP_PORT="${ZAP_PORT:-8090}"
ZAP_BIN="${ZAP_BIN:-/usr/share/zaproxy/zap.sh}"
ZAP_JAR="${ZAP_JAR:-/usr/share/zaproxy/zap-2.17.0.jar}"
ZAP_API_KEY="${ZAP_API_KEY:-}"

mkdir -p logs data/scans data/repos

# A missing/placeholder key breaks every web scan (the daemon and the app
# must share it), so mint one once and persist it.
if [ -z "$ZAP_API_KEY" ] || [ "$ZAP_API_KEY" = "<your-long-random-value-here>" ]; then
  ZAP_API_KEY="$(openssl rand -hex 32)"
  if grep -q "^ZAP_API_KEY=" .env 2>/dev/null; then
    sed -i "s|^ZAP_API_KEY=.*|ZAP_API_KEY=$ZAP_API_KEY|" .env
  else
    printf '\nZAP_API_KEY=%s\n' "$ZAP_API_KEY" >> .env
  fi
  echo "Minted new ZAP_API_KEY and saved it to .env"
fi

ZAP_URL="http://127.0.0.1:${ZAP_PORT}"
APP_URL="http://${APP_HOST}:${APP_PORT}"
ZAP_PID=""
APP_PID=""

# Kill anything this script started (used on error paths and Ctrl+C).
kill_started() {
  [ -n "$APP_PID" ] && kill "$APP_PID" 2>/dev/null
  [ -n "$ZAP_PID" ] && kill "$ZAP_PID" 2>/dev/null
}

cleanup() {
  echo ""
  echo "Stopping OctoScan…"
  kill_started
  exit 0
}
trap cleanup INT TERM

fail() {
  echo "ERROR: $1" >&2
  kill_started
  exit 1
}

zap_healthy() {
  curl -s -m 3 "${ZAP_URL}/JSON/core/view/version/?apikey=${ZAP_API_KEY}" \
    | grep -q '"version"'
}

app_healthy() {
  curl -s -m 3 -o /dev/null -w "%{http_code}" "${APP_URL}/health" \
    | grep -q "200"
}

start_zap() {
  if zap_healthy; then
    echo "ZAP already healthy on ${ZAP_URL} — reusing it"
    return 0
  fi
  if curl -s -m 2 -o /dev/null "${ZAP_URL}/JSON/core/view/version/"; then
    echo "ERROR: something answers on ${ZAP_URL} without our API key." >&2
    echo "A foreign ZAP daemon may hold the port — stop it first, then retry." >&2
    return 1
  fi
  echo "Starting ZAP daemon (log: logs/zap-run.log)…"
  # A stale "clean" session from a previous run makes -newsession fail
  # ("file already exists") and leaves the daemon API-less — clear it first.
  rm -f "${HOME}/.ZAP/session/clean.session"* 2>/dev/null
  if [ -x "$ZAP_BIN" ]; then
    nohup "$ZAP_BIN" -daemon -port "$ZAP_PORT" -host 127.0.0.1 \
      -newsession clean \
      -config "api.key=${ZAP_API_KEY}" \
      -config api.disablekey=false \
      -config autoupdate.checkOnStart=false \
      -config callhome.callHome=false \
      > logs/zap-run.log 2>&1 &
  elif [ -f "$ZAP_JAR" ]; then
    nohup java -Xmx4g -jar "$ZAP_JAR" -daemon -port "$ZAP_PORT" -host 127.0.0.1 \
      -newsession clean \
      -config "api.key=${ZAP_API_KEY}" \
      -config api.disablekey=false \
      -config autoupdate.checkOnStart=false \
      -config callhome.callHome=false \
      > logs/zap-run.log 2>&1 &
  else
    echo "ERROR: no ZAP launcher found (tried $ZAP_BIN and $ZAP_JAR)." >&2
    echo "Set ZAP_BIN or ZAP_JAR in .env (see .env.example)." >&2
    return 1
  fi
  ZAP_PID="$!"
  for _ in $(seq 1 60); do
    zap_healthy && { echo "ZAP healthy on ${ZAP_URL}"; return 0; }
    sleep 2
  done
  echo "ERROR: ZAP did not become healthy in ~120s — see logs/zap-run.log" >&2
  return 1
}

start_app() {
  if app_healthy; then
    echo "App already healthy on ${APP_URL} — reusing it"
    return 0
  fi
  echo "Starting app (log: logs/app-run.log)…"
  nohup ./.venv/bin/uvicorn app.main:app --host "$APP_HOST" --port "$APP_PORT" \
    > logs/app-run.log 2>&1 &
  APP_PID="$!"
  for _ in $(seq 1 30); do
    app_healthy && { echo "App healthy on ${APP_URL}"; return 0; }
    sleep 2
  done
  echo "ERROR: app did not become healthy in ~60s — see logs/app-run.log" >&2
  return 1
}

if [ "$APP_ONLY" -eq 0 ]; then
  start_zap || fail "ZAP did not start — see logs/zap-run.log"
fi
if [ "$ZAP_ONLY" -eq 0 ]; then
  start_app || fail "app did not start — see logs/app-run.log"
fi

echo ""
echo "OctoScan is up:"
[ "$ZAP_ONLY" -eq 0 ] && echo "  Dashboard: ${APP_URL}"
[ "$APP_ONLY" -eq 0 ] && echo "  ZAP API:   ${ZAP_URL}"
echo "  Logs:      logs/app-run.log, logs/zap-run.log"
if [ -z "$ZAP_PID$APP_PID" ]; then
  echo "Nothing to keep running (everything was already up) — exiting."
  exit 0
fi
echo "Press Ctrl+C to stop."
wait
