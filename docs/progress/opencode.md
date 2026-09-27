# opencode - progress log (hackathon 27 Sep 2026)

## 12:20 - ZAP fix implemented (fixes A–E)
- Done: `app/scanners/zap_scanner.py` — per-target try/except (timeout/400/url_not_found → stop scanId, record, continue; only daemon-unreachable aborts via `_daemon_alive` probe); per-target cap = budget/len(targets) min 60s enforced via `setOptionMaxScanDurationInMins` (save/restore) + poll cap+20s; `finally` stops + removes all started scans; ranking `?`+`/rest/`|`/api/` first, `#` URLs dropped (+ removed `/#/` seed); coverage gains `ascan_per_target_cap`. `start.sh` — `-silent` on both ZAP launches, health wait 120s→180s. `py_compile` + `bash -n` clean. Setup: user-space ZAP 2.17.0 (`~/.local/opt`, `ZAP_BIN` in gitignored `.env`; `sudo apt` unavailable — no terminal for password); venv + reqs installed; `~/.ZAP/plugin/*.zap` all valid; `.env` has `ALLOW_PRIVATE_TARGETS=true` (gitignored, never committed).
- State: partial — `./start.sh` booting in background; test scans pending
- Next: POST `["zap"]` scan on http://localhost:3000 ×2 back-to-back; verify ≥18/20, no orphan RUNNING scans; commit
- Decisions: kept API-key requirement, open-daemon probe, apikey redaction, SSRF guard untouched; additive coverage key only
