# Team board: who owns what (edit this first thing at 11:15)

Rule: one owner per file. Only the owner edits it. Everyone else asks via "Requests".

| Person | Tool | Branch | Owns (files) | Task |
|---|---|---|---|---|
| Islam | Claude Code | hack/islam-core | app/ai_fix.py, app/models.py, app/main.py | AI engine + API contract + merges |
| ? | Antigravity | hack/?-ui | app/static/fix.js, app/static/scan.html | Dashboard UI for AI results |
| ? | OpenCode | hack/?-eval | eval/*, docs/results.md | Labelled test set + measured numbers |
| ? | any | hack/?-docs | docs/project-card.md, docs/disclosure.md, video | Submission + 90 s video |

## API contract (frozen at 11:45; change only via integrator)
- `POST /api/repo-scans/{id}/ai-fix` -> starts AI fix job for top findings
- `GET  /api/repo-scans/{id}/ai-fix` -> `[{finding_id, verdict, confidence, reasoning, patch, verified, model, latency_ms}]`
  (the UI person builds against a fake JSON file with this shape until the endpoint is merged)

## Sync points (integrator merges into main, everyone pulls)
- 11:45  contract + skeletons merged
- 13:00  first working vertical slice
- 15:30  feature freeze (merge everything, run smoke test)
- 17:00  final: submission links checked

## Requests (need a change in a file you don't own? write it here)
- n3yx-batch2 (hack/n3yx-scan-quality): `normalize.py` CONCEPT_SEVERITY + clean_cwe + shortest-URL rep + correlate() chains + CVSS estimates in prioritize; `zap_scanner.py` SQLi evidence/fix + ascan re-rank + verified OpenAPI import w/ coverage; `nikto_scanner.py` HSTS-on-HTTP drop + generic catch-all; `nuclei_scanner.py` cwe cleanup; `sensitive.py` +5 probes + _is_listing + dir-index on discovered URLs; `store.py` auth sidecar; `main.py` export excludes auth (1 line). `tests/test_scan_quality2.py` (12 tests). No owner files touched except the 1-line export guard.
- n3yx-controls (hack/n3yx-scan-quality): strict Pause/Finish — NEW `ScanStopped` + `stop_check`/`_check_stop` in `app/scanners/base.py`; `pipeline.py` wires hook + catches (sequential/parallel) via `_stop_now` (user stop logged to activity, never counted as error); ZAP spider/ascan/ajax/tree waits poll the hook (existing finally blocks stop+remove orphan scans); `status.html` shows instant stopping feedback. `tests/test_controls.py` (5 tests). No owner files touched.
- n3yx-scanquality (hack/n3yx-scan-quality): `zap_scanner.py` CWE guard (b730b65 idiom) + JUNK_INFO_TITLES drop; `testssl_scanner.py` HTTP→[]; `nmap_scanner.py` target-port skip; `nuclei_scanner.py` NUCLEI_SEVERITY_OVERRIDES (prometheus-metrics→low); NEW `tests/test_scan_noise.py` (8 tests). No owner files touched (models.py/main.py intact).
- n3yx-visuals (hack/n3yx-scan-quality): rewrote `frontend/src/components/Visuals.tsx` (was TODO placeholders) — AttackRadar now a real recharts RadarChart fed by latest-10 findings per surface + coverage sub-lines; VulnSunburst a nested-pie sunburst (inner severity, outer scanner→severity) reusing brand SEV_COLORS; 1-line `App.tsx` prop wire. No new deps (Nivo skipped — heavy; recharts already in stack).
- n3yx-compare (hack/n3yx-scan-quality): NEW `frontend/src/components/Compare.tsx` (baseline→current diff: severity Δ, per-scanner table, fixed/new/persisting, risk-improvement %); minimal wires — `Sidebar.tsx` NavId +1 link (`compare`, 05), `App.tsx` import + section. No backend changes; pure client-side over loaded web+repo jobs.
- n3yx-apk-bridge (hack/n3yx-scan-quality): touched Islam-owned `app/main.py` with user approval — 6-line guarded mount only (`try: from app.apk import router; app.include_router`). Router + schemas live in NEW `app/apk.py` (no models.py changes). Frontend: NEW `frontend/src/components/MobileApk.tsx`, 2-line wire in `ScanTabs.tsx` (import + placeholder→`<MobileApk/>`). Please keep the mount on merge; all APK logic stays in `app/apk.py`.
- n3yx-cleanup: kept `ScanAuth` (app/models.py, used in base.py + ScanJob fields), `AnalyzeReply` (app/ai.py, used at call_json), `BaseScanner` re-export (scanners/__init__.py `__all__`) — audit flagged them but verification shows they are live. (`HttpUrl` in main.py removed by Islam directly.)
