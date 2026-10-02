# opencode - progress log (hackathon 27 Sep 2026)

## 12:20 - ZAP fix implemented (fixes A–E)
- Done: `app/scanners/zap_scanner.py` — per-target try/except (timeout/400/url_not_found → stop scanId, record, continue; only daemon-unreachable aborts via `_daemon_alive` probe); per-target cap = budget/len(targets) min 60s enforced via `setOptionMaxScanDurationInMins` (save/restore) + poll cap+20s; `finally` stops + removes all started scans; ranking `?`+`/rest/`|`/api/` first, `#` URLs dropped (+ removed `/#/` seed); coverage gains `ascan_per_target_cap`. `start.sh` — `-silent` on both ZAP launches, health wait 120s→180s. `py_compile` + `bash -n` clean. Setup: user-space ZAP 2.17.0 (`~/.local/opt`, `ZAP_BIN` in gitignored `.env`; `sudo apt` unavailable — no terminal for password); venv + reqs installed; `~/.ZAP/plugin/*.zap` all valid; `.env` has `ALLOW_PRIVATE_TARGETS=true` (gitignored, never committed).
- State: partial — `./start.sh` booting in background; test scans pending
- Next: POST `["zap"]` scan on http://localhost:3000 ×2 back-to-back; verify ≥18/20, no orphan RUNNING scans; commit
- Decisions: kept API-key requirement, open-daemon probe, apikey redaction, SSRF guard untouched; additive coverage key only

## 14:37 - octoscan-ui skill created
- Done: new file `.opencode/skills/octoscan-ui/SKILL.md` (brand tokens, typography stack, component rules for the React dashboard)
- State: works (file written verbatim as requested; no existing files touched)
- Next: none — skill available for UI work
- Decisions: new file only, no ownership conflicts per docs/TEAM.md

## 14:45 - octoscan-ui corrections (skill-driven refactor)
- Done: `frontend/src/components/Dashboard.tsx` (KPI metrics 28px Space Grotesk, donut center total overlay, LiveFeed rewritten as 8-item scrollable console with #4ADE80/#ff6a2c status colors), `App.tsx` (console body max-h-170px scroll), `ui/controls.tsx` (muted/info badges border-only), `History.tsx` (accent row hover)
- State: works — `tsc -b && vite build` clean, dev server 200 on :5173
- Next: visual check in browser; replace Visuals placeholders with real Recharts radar/sunburst
- Decisions: FAILED maps to #ff6a2c per request; white fills removed entirely (borders were already exact)

## 14:55 - logo integrated + static sync
- Done: `Sidebar.tsx`/`Topbar.tsx` brand marks now render `/static/logo.png` (Bug/"O" placeholders removed); rebuilt and re-synced `dist/` -> `app/static/` (index.html + hashed assets, stale hashes pruned)
- State: works — build clean, vite 200, logo 200 via proxy; note `/assets/*` still 404s under FastAPI (needs base fix, user deferred)
- Next: visual check in browser
- Decisions: logo (orange octo mark, transparent bg) sits directly on dark surfaces, no accent box

## 15:00 - repo synced, dashboard pushed
- Done: committed 90d61e1 (React dashboard, static build, skill); new SSH key `~/.ssh/octoscan_github` (user added pub to GitHub); pushed `web_scanners`, now 0 ahead / 0 behind
- State: works — push accepted (84103f3..90d61e1)
- Next: integrator merges to main at sync point
- Decisions: pushed via explicit SSH URL (remote still points at https); GitHub notes repo moved to `islamnyx/OctoScan` — future pushes should use the new location

## 15:10 - full stop, relaunch from zero, green test pass
- Done: killed all (uvicorn/vite/ZAP/juice), ports verified free, relaunched all four from zero (app PID 334166, vite PID 334219, ZAP 2.17.0 ~8s, juice 200)
- State: works — live headers scan 66a90857 completed, 4 findings, gate PASSED; vite proxy, repo endpoint, dash/logo/api-root all 200; Juice serves real OWASP page
- Next: none — stack verified end to end
- Decisions: no full web scan demoed (20-min rule); headers-only scan proves pipeline

## 15:45 - main sync complete
- Done: resolved rebase conflicts across README/.env/.gitignore, kept the merged project state, rebased local main onto the latest upstream history, and pushed the result to origin/main
- State: works — clean branch, `git status --short --branch` shows `## main...origin/main [ahead 13]` before the push, then push succeeded
- Next: none; branch is synced and published to main
- Decisions: kept the final merged README and removed the stale local `.claude` config to preserve the current clean branch state

## 11:30 - Professional cleanup (hack/n3yx-cleanup)
- Done: removed root clutter (brand identity.zip 5M, codebase-map-clean.html, skills-lock.json), deleted dead app/scanners/stubs.py (no imports, shadowed by source_*), removed dead repo_file_path() + Path/ROOT imports in app/ai.py, removed dead imports AgentFix (ai_agent), Callable (repo_pipeline), json (store); deleted empty tests/__init__.py; archived docs/AI-PLAN/HANDOFF/NEXT + TO_DO.md to docs/archive/; pycache + logs cleaned; TEAM.md request added for main.py HttpUrl (Islam-owned, untouched)
- State: works — 327 pytest pass, no ownership violations (main.py/models.py/ai_fix.py untouched; ScanAuth/AnalyzeReply/BaseScanner kept after verification they are live)
- Next: integrator merges hack/n3yx-cleanup; follow-ups left out: split long files (zap 696/main 679/agent 622/review 613), toolkit wrapper merges, test-fixtures prune, frontend rebuild
- Decisions: skills (.agents/.opencode/.claude) kept — not clutter; app/static/assets kept (tracked build output); audit corrections recorded in TEAM.md requests

## 11:45 - Cleanup merged to main (integrator override by n3yx)
- Done: merged hack/n3yx-cleanup (e71b3d0 + 6d75dfe) into main, pushed origin/main (25e8c4d..6d75dfe); 327 pytest pass on merged main
- State: works — main in sync with origin/main, branch hack/n3yx-cleanup kept (not deleted, integrator decides)
- Next: remote CI (security.yml gitleaks + pip-audit) runs on push — check GitHub Actions; repo moved to islamnyx/OctoScan, update remote URL
- Decisions: user overrode TEAM.md integrator rule (Islam merges) with explicit typed approval; merge was fast-forward, no conflicts

## 19:20 - APK bridge linked into dashboard + main app (hack/n3yx-scan-quality)
- Done: NEW `app/apk.py` (APIRouter `/api/apk/scans` — multipart .apk/.ipa/.aab upload preserves filename, intake via scan_toolkit engagements, static stage in bg thread intake→scanning→reviewing, list/detail with tools/notes/errors + Finding rows); NEW `frontend/src/components/MobileApk.tsx` (upload + recent + detail), wired into `ScanTabs.tsx` pane-apk placeholder (import + 1 line); guarded 6-line mount in `app/main.py` (try/except, TEAM.md request logged); NEW `tests/test_apk_bridge.py` (reject non-APK, upload/list/detail); rebuilt frontend (`build.sh`, bundle contains Mobile APK) + restarted API
- State: works — 329 pytest pass (327 + 2 new); live: `GET /api/apk/scans` 200, fake-APK upload → reviewing/partial with honest tool errors, filename kept, test engagements cleaned; dashboard 200, Juice 200, ZAP 2.17.0
- Next: upload a REAL APK for true static signal (apktool/jadx/semgrep); add SCA/dynamic/API tabs + LLM Finding rows; Islam to keep the `app/apk.py` mount on merge
- Decisions: no `app/models.py` changes; 300 MB cap; scope auto-confirmed on dashboard upload; static errors degrade to partial, never fake findings

## 19:35 - Compare-runs panel in left sidebar (hack/n3yx-scan-quality)
- Done: NEW `frontend/src/components/Compare.tsx` — pick baseline + current from web/repo jobs; severity A-vs-B table with Δ, per-scanner (each test) table, fixed/new/persisting lists, risk-improvement % (10·crit+5·high+2·med+1·low+0.5·info); left-sidebar NavId `compare` (05) + `App.tsx` section; fixed `test_apk_bridge.py` hermeticity (db_url override — tests no longer leak acme rows into real toolkit.db); rebuilt + synced bundle
- State: works — tsc clean, build 3.5s, bundle contains compare strings, dashboard 200, API ok, 2 apk tests pass, `/api/apk/scans` back to []
- Next: include APK engagements in compare + same-target shortcut filter; commit slice
- Decisions: pure client-side diff (no backend), finding identity = scanner｜title｜location; tests mutate+restore cached settings, cache_clear after

## 19:45 - Attack Radar + Sunburst fed with real data (hack/n3yx-scan-quality)
- Done: `Visuals.tsx` rewritten — AttackRadar is a real recharts RadarChart over latest-10 web+repo findings (Ports=nmap, TLS=testssl, Headers=headers, Web vulns=zap+nikto+sensitive-files, CVEs=nuclei+osv/cve-flagged, Secrets=gitleaks) with count tiles + scanner-coverage sub-lines; VulnSunburst is a nested-pie sunburst (inner severity, outer scanner→severity slices, severity brand colors) with scanner legend; `App.tsx` passes web+repo props; both TODOs removed
- State: works — tsc clean, build 3.5s, bundle verified (TODO strings gone), dashboard 200, apk tests still pass, toolkit DB clean
- Next: empty states show until real scans land; consider same-target filter for radar window
- Decisions: Nivo skipped (heavy new dep, banned pattern) — recharts nested pies give the sunburst read with zero installs; CVE axis counts nuclei/osv findings OR any finding carrying a CVE

## 20:05 - Scan-quality fixes #1 #2 #5 done, auth scan running (hack/n3yx-scan-quality)
- Done: #1 CWE--1/CWE-0 guard re-added (b730b65 idiom, ZAP cweid arrives as str) + Modern Web Application / User Agent Fuzzer dropped at info risk + testssl HTTP→[]; #2 nmap skips target's own port w/ expected-open info marker; #5 verified live (/metrics real 26 KB → keep, tuned to low via NUCLEI_SEVERITY_OVERRIDES + severity_tuned_from; DOMPurify 3.4.12 TRUE POSITIVE per CVE-2026-75838 High 7.3, fixed 3.4.13 — keep medium); NEW tests/test_scan_noise.py; auth scan f156b516 (admin JWT, same 7 scanners) running for Compare vs baseline 92e0a552; Notion 03 Progress Log updated (list + results, AI triage marked deferred per owner)
- State: works — 335 pytest pass; AI triage untouched (agentic side not ready)
- Next: #4 XSS/ascan-target check once auth scan lands (~20 min); then commit slice
- Decisions: stock Nuclei medium for metrics overridden locally with audit trail in raw; DOMPurify kept at medium (bundled /api-docs lib, second-order exploitability)

## 20:15 - Strict Pause/Finish shipped + live proof, fresh auth scan running (hack/n3yx-scan-quality)
- Done: root cause was flags read only BETWEEN scanners (ZAP = one 15-min blocking step). NEW ScanStopped + stop_check/_check_stop in base.py; pipeline catches in sequential + parallel via _stop_now (activity-logged, never an error); ZAP spider/ascan-per-target/ajax/tree waits poll it (finally blocks still stop+remove orphan ZAP scans); status.html control() shows instant 'Pausing/Finishing… finalizing partial results'. NEW tests/test_controls.py (5). Restarted app to load it.
- State: works — 340 pytest pass; LIVE PROOF: pause on fresh auth scan 44f0827a pressed mid-ascan → paused in ~3s, resume → running with checkpoints intact. f156 post-mortem: user's Finish press landed at ZAP→headers checkpoint (zap-only 9 findings) — exactly the lag now fixed. Fresh FULL auth scan 44f0827a running with new code for Compare + XSS check. Notion updated.
- Next: baseline-vs-auth Compare + #4 XSS check on completion (~20 min); then commit slice
- Decisions: subprocess scanners (nmap/nikto/nuclei/testssl) still stop between steps only — Popen-interrupt is follow-up work; ZAP covers ~80% of wall time so this is where strictness matters

## 20:20 - 10-item batch done, full auth scan relaunched (hack/n3yx-scan-quality)
- Done: all 10 wired — CONCEPT_SEVERITY canonical table (+singletons) + clean_cwe shared helper + shortest-URL representative + correlate() (robots→ftp→listing chain, login-500→SQLi pointer) + estimated CVSS flagged in raw; SQLi evidence param/payload/response + stack fix; Nikto HSTS drop on HTTP + catch-all on every path finding (per-ID lists removed); ascan API-first re-rank, /assets + /socket.io skipped; OpenAPI import verified by tree growth into coverage (Juice Shop serves UI shell only — documented, seeds+spider remain the surface); sensitive-files +5 probes and dir-listing detection on discovered URLs; auth sidecar (job.json/exports clean, f156 migrated, running scan auto-migrates); restarted app to load it all; FULL auth scan 3ca6e097 running. Notion updated.
- State: works — 352 pytest pass; export verified auth-free
- Next: Compare 92e0a552 vs 3ca6e097 + #4 XSS check on completion; then commit slice
- Decisions: estimates use CVSS-range midpoints, always flagged; canonical severities match current sensible winners (stability > reinvention); OpenAPI honesty over heroics — record what imported, don't pretend

## 20:30 - Stack shut down (owner request)
- Done: app (uvicorn), ZAP daemon (java), Juice Shop (docker stop) all down, verified ports/processes free
- State: auth scan 3ca6e097 was mid-run — will be marked failed/orphaned on next startup by recover_orphaned_scans; relaunch when back
- Next: `./start.sh` + `docker start juice-shop` to resume; then Compare + XSS check

## 19:55 - Wiped all scan test data, back to zero (hack/n3yx-scan-quality)
- Done: stopped app, deleted 55 web scans (11M) + 21 repo scans w/ clones (147M) + agent runs + engagements + toolkit.db; kept ai_config.json + toolkit.log + dir skeleton; cleared ZAP spider+ascan history (both Result OK); restarted app
- State: works — /api/scans, /api/repo-scans, /api/apk/scans, /api/agent-scans all []; dashboard 200, Juice 200, app healthy
- Next: fresh baseline scans (web / codebase / APK) to populate radar, sunburst, compare
- Decisions: no running threads at wipe time (1 paused web scan discarded with its files); ZAP daemon + Juice kept running, only their scan history cleared

## 20:40 - Review-round fixes: OpenAPI honesty, CWE/OWASP merge, auth-aware merging, coverage, auth export (hack/n3yx-scan-quality)
- Done: `zap_scanner.py` — swagger.json serves UI shell (verified live: HTML, not JSON) so importUrl "OK" with zero tree growth is now recorded honestly + fallback parses embedded spec paths from /api-docs/swagger-ui-init.js; restored PLUGIN_OWASP/CWE_OWASP/_owasp_for from scan-quality-v2 (10109 dropped, -1/0 guard per b730b65); _parse writes cwe/owasp lists, cve stays None (Private IP plugin 2 mapped). `normalize.py` — escalate_auth_errors restored (checks affected_urls too, runs in prioritize); dedupe rep URL prefers auth endpoints (/rest/user/login beats /api); correlate links robots<->listing both ways. `nuclei` metrics back to medium (override removed). `testssl`/`nmap` skips now in coverage as not-applicable (no more info findings). `main.py` export carries auth {used, type} without secret + Auth line + CWE/OWASP/CVSS-est in text reports. CVSS "(est.)" in scan.html (rows/fix-first/meta), React History badge, print-PDF. NEW tests/test_scan_quality3.py (9 tests); updated noise/quality2 expectations
- State: works — 361 pytest pass; live headers/testssl/nmap scan 184e06ca: coverage not-applicable x2, CVSS est flags, export auth anonymous, no secret; f156 export shows auth bearer; 4 nikto FP paths verified byte-identical to / live
- Next: full web re-scan to confirm SQLi + login-500 escalated/medium + Private IP when ZAP reports it; commit slice (left uncommitted per no-commit rule)
- Decisions: old stored scans keep stale cve="CWE-89" shape (re-scan to refresh); headers findings carry no taxonomy (no data, not invented); frontend rebuilt + synced (old hashed bundle replaced)

## 21:30 - Authenticated retest vs Juice Shop (scan b43fe20e, admin JWT, all scanners)
- Done: full auth scan completed (19 findings, gate FAILED on SQLi as designed); verified on real data — OpenAPI coverage honest (swagger-ui-init.js, 1 URL, "/rest/* not in spec"), ZAP cwe/owasp lists + cve None, error-disclosure rep now exact /rest/user/login + ESC low->medium + SQLi login_500_candidate pointer, metrics medium+EST, 4 nikto FPs at info, testssl/nmap not-applicable in coverage, export auth bearer without secret. Follow-up fixes from the retest: LOGIN_PATH_RE (login sink beats broader /rest/user as rep), correlate checks affected_urls for login-500, _looks_dir_like (ZAP strips /ftp/ slash) + restored serve-index _is_listing (title "listing director" + hrefs) + direct /ftp/ wellknown probe — live: listing fires via discovered URLs and probe
- State: works — 363 pytest pass (quality3 now 11 tests); app restarted with all fixes, 200 healthy
- Next: commit slice; Private IP Disclosure never emitted by ZAP in 146 alerts (auth or not) — code keeps + tags it when present, nothing further to fix client-side
- Decisions: ZAP absence of plugin-2 is a scanner-coverage fact, reported honestly; extensionless routes get one listing-probe GET each (JSON/API bodies never match _is_listing)

## 22:10 - AJAX spider caged: works by default without OOM risk (hack/n3yx-scan-quality)
- Done: root cause was daemon defaults (12 browsers, depth 10, states unlimited, 60-min cap). `config.py` — enabled by default with bounds (1 browser, depth 5, 200 states, 5 min, 300 s poll cap, 1.5 GB free-RAM minimum else skip with note). `zap_scanner.py` — _cage_ajax/_uncage_ajax save+apply+restore daemon options per scan; subtreeOnly crawl; stop+restore+reap in finally; _reap_firefox kills only PIDs snapshotted as new (desktop browser never touched, PID-reuse re-validated); coverage gains ajax_note/browsers/max_states (+ states crawled, tree growth). tests: cage/restore, low-mem skip, disabled flag, helper shapes (quality3 now 15 tests)
- State: works — 367 pytest pass; LIVE standalone run vs Juice: completed in 40 s, 230 states, tree 24->75 (+51 URLs for ascan), peak java 1980 MB (2 g heap) + firefox 1054 MB, 6772 MB still free, spider stopped clean, user's firefox PID untouched; app restarted, 200 healthy
- Next: commit slice; next full web scan will exercise it end-to-end (watch ajax_note in coverage)
- Decisions: ZAP-side MaxDuration stays as backstop alongside our poll deadline; inScopeOnly not used (no context configured) — subtreeOnly + states cap contain off-site wandering instead

## 23:15 - Coverage-collapse audit: host theory disproven, real leaks fixed + auth retest (hack/n3yx-scan-quality)
- Done: A/B spider experiment (fresh newSession each) — localhost AND 127.0.0.1 both find 61 URLs; bodies/headers identical, no redirect. Host is NOT the cause. Real finds: (1) LEAKED enabled `octoscan-auth-0b21…` rule (localhost scope, stale token, job long wiped — pkill'd worker skipped finally) — deleted live; (2) `_purge_stale_auth_rules` at run start (self-heal) + scope test (127 vs localhost) + purge tests; (3) coverage gains `spider_found` so "URLs seen" is recorded, not guessed. ZAP daemon restarted fresh (days uptime). Auth retest on localhost (047d5f1d, admin JWT, all scanners): 22 findings, ascan 20/20, ajax completed 229 states +51 URLs in-pipeline, spider_found 24, Private IP Disclosure PRESENT (auth admin page, CWE-497/A01), error rep exact login + ESC + SQLi pointer, export bearer, gate FAILED on SQLi
- State: works — 370 pytest pass; app 200, ZAP fresh, Juice 200
- Next: commit slice; note: my retest request omitted sensitive-files from the picker so the post-pass skipped (pipeline marks deselected as run) — robots/ftp link fires once a scan includes it; resume can't re-add it (requested set is frozen at creation)
- Decisions: no timeout/cap formula changes (b43's 11/18 was one datapoint under an old daemon; fresh daemon did 20/20); stale-rule double-Authorization risk eliminated at both ends (purge + finally)

## 00:30 - Fix-list round: targeting, attribution, OWASP, evidence, live verification (hack/n3yx-scan-quality)
- Done: NEW `app/owasp.py` (CWE_OWASP incl 497->A01 both disclosures, 1395->A06, 598->A01 + CLASS_OWASP + keyword fallback; `owasp_for()`); `normalize.fill_owasp` backfills empty owasp centrally; sitewide concepts rep at origin root (CSP/CORS stop jumping); finding_class tagged in zap/headers/nikto/nuclei/sensitive/testssl. ZAP: socket.io dropped from parse+targets, counted in coverage; target selection ranks rest/api/params, drops shell-body paths (bounded, fail-open), budget-driven to ceiling with selection stats. Nikto: proven-catchall rows folded into one aggregate (names listed); robots low/info folded into listing (robots_folded). Nuclei: exposure/misconfig second pass (tag-scoped, info allowed), classification cwe+cvss-score parsed (metrics now measured 5.3), wire evidence + per-template fixes (experiment: only swagger-api-info + metrics-medium match Juice). sensitive-files coverage always written; empty picker persists full scanner list. NEW `app/verify.py`: SQLi differential confirm (replays ZAP attack) + login injection probe (baseline vs 2 payloads) hooked post-scan, bounded, fail-open
- State: works — 381 pytest pass (NEW quality4, 10 tests); LIVE: login probe got HTTP 200 + session token on `' OR 1=1-- -` (confirmed auth bypass); SQLi confirmed 200/30B vs 500/1072B on attack replay; nuclei parse verified on real exposure output; app 200
- Next: commit slice; next full scan exercises verify hook + exposure pass end-to-end (expect 047's 2 socket.io rows gone, +2 nuclei exposure rows, login/SQLi confirmations inline)
- Decisions: info findings never fail the gate (exposure pass can't flip verdicts); probes are read-only (2 GETs + 3 POSTs max) — no brute force, no mutation; ceiling 20 kept (gate denominator stability) with budget governing depth

## 01:20 - Full auth scan da29 + tail fixes (hack/n3yx-scan-quality)
- Done: full scan localhost admin JWT all-7 (22 raw findings) then fixed 3 tail bugs it exposed: (1) sensitive rows never reached final (pipeline updated job.findings but finalized the local list) — now extended; (2) verify ran pre-merge so login probes never fired (no tags/affected yet) — prioritize before verify; (3) nikto 007352 had no OWASP class + "header is not set" keyword missing. Backfilled da29 tail through real functions (idempotent v2 script): FINAL 18 findings — SQLi CONFIRMED + LOGIN500, error exact-login + bypass-indicated probe, /ftp listing CHAIN with robots folded, metrics measured 5.3, swagger-api info, 20 socket.io dropped, sitewide reps at root, export bearer, gate FAILED on SQLi. 381 pytest pass; app 200
- State: works — backfill reruns the pipeline tail only (scanner outputs hours-old, target unchanged); next fresh scan needs no backfill
- Next: commit slice (branch now ~15 files + quality4/verify/owasp)
- Decisions: /ftp vs /ftp/ deduped (emitted-set + dedupe_listings); probe findings carry directory_listing flag so the dedupe sees both sources

## 02:40 - Scan-7 order: parallel, attribution, OWASP, evidence, verify (hack/n3yx-scan-quality)
- Done: (1) parallel non-ZAP pool (ZAP first alone, rest x3, sensitive post-pass stays sequential) + duration_s in every scanner coverage; default scan_max_parallel 3. (2) nikto aggregate + sensitive catchall aggregate -> coverage not-applicable, zero info rows. (3) nikto /ftp/ row folds into listing (folded_findings); ZAP 10055 maps to csp-missing (CSP single at root, medium); 999100 x-recruiting -> info via nikto-uncommon-header. (4) CONCEPT_SEVERITY + CLASS_OWASP + title keywords = one table; finding_class tagged at all scanners; fill_owasp central. (5) /ftp enrichment LIVE HIGH: 11 files listed, 5 sensitive (.kdbx, .bak x3, .pyc); escalates + names files. (6) SQLi result error-confirmed + boolean tautology second check (live: both hit) + stack-specific fixes (Juice honestly generic, no X-Powered-By). (7) login bypass was wired; fixed pipeline order so probes fire post-merge (da29 backfill proves bypass-indicated). (8) coverage target_selection gains ranked_targets/cut/cut_sample/eligible. (9) nuclei extra tags += jwt (templates verified present)
- State: works — 386 pytest pass (quality4 now 15 tests); app 200 with all of it
- Next: commit slice (branch ~18 files); next scan validates parallel wall-time + exposure pass incl jwt; (10) two-token IDOR diff + (11) DOM XSS via ajax firefox scoped for later (11 needs new browser-automation deps)
- Decisions: ceiling 20 kept (gate denominator); info never fails gate; probes read-only; stack guess falls back to generic rather than inventing

## 03:10 - Full auth scan 43005a + all 9 fix-list items live (hack/n3yx-scan-quality)
- Done: localhost admin JWT, all-7, ~23 min wall (parallel pool: nikto+nuclei overlapped; was ~40). FINAL 14: SQLi error-confirmed+boolean-indicated + LOGIN500; error exact-login ESC + PROBE:bypass-indicated; /ftp HIGH (11 files, 5 sensitive) CHAIN FOLD:2 (robots + nikto rows gone); CSP/CORS single at root; metrics measured 5.3; swagger-api info; Private IP A01; 007352/013587/referrer A05; x-recruiting info; 20 socket.io dropped; spider_found 29; target_selection tree 75 -> kept 20 / eligible 26 / cut 6 + ranked list visible; per-scanner durations everywhere (zap 864 s, nuclei 399 s, nmap 11 s); sensitive-files coverage incl duration; export bearer; gate FAILED on SQLi. 3 post-scan tail fixes applied (sensitive extend, verify post-merge, 007352 class) + sensitive duration; 386 pass; app 200
- State: works — scan record is the proof; branch ready to commit
- Next: commit slice; remaining laters: (10) two-token IDOR diff, (11) DOM XSS via ajax firefox
- Decisions: spider count variance is real (29/61/98 across runs) — recorded per scan, trend over anecdotes

## 04:20 - Scan-7 order: ftp verify, ranking, agent-prep 12-16 (hack/n3yx-scan-quality)
- Done: (A) verify_listed_files — per-file GET + %00.md bypass probe, HIGH only on real downloads (live: legal.md + .kdbx 200; 4x403 with 400/404 bypasses, all recorded). (B) value scoring (params 100 + rest/api 120 + auth 30, junk basenames dropped, /api seed removed after live 500 check, shell-check on all non-?/non-rest, socket.io all forms) + ranked/cut/eligible visible. (12) stable_id sha1(scanner|concept) in dedupe (idempotent, 12-hex, verdicts survive). (13) request/response on Finding, populated by zap/nuclei/headers/nikto/sensitive. (14) confidence 0-1 + verified on all via rubric (live-confirm 0.95 > fetch 0.9 > measured 0.85 > observed 0.7 > estimated 0.5 > low-signal 0.3; live_verified set at creation). (15) NEW app/redact.py, ai_core imports it (all model calls already flow through call_*). (16) SCHEMA_VERSION=2 stamped at create+finalize; tests/test_schema.py (shape, legacy load, export no-leak, id stability). 391 pass; app 200
- State: works — live spot-checks (ftp HIGH, boolean SQLi, nuclei parse) + offline re-prioritize of da29 (unique idempotent ids, SQLi 0.95/True)
- Next: commit slice; next scan proves new shape end-to-end
- Decisions: old rows keep random ids until rescanned (fine); verified=False reserved for refuted (unused); ceiling 20 unchanged

## 05:00 - Logged to Notion + merged to main (hack/n3yx-scan-quality)
- Done: Notion 03 Progress Log appended (Oct-2 day summary, 7 bullets); committed da1afac (28 files, +2898/-388, no secrets in diff); pushed branch + fast-forward merged to main (4f32d17..da1afac) + pushed; 391 pytest green on main, tree clean
- State: main = branch; app 200 serving merged code (restarted before merge)
- Next: agent integration (items 12-16 unblock it); laters (10) IDOR diff, (11) DOM XSS
- Decisions: remote still points at startup-mvp (push accepted with moved-repo notice); left as-is so others' setups don't break
