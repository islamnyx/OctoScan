# friend-a - progress log (hackathon 27 Sep 2026)

## 14:05 - Triage + prefilter + tests (hack/friend-a-triage)
- Done: `app/ai_triage.py` (locate/prefilter/code_window/triage, 5 per call_json, AIError->review), `tests/test_ai_triage.py` (11 tests, stubbed call_json), `eval/run_triage.py` (real-model eval -> docs/results.md)
- State: works — `.venv/bin/python -m pytest tests -q` 31 passed (20 existing + 11 new)
- Next: codebase scans for NodeGoat + Juice Shop (binaries missing on this box, builtin fallback only), hand-label 20+10 in eval/labels.json, live eval with Brev/Ollama Qwen3 model, fill docs/results.md with real numbers
- Decisions: contracts from docs/NEXT.md §2 exactly; model only via app.ai_core.call_json (purpose=triage, max_tokens=1500); prefilter keeps prioritize() order; code_window clamps edges, blocks traversal; eval groups by workdir, refuses to invent numbers when no provider is configured

## 14:40 - Eval inputs ready, live run blocked on provider
- Done: codebase scans recreated on this box (NodeGoat 43d3ad8721764e6e: 111 files/14 findings; Juice Shop 8a617195bea940e6: 1298 files/34 findings — builtin fallback, no semgrep/gitleaks/osv binaries here); `eval/labels.json` 22 hand-labels (12 NodeGoat 7r+5fp, 10 Juice 6r+4fp, per-finding rationale in TO_DO.md §2); `docs/results.md` pending skeleton with measured scan stats; `TO_DO.md` with provider + live-eval steps
- State: partial — `.venv/bin/python -m pytest tests -q` green (31 passed); `eval/run_triage.py` refuses without a provider (by design, no invented numbers); `.env` AI_* left empty per user request
- Next: when Brev host/tag or NVIDIA key is ready — set `.env`, curl-check `/v1/models`, run `eval/run_triage.py`, commit results, tell Islam
- Decisions: labels include prefilter-dropped fixtures as FP (tests triage, not prefilter); Gruntfile exec + livereload document.write labelled FP (heuristic misfires); dev-config ZAP key labelled real (committed credential)

## 15:00 - Dashboard<->tool linkage verified (no changes needed)
- Done: pulled web_scanners (25f0b29, my branch merged as 51b7f45); restarted pre-merge uvicorn (was 404ing /api/agent-scan + /agent); e2e agent run on NodeGoat: done in 15s, 5 steps, 10 findings with verdict/confidence/reason (triage AIError fallback firing correctly), verdict not_ready + blockers + story + stats; live API keys == fake-agent-run.json keys == NEXT.md contract; agent.js reads verdict/confidence/reason/verified/blockers/story/stats — page renders both live and ?demo=1. Full web scan also completed: 24 findings (1 high/6 med/7 low/10 info), all 7 scanners ran, gate FAILED on zap SQL Injection, no errors.
- State: works — linkage verified, nothing to fix, so no code commit (others' files untouched per ownership)
- Next: live-model eval when provider ready (TO_DO.md); re-verify linkage with real verdicts then
- Decisions: did NOT commit to web_scanners directly (Islam merges); offline all-review/0-fix output is the designed fallback, not a linkage bug

## 16:25 - Fixed sys.path crash in eval/run_triage.py
- Done: `sys.insert` -> `sys.path.insert` (the crash Islam flagged); verified `.venv/bin/python eval/run_triage.py` now starts cleanly and refuses with "no AI provider configured" instead of AttributeError (Brev tunnel :11436 lives on Islam's box, not reachable here)
- State: works — 31 pytest pass; live eval still blocked on provider (TO_DO.md)
- Next: run live eval where the Brev tunnel is up, or with NVIDIA key
