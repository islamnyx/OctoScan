# islam - progress log (hackathon 27 Sep 2026)

## 01:15 - Environment ready
- Done: setup script ran; semgrep, gitleaks, osv-scanner installed; NodeGoat scan saved as demo data (215 findings)
- State: works (smoke test passed)
- Next: verify with Claude Code, push hack/setup, get NVIDIA API key
- Decisions: omniroute proxy settings parked; team rules in AGENTS.md; ownership in docs/TEAM.md

## 12:02 - AI-layer fixes + ai_core (branch hack/islam-core, b6dd720)
- Done: new app/ai_core.py (call_json/call_text: <think>+fence strip, pydantic + 1 repair retry, provider fallback chain incl. .env AI_*, secret redaction on every message, call log data/ai_calls.jsonl + stats()); ai.chat_complete delegates to it; analyze_findings validated JSON + non-AI fallback; balanced digest (NodeGoat: 19 osv/19 semgrep/2 gitleaks, 0 dev-only); ai_review nomination fix + numbered ~30-line code windows (8 KB/file cap); NVIDIA + Brev presets (ai.py, index.html)
- State: works offline — 17 pytest pass (.venv/bin/python -m pytest tests -q), app smoke OK; NOT yet tested live: no AI provider configured on this machine
- Next: add NVIDIA key + model id via dashboard, live smoke of call_json; then pre-filter -> triage
- Decisions: call_json contract as in HANDOFF §3 (+ meta attempts/redactions); structured output (json_schema) only for provider "brev"/"vllm"; problem 7 (/ai-analyze blocking) handled by the background-thread agent, old endpoint unchanged; pytest in requirements-dev.txt

## 12:38 - AI-layer verified end-to-end (hack/islam-core, 24959f0)
- Done: 60 s cooldown for down providers (unreachable/5xx/429) in ai_core; AI review manifest now names the models that actually answered (+ "(fallback)")
- State: works — 19 pytest pass; E2E via real app endpoints vs a fake OpenAI-compatible reasoning model (sandbox DATA_DIR): test-connection strips <think>; primary down -> fallback (dead primary hit 1x not 6x); nomination reaches review; numbered lines; analyze repaired prose -> valid JSON; 0 of 3 repo secret literals + 0 private key sent (10 [REDACTED]); total outage -> HTTP 200 non-AI summary
- Next: live test with a real NVIDIA key + model id (still no provider configured here); then pre-filter -> triage
- Decisions: fallback_used = "not the configured primary"; client errors (400/401/413) don't trigger cooldown

## 12:52 - AI layer tested on Juice Shop (hack/islam-core)
- Done: Juice Shop codebase scan saved (id 8a617195bea940e6: 98 semgrep, 66 gitleaks of which 58 test fixtures, 1298 files, 60 s); digest now fills with fixtures/dev deps only after real findings (Juice Shop: 31 semgrep + 8 gitleaks, 0 fixtures, all 19 highs); redaction also masks `password === '...'` literals
- State: works — 20 pytest pass; sandbox E2E with fake reasoning model: HTTP 200 in 11 s, 8 files / 3 prompts, JSON repaired; private key in lib/insecurity.ts masked; all quoted secrets on gitleaks-flagged non-test lines masked
- Next: real NVIDIA model test (still no key configured), then pre-filter -> triage
- Decisions/gotchas: Juice Shop has no lockfile -> osv-scanner exits 128 and the app mislabels it "osv-scanner not installed" (source_osv.py _unavailable title; not fixed, not AI). Review samples 8 of 1298 files (byte budget) until real-model nomination runs

## 13:25 - Verified friend's ZAP fix (origin/web_scanners a9b6e87)
- Done: merged origin/web_scanners into LOCAL main (fast-forward, not pushed); ran 2 back-to-back ZAP-only web scans of Juice Shop via POST /api/scans
- State: works — run 1: 16/20 targets, 495 s, SQL Injection found (1 high, 4 med, 2 low, 1 info after dedupe; 148 raw), 0 orphan scans, daemon alive; run 2: identical, 480 s. Before the fix: 1/20, no SQLi
- Next (friend, owns zap_scanner.py): (1) restore bug: `int(...) or None` drops ZAP's default 0 -> daemon left at MaxScanDurationInMins=1 (confirmed); (2) budget = min(1200, SCAN_TIMEOUT_SECONDS/2) = 450 s, but 20 x 60 s min cap = 1200 s -> max ~16/20; (3) junk ascan targets (/juice-shop/node_modules/..., assets/public/assets/public/...) waste slots
- Decisions: web scan never demoed live (AGENTS.md); SQLi detection is enough for the stretch "web + code correlation"

## 13:45 - Integrated + next-phase plan
- Done: web_scanners = 769f6d0 (friend's ZAP fix + AI foundation), 20 tests pass; wrote docs/NEXT.md (3-person split, contracts, timeline)
- State: works; still NO AI key configured anywhere -> first step for everyone (.env AI_* = NVIDIA)
- Next: Islam -> hack/islam-agent (ai_agent.py loop, ai_fix.py fix+verify, /api/agent-scan); A -> prefilter+triage+eval; B -> story + agent.html + docs
- Decisions: integration branch is web_scanners (origin/main left at 5fc04ea); CUT learn-rule, Brev, ZAP follow-ups

## 14:20 - ai_fix + agent models (hack/islam-agent, 3819274)
- Done: app/ai_fix.py (one call_json -> PatchReply line-range replacement in a ~40-line window, difflib diff, patch on data/agent/<run>/<fix>/{before,after} copies, re-run ONLY the fired rule: semgrep r/<check> or semgrep-rules/, gitleaks rule+merged rules); AgentRun/Step/Finding/Fix/Stats models
- State: works — 40 pytest pass; real NodeGoat: eval 3->0 verified, zapApiKey 2->0 verified, broken patch -> verified false, clone untouched
- Next: ai_agent.py loop + /api/agent-scan
- Decisions: verified null also when no re-scan ran (AI down, patch rejected, rule doesn't fire on original); main model = Brev vLLM (provider "brev", json_schema structured output)
