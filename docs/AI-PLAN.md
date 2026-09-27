# OctoScan AI Integration Plan
Goal: turn OctoScan into an AI security agent: it scans, drops false alarms, fixes what's real, proves each fix with a re-scan, learns new rules, and explains the risk in plain words.

## Architecture: 1 guided agent + 4 tools
- The scanners still find problems (semgrep, gitleaks, osv for code; ZAP, nuclei etc. for web).
- The AGENT (3) is a loop with a fixed backbone: scan -> triage -> fix -> verify -> story. The AI decides inside each step (what's real, what to fix first, whether to re-scan, when to learn a rule). Each step = the model returns JSON {thought, tool, args}. Raw Python loop, no LangGraph/CrewAI.
- Tools, each ONE focused model call through app/ai_core.py:
  1. FP filter (triage): finding + ~40 lines of code -> real / false_positive / review, confidence, reason
  2. Fix + verify: the model returns a line-range patch for a ~40-line window; it is applied to a COPY (data/agent/<run>/<fix>/{before,after}, the kept clone data/repos/<id> is only read), then ONLY the rule that fired (semgrep r/<check> or semgrep-rules/, gitleaks rule) re-runs on both copies -> diff, explanation, verified true/false. verified=true ONLY when a re-scan actually ran and the rule fires less; null = not verifiable (OSV, ZAP, AI down, rule unavailable).
  4. Attack story: chains real findings into how an attacker would break in + ready/not_ready verdict + blockers
  5. Learn rule: for a real flaw no scanner caught, AI writes a semgrep rule, semgrep --validate + test it catches the flaw, save to semgrep-rules/learned/
- Cost control: filter WITHOUT AI first (drop dev-only OSV deps and duplicates, using existing scope/dedupe data), then send only the top ~30 findings to the AI, 5 per call. Never 215 calls.
- Stretch: web + code correlation (semgrep finds SQLi in /login code, ZAP confirms it on the live /login page) only if ZAP is fixed.

## New files
app/ai_core.py (call_json: JSON-only, strip <think> and ``` fences, pydantic validation, retry once, timeout, fallback provider, logs model/latency/tokens, secret redaction)
app/ai_triage.py, app/ai_fix.py, app/ai_rules.py, app/ai_agent.py, app/static/agent.html
Reuse: app/activity.py for live agent steps, app/normalize.py for dedupe/priority, repo_store workdir for the clone.
Note: Finding has one `location` string, no file/line fields -> needs a helper to split it.

## API (frozen at 11:45)
POST /api/agent-scan {"repo_url": "...", "target_url": null} -> {"run_id": "..."}   (runs in a background thread, like repo scans)
GET /api/agent-scan/{run_id} -> {"status": "running|done|failed",
  "steps": [{"n", "thought", "tool", "result"}],
  "findings": [{"id","title","severity","file","line","verdict":"real|false_positive|review","confidence","reason"}],
  "fixes": [{"finding_id","diff","explanation","verified"}],
  "verdict": "ready|not_ready", "blockers": [...], "attack_story": "...",
  "stats": {"model","calls","median_latency_ms","fallback_used"}}

## Models
Main = NVIDIA Brev: our own GPU instance serving a model with vLLM (OpenAI-compatible), saved in the dashboard as provider "brev" (data/ai_config.json, key never printed) -> code never leaves our infrastructure. NVIDIA hosted API (https://integrate.api.nvidia.com/v1) is only a fallback if a key exists. ai_core sends vLLM structured output (response_format json_schema) to provider "brev"; the agent's per-step Decision schema has `tool` as a Literal of the allowed tools, so guided decoding can only emit a legal tool. The live NodeGoat demo runs on the Brev model: `stats.model` in GET /api/agent-scan/{run_id} = the Brev model id (fallback models are listed too if one answered). Log GPU/model/latency for the Brev disclosure.

## Team
#1 Brev GPU + vLLM model + fallback keys, docs/models.md | #2 ZAP fix, then learn-rule tool | #3 Islam (me): ai_core, triage, fix+verify, agent, story, merges | #4 agent.html on fake data, demo video | #5 submission package + pitch

## Order + checkpoints
Now-12:30: fix the 7 AI-layer problems + ai_core.py. 12:30 merge. Then pre-filter -> triage -> agent loop -> fix+verify -> story -> learn rule. 15:15 full flow merge. 15:45 FREEZE. 17:30 submit.
Cut order if late: learn rule, then story polish. Never cut: triage, fix+verify, live agent page.

## Safety
Only user-given targets, SSRF guard stays on, secrets removed before any model call, patches are suggestions a human applies, every verdict shows reason + confidence.
