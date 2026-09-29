# Handoff: who does what (27 Sep 2026)

Read first: `AGENTS.md` (rules), `docs/AI-PLAN.md` (source of truth for the AI product),
`docs/TEAM.md` (ownership), `docs/progress/*` (what happened so far).

## 1. Status at 11:30
- Environment verified: venv (Python 3.14) OK, semgrep 1.178 / gitleaks 8.30 / osv-scanner 2.6 OK,
  all 33 Python files compile, app + `/health` + reports OK.
- Demo data: NodeGoat codebase scan, 215 findings (osv 179, semgrep 34, gitleaks 2;
  18 critical / 104 high / 78 medium / 15 low). 87 are dev-only deps. Clone kept in
  `data/repos/<id>/src` (not in git: regenerate with a codebase scan of
  https://github.com/OWASP/NodeGoat).
- ZAP web scan: broken (diagnosed live, see section 4).
- AI layer: works, but has 7 problems that block the AI features (section 3).

## 2. Who does what (no two people edit the same file)
| Who | Branch | Owns | Work |
|---|---|---|---|
| Islam (#3) | hack/islam-core | app/ai.py, app/ai_review.py, app/ai_core.py, app/ai_triage.py, app/ai_fix.py, app/ai_agent.py, app/main.py, app/models.py, app/static/index.html | 7 AI fixes + ai_core, then triage, fix+verify, agent, story; merges |
| Friend (#2) | hack/<name>-zap-fix, then hack/<name>-learn-rule | app/scanners/zap_scanner.py, start.sh, app/ai_rules.py, semgrep-rules/learned/, tests/test_ai_rules.py | ZAP fix, then learn-rule tool |
| #1 | - | docs/models.md | Brev GPU + vLLM model + fallback keys |
| #4 | - | app/static/agent.html | agent page on fake data, demo video |
| #5 | - | docs/project-card.md, docs/disclosure.md | submission + pitch |

Nobody else touches `app/config.py`. Need a change in a file you don't own: add it to
"Requests" in `docs/TEAM.md`.

## 3. Islam: the 7 AI-layer problems (fixing now, merge 12:30)
1. `ai_review.py`: `_parse_review_reply` keeps only dicts, so `nominate_files` always
   gets `[]` (the model's file picks are silently lost).
2. `ai.py` `_findings_digest`: the top 40 findings sent to the model are all OSV on
   NodeGoat; the 34 semgrep code findings never reach it.
3. `chat_complete` has no fallback provider (error -> HTTP 502).
4. No logging of model / latency / tokens (`usage` is dropped).
5. Weak JSON handling: no `<think>` / ``` stripping, no pydantic check, no retry.
   Reasoning models (Nemotron, R1) break the `{...}` slicing or return empty answers.
6. No secret redaction; AI review sends whole files (up to 20 KB each). NodeGoat
   evidence already contains a private key.
7. `POST /ai-analyze` runs minutes inside one HTTP request -> the agent runs in a
   background thread instead.
Plus: NVIDIA + Brev presets in `ai.py:26` and `index.html` (dropdown + JS PRESETS).

### Contract other people code against (ready ~12:30)
```python
from app.ai_core import call_json
obj, meta = call_json(messages, schema, *, max_tokens=800, purpose="learn-rule")
# messages: list of {"role", "content"}; schema: a pydantic BaseModel class
# obj: validated schema instance
# meta: {"model", "provider", "latency_ms", "tokens_in", "tokens_out", "fallback_used"}
# raises app.ai_core.AIError when every provider failed (caller uses a non-AI fallback)
```
Until it is merged, stub `call_json` with this exact signature in your tests.

## 4. Friend (#2), phase 1: fix the ZAP web scan (time box 45 min)
Measured live (ZAP 2.17.0 vs Juice Shop): 1/20 ascan targets, 105 findings
(83 medium / 12 low / 10 info), no SQLi/XSS, 278 s.

Root causes:
1. `zap_scanner.py` ~169-208: ONE try wraps the whole ascan loop. Target 2
   (`/search?q=ZapTest`) hit the 150 s per-target cap at 34% -> "timed out" -> loop
   exits -> the other 18 targets never run.
2. The timed-out ascan is never stopped (`ascan/view/scans` still showed it RUNNING
   after `run()` returned). They pile up across scans -> daemon unresponsive ->
   httpx 30 s timeouts -> 0/20 on the next scan.
3. Budget: 20 targets x 150 s = 3000 s > 1200 s budget (target 1 alone = 111 s).
4. Ranking: `/search?q=` and `/#/search?q=` are SPA routes (return index.html) but rank
   equal to the real SQLi sink `/rest/products/search?q=`.
5. `start.sh`: on first start ZAP downloads ~35 add-on updates; the 120 s health wait
   kills it mid-download -> corrupt `.zap` files in `~/.ZAP/plugin`.

Fix:
- A. Per-target try/except inside the loop: on timeout/400 -> `ascan/action/stop`
  (scanId), record the reason, continue. Only "daemon unreachable" aborts.
- B. Per-target cap = ascan_budget / len(targets), min 60 s. Enforce inside ZAP with
  `ascan/action/setOptionMaxScanDurationInMins` (save the old value in
  `_throttle_ascan`, restore in `_restore_throttle`); poll timeout = cap + 20 s.
- C. In `finally`: stop + `ascan/action/removeScan` for every scan id we started.
- D. `_select_ascan_targets`: URLs with `?` AND `/rest/` or `/api/` first; drop URLs
  containing `#`.
- E. `start.sh`: add `-silent` to both ZAP launch commands; health wait 180 s.

Keep: ZAP API key required (never `api.disablekey=true`), the open-daemon probe,
apikey redaction in errors, the SSRF guard. Don't touch other scanners.

Test:
```bash
export ALLOW_PRIVATE_TARGETS=true        # shell only, never commit .env
./start.sh                               # ZAP + app
curl -s -X POST localhost:8000/api/scans -H 'Content-Type: application/json' \
  -H "X-API-Key: $API_KEY" \
  -d '{"target_url":"http://localhost:3000","scanners":["zap"]}'
# (X-API-Key only if API_KEY is set in .env)
```
Report: ascan_scanned/ascan_targets (job coverage), findings by severity, any SQLi/XSS,
total time, and that `ascan/view/scans` has no RUNNING scan afterwards. Then run a
second scan right after: the daemon must still respond.
Done = >= 18/20 targets, no orphan scans, 2 back-to-back scans OK. If SQLi is still
missed at 60 s/target, report it; don't raise the caps without asking.

## 5. Friend (#2), phase 2: learn-rule tool (after ZAP is merged)
`app/ai_rules.py`:
```python
learn_rule(finding: dict, code_window: str, language: str) -> dict
# -> {"rule_id", "yaml", "validated": bool, "catches_flaw": bool, "path": str | None, "reason"}
```
- Model call only through `app.ai_core.call_json` (section 3 contract).
- Pipeline: the model writes one semgrep rule -> write it to a TEMP dir ->
  `semgrep --validate --config <tmp>` -> run it on the flawed code window (must match
  >= 1) -> only then move it to `semgrep-rules/learned/<rule_id>.yml`.
- CRITICAL: semgrep loads everything under `semgrep-rules/` (including `learned/`) on
  every scan. One invalid rule breaks ALL semgrep scans. Never write an unvalidated
  file there. Rule ids start with `learned-`.
- Redact secrets in `code_window` before the call; send <= 40 lines.
- `tests/test_ai_rules.py` (create `tests/`): valid rule saved, invalid rule rejected,
  rule that does not match the flaw rejected (stubbed model, real semgrep).
- First to cut if late (AI-PLAN "Cut order").

## 6. Friend setup (OpenCode)
```bash
git clone https://github.com/islamnyx/OctoScan.git && cd OctoScan
git switch -c hack/<name>-zap-fix
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cp .env.example .env
sudo apt install -y zaproxy               # 2.17.0, needs Java 17+
pipx install semgrep                      # phase 2
docker run -d --name juice-shop -p 3000:3000 bkimminich/juice-shop
for f in ~/.ZAP/plugin/*.zap; do unzip -tq "$f" >/dev/null 2>&1 || rm -v "$f"; done
opencode
```
OpenCode reads `AGENTS.md` automatically. Do NOT run `/init` (it rewrites AGENTS.md).
Use the Plan agent (Tab) first, then Build. First message:
"Read AGENTS.md and docs/HANDOFF.md. You are teammate #2. Do section 4, then section 5."

## 7. Timeline
11:45 API frozen | 12:30 merge (7 fixes + ai_core) | 15:15 full-flow merge |
15:45 FEATURE FREEZE | 17:30 submission closes.
Small commits on your branch, append to `docs/progress/<name>.md` after each task,
tell Islam when a branch is ready to merge. Never commit `.env`, `data/`, keys,
`CLAUDE.md` or `.claude/`.
