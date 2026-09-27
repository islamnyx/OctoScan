# Next phase: build the AI agent (13:45 -> 15:45 freeze)

Integration branch: `web_scanners` (769f6d0 = ZAP fix + AI foundation). Branch from it,
Islam merges back into it. Rules: `AGENTS.md`. Product: `docs/AI-PLAN.md`.
Already done: `app/ai_core.py` (`call_json` / `call_text`: JSON + pydantic + retry,
fallback, redaction, call log), NVIDIA/Brev presets, fixed AI review. 20 tests pass.

## 0. Everyone first (5 min)
- Get your own free key at build.nvidia.com and copy the EXACT model id from the model page.
- Put it in your gitignored `.env` (no dashboard needed, ai_core reads it as a provider):
  `AI_PROVIDER=nvidia`, `AI_BASE_URL=https://integrate.api.nvidia.com/v1`,
  `AI_API_KEY=nvapi-...`, `AI_MODEL=<exact id>`
- Check: `.venv/bin/python -c "from app import ai_core; print(ai_core.call_text([{'role':'user','content':'Reply ok'}], max_tokens=200))"`
- Never commit `.env` or keys.

## 1. Who does what (no two people edit the same file)
| Who | Tool | Branch | Owns | Builds |
|---|---|---|---|---|
| Islam (hardest) | Claude Code | hack/islam-agent | app/ai_agent.py, app/ai_fix.py, app/main.py, app/models.py, tests/test_ai_agent.py, tests/test_ai_fix.py | agent loop + fix & verify + API + merges |
| Friend A | OpenCode | hack/<a>-triage | app/ai_triage.py, tests/test_ai_triage.py, eval/*, docs/results.md | pre-filter + triage + measured accuracy |
| Friend B | OpenCode | hack/<b>-ui | app/ai_story.py, tests/test_ai_story.py, app/static/agent.html, app/static/agent.js, app/static/fake-agent-run.json, docs/project-card.md, docs/disclosure.md | attack story + agent page + submission docs |

`app/ai_core.py` is frozen (owner Islam). Need a change anywhere else: "Requests" in `docs/TEAM.md`.
CUT: learn-rule tool, Brev self-hosting, ZAP follow-ups (web scans are never demoed live).

## 2. Contracts (code against these, don't wait for each other)

### Friend A: `app/ai_triage.py`
```python
def locate(f: Finding) -> tuple[str | None, int | None]
    # file + line from f.raw["file"] or the "...#path:line" suffix of f.location
def prefilter(findings: list[Finding], limit: int = 30) -> list[Finding]
    # NO AI: drop raw.scope == "dev", raw.likely_test_fixture, severity info,
    # scanner "ai-code-review" meta rows; keep prioritize() order; top `limit`
def code_window(workdir: Path, rel: str, line: int, radius: int = 20) -> str
    # "N: code" numbered lines, ~40 lines; "" if file missing
def triage(findings: list[Finding], workdir: Path) -> list[dict]
    # 5 findings per call_json call. Each item:
    # {"finding_id", "verdict": "real|false_positive|review", "confidence": 0..1, "reason"}
    # AIError -> every item {"verdict": "review", "confidence": 0.0, "reason": "AI unavailable: ..."}
```
Eval (rubric: testing 15 + AI quality 20): hand-label 20 NodeGoat + 10 Juice Shop findings
(`eval/labels.json`: finding_id -> real/false_positive), run triage, write accuracy,
false-positive rate, median latency and tokens (from `data/ai_calls.jsonl`) to `docs/results.md`.
Scans on disk: NodeGoat `data/repos/43d3ad8721764e6e`, Juice Shop `data/repos/8a617195bea940e6`
(re-create with a codebase scan if missing on your machine).

### Friend B: `app/ai_story.py` + agent page
```python
def attack_story(real: list[dict], target: str) -> dict
    # input: triage items with verdict "real" (+ title, severity, file, line)
    # output: {"verdict": "ready|not_ready", "blockers": [str], "attack_story": str}
    # one call_json call; AIError -> rule-based: not_ready if any critical/high real finding
```
Agent page `app/static/agent.html` + `agent.js`: repo URL input -> `POST /api/agent-scan`,
poll `GET /api/agent-scan/{run_id}` every 2 s, show live steps (thought -> tool -> result),
findings with verdict + confidence + reason, fixes with diff + verified badge, final verdict,
attack story, stats (model, calls, median latency, fallback). Build against
`app/static/fake-agent-run.json` (exact shape below) until the API is merged.

### Islam: API (frozen, from AI-PLAN)
```
POST /api/agent-scan {"repo_url": "...", "target_url": null} -> {"run_id": "..."}
GET  /api/agent-scan/{run_id} -> {
  "status": "running|done|failed",
  "steps": [{"n": 1, "thought": "...", "tool": "triage", "result": "..."}],
  "findings": [{"id","title","severity","file","line","verdict","confidence","reason"}],
  "fixes": [{"finding_id","diff","explanation","verified": true|false|null}],
  "verdict": "ready|not_ready", "blockers": ["..."], "attack_story": "...",
  "stats": {"model","calls","median_latency_ms","fallback_used"}}
```
`verified`: true/false only when a semgrep/gitleaks re-scan actually ran; null = not verifiable (OSV, ZAP).

## 3. Timeline
- 13:45 start (key + branch)
- 14:30 checkpoint: A pushes prefilter+triage+tests, B pushes story+tests+page on fake data -> Islam merges
- 15:15 full flow on NodeGoat through the agent page, real NVIDIA model
- 15:45 FEATURE FREEZE. After: bug fixes, eval numbers, video, card, disclosure
- 17:00 final check (hackathon-submit skill) | 17:30 submission closes

Each task: small commits, `.venv/bin/python -m pytest tests -q` green, append to
`docs/progress/<name>.md`, push your branch, tell Islam.
