# OctoScan: rules for every AI coding agent (Claude Code, Antigravity, OpenCode, Copilot...)

## What this is
OctoScan (OctoSec Labs) = pre-launch security check for startups.
- Codebase scan: shallow-clone a https repo -> gitleaks + semgrep (+ custom rules in
  `semgrep-rules/`) + osv-scanner -> normalise, dedupe, prioritise -> dashboard.
- Web scan: nmap, ZAP, testssl, headers, nikto, nuclei + sensitive-file probes.
- AI layer: any OpenAI-compatible provider (`app/ai.py`), AI code review (`app/ai_review.py`).
Stack: Python 3.10+, FastAPI, pydantic v2, httpx. Frontend = static HTML + vanilla JS in `app/static/`.

## Hackathon (GOMYCODE x NVIDIA, 27 Sep 2026)
- Only what we build TODAY is judged. The scanner is the base; the new AI features are the product.
- Rubric: user value 20 | works live 20 | quality of AI use 20 | testing+reliability 15 |
  demo 15 | responsible AI 10.  Submission closes 17:30 (Tunis/Algiers time).
- Feature freeze 15:45. After that: bug fixes, video, docs only.

## Run
```
source .venv/bin/activate
./start.sh --app-only          # codebase scans, http://127.0.0.1:8000
curl -s localhost:8000/health
```
Web scans need ZAP (`./start.sh`) and take up to 20 min: never demo a live web scan.
Demo target for codebase scans: https://github.com/OWASP/NodeGoat

## Code map
- `app/main.py` routes | `app/models.py` pydantic models (Finding, ScanJob, RepoScanJob, AIAnalysis)
- `app/repo_pipeline.py` codebase pipeline | `app/pipeline.py` web pipeline
- `app/normalize.py` severity + dedupe | `app/cvss.py` CVSS 3.1 | `app/rules.py` quality gate
- `app/ai.py` providers + `chat_complete()` + `analyze_findings()` | `app/ai_review.py` AI review
- `app/scanners/*` one file per scanner | `app/static/*.html` dashboard

## Team rules (avoid overlapping work)
- Read `docs/TEAM.md` first: it says who owns which files. Do NOT edit files owned by someone else;
  if you need a change there, write it in the TEAM.md "requests" list.
- New features go in NEW files (e.g. `app/ai_fix.py`, `app/static/js/fix.js`) instead of rewriting
  existing modules. Shared files (`app/main.py`, `app/models.py`) are edited only by their owner.
- One branch per person: `hack/<name>-<feature>`. Pull `main` before starting each task.
  Small commits. Merge into `main` only through the integrator at the sync points.
- Never commit `.env`, `data/`, API keys or `nvapi-...` tokens.

## Coding rules for AI features
- Call models only through `app.ai.chat_complete()`; no openai SDK, no new heavy deps.
- NVIDIA hosted API: base URL `https://integrate.api.nvidia.com/v1`, key from build.nvidia.com,
  exact model id copied from the model page.
- Every model call: timeout, try/except, fallback (second provider, then non-AI result).
- Ask for strict JSON, strip ```json fences, validate with pydantic, retry once.
- Redact secrets before sending code to a cloud model. Send small code windows, not whole files.
- Log model id, latency, token counts (never keys) so we can report real numbers.
- Keep SSRF guard / `ALLOW_PRIVATE_TARGETS` protections intact. Never log keys.

## Progress log (shared memory across sessions and tools)
- BEFORE starting work: read every file in `docs/progress/` and `git log --oneline -15`.
- AFTER finishing a task (and before any context reset): append an entry to
  `docs/progress/<your-owner-name>.md` in the format from `docs/progress/README.md`.
- Only append to your own owner's file. Never edit someone else's log.
