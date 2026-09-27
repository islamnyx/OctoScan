<img src="app/static/logo.png" width="120" alt="OctoScan logo" />

# OctoScan by OctoSec Labs

Pre-launch security check for startups. Scan a live web app (DAST) or a codebase (SAST + secrets + dependencies), then our AI agent reasons over every finding: drops the false alarms, writes the fix, re-scans to prove it, and tells you the attack story in plain words.

<p>
  <img src="Presentation/assets/Untitled-removebg-preview.png" height="90" alt="NVIDIA" />
</p>

**Built for the GOMYCODE x NVIDIA hackathon — AI runs on NVIDIA Brev:** our own A100 80GB instance serves `qwen3:32b` (Ollama, OpenAI-compatible, structured JSON output), so the code we analyse never goes to a third-party AI API. Any OpenAI-compatible provider (NVIDIA hosted API at build.nvidia.com, Groq, local Ollama/LM Studio) can be added as a fallback in the dashboard.

## Security Assessment Toolkit

This repository contains two tools sharing a single codebase:

1. **app/** — web vulnerability scanner (FastAPI dashboard for Nmap/ZAP/testssl.sh/Nikto/Nuclei)
2. **scan_toolkit/** — mobile app security assessment toolkit (CLI, local-first)

The mobile toolkit focuses on deterministic security scans against client-supplied APK/IPA binaries, normalizes output into a shared finding schema, and layers LLM agents on top for correlation, prioritization, and report writing.

## Live demo (2 minutes, no setup)

No API keys, no waiting: open the agent page with the recorded run and watch the full loop replay — triage verdicts with confidence, proposed diffs with verified badges, ready/not-ready verdict, attack story.

- Dashboard: `http://127.0.0.1:8000` — Web / Codebase / AI-provider tabs; the orange **AI Agent · results** button opens the agent page
- Agent page: `/agent` — start a run, watch live steps, and reopen any past run under **Recent AI runs** (`/agent?run=<id>`)
- Replay: `/agent?demo=1` — instant replay of a **real recorded run on Brev** (`qwen3:32b`, no backend AI needed)
- Full run: `POST /api/agent-scan {"repo_url": "https://github.com/OWASP/NodeGoat"}` — our reference target: **215 findings** (18 critical / 104 high / 78 medium / 15 low, 87 dev-only); about 7 minutes on Brev

> Never demo a live web scan (up to 20 min) — the recorded web output and the NodeGoat codebase run are the jury path.

## How the AI agent works

Fixed backbone, AI decides inside each step — raw Python loop, no LangGraph/CrewAI:

1. **Scan** — semgrep + gitleaks + OSV (codebase) or Nmap/ZAP/Nuclei/Nikto/testssl/headers (web)
2. **Prefilter (no AI)** — drops dev-only deps, test fixtures and duplicates first, so 215 findings become ~30 sent to the model (5 per call, ~40 lines of code each)
3. **Triage (qwen3:32b on Brev)** — every finding gets `real / false_positive / review` + confidence + reason; rules win over the model on highs, and the run is never `ready` with unconfirmed criticals
4. **Fix + verify** — the model patches a ~40-line window; the patch is applied to a copy (never the cloned repo), then ONLY the rule that fired (semgrep or gitleaks) is re-run on the original and the patched copy. `verified=true` means that rule matches **fewer times in the patched file** (a per-file count, not a per-line proof); `false` = still matches as often, or the patch breaks parsing; `null` = no re-scan possible (OSV/ZAP findings, AI down)
5. **Story** — findings chained into how an attacker would break in, plus a ready/not-ready ship verdict with blockers

## Measured, not claimed

| Signal | Result | Where |
|---|---|---|
| Reference scan (OWASP NodeGoat) | 215 findings: 18 crit / 104 high / 78 med / 15 low | demo data + replay |
| Live agent run on Brev (`qwen3:32b`, A100), NodeGoat | 215 -> 30 findings without AI; triage 24 real / 6 false positive; 22 model calls, median 13.5 s, 33.3k tokens in / 13.7k out, no fallback; 6 min 41 s | `app/static/fake-agent-run.json` (run `6450f7181f364d57`) |
| Patches in that run | 2 verified by re-scan (`eval()` in contributions.js: 3 -> 0 matches for both rules); 1 rejected by the re-scan (`$where` patch broke parsing) | same run, `/agent?demo=1` |
| Launch verdict | `not_ready`, 6 blockers + attack story written by the model | same run |
| Tests | 327 pytest pass (75 for the AI layer: core, triage, fix, story, agent) | `tests/` |
| Triage accuracy (hand-labelled NodeGoat set) | pending: `eval/run_triage.py` writes real numbers to `docs/results.md` | `eval/` |
| ZAP repair (was 1/20 targets, orphan scans) | per-target isolation + budget caps, verified back-to-back on Juice Shop | `app/scanners/zap_scanner.py` |
| Model accountability | every call logs model, latency, tokens (never keys) to `data/ai_calls.jsonl` | `app/ai_core.py` |

## Responsible AI

- Secrets redacted before any code reaches a cloud model; small windows, never whole files
- Fallback chain (second provider, then non-AI result) — the agent stops fixing instead of hallucinating when AI is down
- Patches are suggestions a human applies; scans are read-only, consent-signed, SSRF-guarded
- The scanner, not the model, decides `verified`; the verdict is never `ready` while critical/high findings are unconfirmed; every triage verdict shows its reason and confidence
- Secrets stay masked in the diffs shown in the UI too
- Fully local option: Ollama / LM Studio, zero data leaves the machine

## Run the AI agent (NVIDIA Brev)

```bash
# 1. App
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt -r requirements-dev.txt
./start.sh --app-only                                  # http://127.0.0.1:8000

# 2. Model: tunnel to our Brev instance (brev login; brev refresh; keep this open)
ssh -o ControlMaster=no -o ControlPath=none -o ServerAliveInterval=20 -N \
    -L 127.0.0.1:11436:localhost:11434 octoscan-gomycode

# 3. Provider "brev" (turns on structured JSON output), once:
curl -s -XPOST localhost:8000/api/ai/providers -H 'content-type: application/json' \
  -d '{"name":"brev","provider":"brev","base_url":"http://127.0.0.1:11436/v1","api_key":"","model":"qwen3:32b","activate":true}'
curl -s -XPOST localhost:8000/api/ai/test -H 'content-type: application/json' -d '{}'   # {"ok":true,...}
```

Then open `/agent` and run `https://github.com/OWASP/NodeGoat`. Needs semgrep, gitleaks and osv-scanner (see Prerequisites) for real scans and patch verification; without an AI provider every step falls back to a non-AI result.

## What it does (base platform)

**Web application scans** — pick any subset before running:
- **Nmap** (ports/services), **OWASP ZAP** (web vulns, capped active scan), **testssl.sh** (TLS), **headers** (security headers + cookie flags), **Nikto** (known-path/CGI misconfigs), **Nuclei** (full CVE/misconfig template set, throttled)
- **Sensitive-files** post-pass: re-examines discovered URLs plus active probes (`/.git/HEAD`, `/.git/config`, `/.env`, `/.DS_Store`) with content-signature verification
- **Quality gate**: FAIL on exploitable rules (XSS/SQLi), WARN on misconfigs — verdict only, never overrides scan status
- Cross-scanner **dedupe** (CORS/ZAP-per-URL/Nikto-noise collapse), pause/resume/finish, live activity feed

**Codebase scans** — shallow-clone a repo URL, then:
- **Gitleaks** (committed secrets; builtin regex fallback) with vendored-tree filtering
- **Semgrep** (`--config auto` + custom `semgrep-rules/` taint rules for NoSQLi/IDOR/redirect/SSRF/XSS) with local evidence snippets, CWE/OWASP tags
- **OSV scanner** (known CVEs per lockfile): same-CVE **rollup** across installs, numeric **CVSS** scores, **direct vs transitive** flags, **runtime vs dev-only** scope from lockfile closure, parent-chain fix advice (`via mocha`)
- Optional **BYO AI** review (any OpenAI-compatible provider; Ollama/LM Studio stay local) + AI triage of all findings
- File+line+type **cross-scanner dedup**, top-level `summary` object (counts, runtime split, merged, secrets), JSON export + plain-text report

**Dashboard** (`http://127.0.0.1:8000`) — dark OctoSec theme (Charcoal `#1A1A1A`, Signal Orange `#FF6B00`, Space Grotesk + JetBrains Mono):
- Web / Codebase / AI-provider tabs, per-scan test picker, per-scan AI model picker
- Results: severity counts, **Fix-first top-5**, severity + scope filters, collapsible per-scanner groups, CVSS/CWE/OWASP on every card, Export JSON + Text report

## scan_toolkit — Mobile Security Assessment CLI

### Architecture

- **Local-first** — runs on the assessor's machine (16-32 GB RAM), no cloud infra
- **SQLite + SQLAlchemy ORM** — swappable to Postgres via config
- **Deterministic tools first** — Semgrep, MobSF, apktool, jadx, OSV/Grype, mitmproxy, ZAP
- **LLM agents layer on top** — structured JSON in/out, never invent findings
- **Human review gate** — findings must be confirmed before report generation

### Quick start

```bash
# 1. Clone & enter
git clone <repo-url>
cd startup-mvp

# 2. Python 3.11+ virtualenv
python3 -m venv .venv
source .venv/bin/activate

# 3. Install (editable, with dev/test deps)
pip install -e ".[dev]"

# 4. Configure
cp .env.example .env
# Edit .env — set SCAN_TOOLKIT_ANTHROPIC_API_KEY, tool paths, MobSF key

# 5. Verify
pytest
scan-toolkit --help
```

### CLI commands

| Command | Status | Description |
|---------|--------|-------------|
| `scan-toolkit intake create` | Done | Register engagement, store binary/docs/credentials |
| `scan-toolkit intake validate <id>` | Done | Check completeness, advance to 'scanning' |
| `scan-toolkit run --engagement <id> --stage static` | Done | Run static analysis pipeline |
| `scan-toolkit run --engagement <id> --stage sca` | Phase 5 | SCA via OSV.dev/Grype |
| `scan-toolkit status` | Phase 11 | Show engagement/queue state |
| `scan-toolkit report <id>` | Phase 10 | Generate report from confirmed findings |

### Data models

Three core ORM models in `scan_toolkit/models.py`:

- **Engagement** — client engagement lifecycle (intake -> scanning -> reviewing -> delivered)
- **Finding** — normalized vulnerability finding with severity/confidence/CWE/evidence
- **AttackChain** — correlated chain of findings with combined severity narrative

Plus **IntakeChecklist** for the intake gate (scope agreement, binary, credentials, etc).

### Intermediate representation

Raw tool output is normalized to IR models (`scan_toolkit/intermediate.py`) before LLM processing:

- **IRFinding** — one finding from one tool, pre-LLM (loose types)
- **IRToolOutput** — envelope for one tool invocation (findings + errors)
- **StageIR** — complete stage output, serialized to JSON for the LLM agent

### Configuration

All settings use the `SCAN_TOOLKIT_` prefix in `.env` (see `.env.example`):

| Variable | Default | Purpose |
|----------|---------|---------|
| `SCAN_TOOLKIT_DATA_DIR` | `./data` | Root for DB + per-engagement artifacts |
| `SCAN_TOOLKIT_DB_URL` | auto (SQLite) | SQLAlchemy connection string |
| `SCAN_TOOLKIT_ANTHROPIC_API_KEY` | — | LLM provider (Phase 4+) |
| `SCAN_TOOLKIT_MAX_CONCURRENT_DYNAMIC_JOBS` | 2 | Job queue limit (Phase 6) |
| `SCAN_TOOLKIT_APKTOOL_BIN` | `apktool` | apktool binary path |
| `SCAN_TOOLKIT_JADX_BIN` | `jadx` | jadx binary path |
| `SCAN_TOOLKIT_SEMGREP_BIN` | `semgrep` | semgrep binary path |
| `SCAN_TOOLKIT_MOBSF_BASE_URL` | `http://127.0.0.1:8000` | MobSF Docker service |
| `SCAN_TOOLKIT_MOBSF_API_KEY` | — | MobSF REST API key |
| `SCAN_TOOLKIT_SEMGREP_EXTRA_CONFIGS` | — | Extra Semgrep configs (comma-separated) |
| `SCAN_TOOLKIT_TOOL_TIMEOUT_SECONDS` | 600 | Per-tool invocation timeout |

## Prerequisites

| Tool | Install (no sudo needed where noted) | Notes |
|------|--------------------------------------|-------|
| Nmap | `sudo apt install nmap` | `NMAP_BIN`, default `/usr/bin/nmap` |
| Nikto | `sudo apt install nikto` | Bounded `-maxtime 240s -Tuning x6` |
| Nuclei | [install](https://github.com/projectdiscovery/nuclei#installation) + `nuclei -update-templates` | Full set, throttled (rate 50, concurrency 10, no `dos` tags) |
| OWASP ZAP | [zaproxy.org](https://www.zaproxy.org/download/) | 4G heap, AJAX spider off by default, shared ascan budget |
| testssl.sh | `git clone https://github.com/drwetter/testssl.sh.git resources/testssl.sh` | Or set `TESTSSL_BIN` |
| Gitleaks | Static binary to `~/.local/bin` ([releases](https://github.com/gitleaks/gitleaks/releases)) | `GITLEAKS_BIN`; builtin fallback otherwise |
| Semgrep | `pipx install semgrep` | `SEMGREP_BIN`; heuristic fallback otherwise |
| OSV scanner | Static binary to `~/.local/bin` ([releases](https://github.com/google/osv-scanner/releases)) | `OSV_BIN`, needs network for OSV database |
| Git | `sudo apt install git` | `GIT_BIN`, shallow clones only |

> **Note:** `resources/` is gitignored — each tool must be installed separately.

```bash
# 1. Clone the repo
git clone https://github.com/islamnyx/OctoScan.git
cd OctoScan

# 2. Create virtualenv + install
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 3. Configure
cp .env.example .env
# Edit .env: set API_KEY to enable auth, ZAP_API_KEY for ZAP

# 4. Start ZAP daemon (authenticated — never disablekey=true)
ZAP_API_KEY="$(openssl rand -hex 32)"; echo "ZAP_API_KEY=$ZAP_API_KEY" >> .env
java -Xmx4g -jar /usr/share/zaproxy/zap-2.17.0.jar \
  -daemon -port 8090 -host 127.0.0.1 -newsession clean \
  -config api.key=$ZAP_API_KEY -config api.disablekey=false \
  -config autoupdate.checkOnStart=false -config callhome.callHome=false

# 5. Start the API
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000

## API

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scans` | Start web scan. `{"target_url": "...", "scanners": ["zap","nuclei",…]}` (omit `scanners` = all) |
| `GET` | `/api/scans` | List web scans |
| `GET` | `/api/scans/{id}` | Scan details (findings, coverage, gate) |
| `GET` | `/api/scans/{id}/export` | JSON download |
| `GET` | `/api/scans/{id}/report` | Plain-text report |
| `POST` | `/api/scans/{id}/pause\|resume\|finish` | Run controls |
| `GET` | `/api/scans/{id}/activity` | Live progress feed |
| `POST` | `/api/scans/{id}/ai-analyze` | AI triage (needs AI config) |
| `POST` | `/api/repo-scans` | Start codebase scan. `{"repo_url": "...", "branch": null, "scanners": ["gitleaks","semgrep","osv"], "include_ai": false, "ai_model": null}` |
| `GET` | `/api/repo-scans` | List repo scans |
| `GET` | `/api/repo-scans/{id}` | Details incl. `summary` (counts, runtime split, merged, secrets) |
| `GET` | `/api/repo-scans/{id}/report` | Plain-text report |
| `POST` | `/api/repo-scans/{id}/pause\|resume\|finish\|ai-analyze` | Run controls + AI |
| `GET` | `/api/repo-scans/{id}/activity` | Live progress feed |
| `GET`/`PUT` | `/api/ai/config` | Provider config (key masked) / save |
| `GET`/`POST` | `/api/ai/providers` | Multi-provider list / add |
| `POST` | `/api/ai/providers/{name}/activate` · `DELETE` | Switch / remove provider |
| `POST` | `/api/ai/test` · `/api/ai/models` | Test connection · list models |
| `POST` | `/api/agent-scan` | Start the AI agent. `{"repo_url": "https://github.com/...", "target_url": null}` -> `{"run_id"}` |
| `GET` | `/api/agent-scan/{run_id}` | Live run: status, steps (thought/tool/result), findings with verdict + confidence + reason, fixes with diff + verified, verdict, blockers, attack story, stats |
| `GET` | `/api/agent-scans` | Recent agent runs (summary) |
| `GET` | `/health` | Health check |

If `API_KEY` is set in `.env`, send header `X-API-Key: <key>` on every `/api/*` call.

## Project structure

```text
app/
├── main.py               # FastAPI app + routes + text reports
├── config.py             # Settings from .env
├── models.py             # ScanJob, RepoScanJob, Finding (cwe/owasp/cvss), AI models
├── pipeline.py           # Web scanner orchestration + finalize/pause
├── repo_pipeline.py      # Clone -> scanners -> optional AI + summary
├── normalize.py          # Severity maps, prioritize, cross-scanner dedupe
├── cvss.py               # Local CVSS v3.1 calculator (OSV vectors)
├── ai_core.py            # ALL model calls: strict JSON + retry, fallback chain, secret redaction, call log
├── ai.py                 # BYO AI provider profiles (dashboard) + analyze_findings
├── ai_review.py          # Two-phase nominate+batch code review
├── ai_triage.py          # Prefilter (no AI) + triage real/false_positive/review, 5 per call
├── ai_fix.py             # Patch ~40-line window -> copy -> re-run only the fired rule -> verified
├── ai_story.py           # Attack story + ready/not_ready verdict (rule wins on highs)
├── ai_agent.py           # Agent loop: scan -> prefilter -> triage -> fix -> verify -> story
├── repo.py               # Safe https clone + caps + vendored filter
├── repo_store.py / store.py / control.py / activity.py
├── security.py           # SSRF guard, auth, rate limit, CSP
├── sensitive.py          # Sensitive-file post-pass + well-known probes
├── rules.py              # DAST quality gate
├── scanners/
│   ├── nmap/zap/testssl/headers/nikto/nuclei scanners
│   ├── source_base.py    # Base + repo_relative() path helper
│   ├── source_gitleaks.py / source_semgrep.py (custom rules dir, local evidence, CWE/OWASP)
│   ├── source_builtin.py # Secret regex fallback (vendored skip)
│   └── source_osv.py     # SCA: CVE rollup, CVSS, direct/transitive, runtime/dev scope, parents
└── static/
    ├── index.html        # Dashboard (React build, assets/ from frontend/)
    ├── agent.html/.js    # AI agent page: live steps, verdicts, verified patches, recent runs
    ├── fake-agent-run.json  # Recorded real Brev run for /agent?demo=1
    ├── scan.html         # Results (counts, fix-first, filters, reports)
    ├── status.html       # Live status + activity feed
    ├── logo.png          # OctoSec Labs logo + favicon
    └── fonts/            # Space Grotesk + JetBrains Mono (self-hosted, CSP-safe)
semgrep-rules/            # Custom logic-flaw rules (NoSQLi/IDOR/redirect/SSRF/XSS)
data/scans/ data/repos/   # Results + clones (gitignored)
data/agent/               # Agent runs + before/after file copies (gitignored)
eval/                     # Triage eval: labels + run_triage.py -> docs/results.md
scan_toolkit/             # Mobile app security assessment toolkit (CLI, local-first)
tests/                    # pytest suite
data/                     # Local data — DB + per-engagement artifacts (gitignored)
```

## Roadmap — Mobile APK Scanner (next)

The third scan mode alongside web + codebase, on a dedicated dashboard tab and the `feature/mobile-scans` branch:

**Planned checks (static, APK never executed):**
- Manifest: `debuggable=true`, `allowBackup=true`, cleartext traffic, backup rules
- Components: exported activities/services/receivers/providers without permissions, deep-link schemes, intent-filter exposure
- Secrets: hardcoded API keys/tokens/URLs in dex strings + resources (same builtin engine, APK-aware)
- Crypto/network: pinning absence, HTTP URLs, weak TLS validation, WebView `setJavaScriptEnabled` + bridges
- Permissions: dangerous-permission inventory vs API usage (over-privileged apps)

**Proposed API (mirrors repo scans):**
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/apk-scans` | Upload APK (`{"file": <binary>, "scanners": ["manifest","secrets","crypto"]}`) |
| `GET` | `/api/apk-scans` | List APK scans |
| `GET` | `/api/apk-scans/{id}` | Details + `summary` |
| `GET` | `/api/apk-scans/{id}/report` | Plain-text report |
| `POST` | `/api/apk-scans/{id}/ai-analyze` | AI triage |

## Contributing

1. Fork the repo
2. Create a feature branch (`feature/...`)
3. Make changes and test against a local target (DVWA/NodeGoat for web+codebase)
4. Open a PR

## License

MIT
