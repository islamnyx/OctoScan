<img src="app/static/logo.png" width="120" alt="OctoScan logo" />

# OctoScan by OctoSec Labs

Pre-launch security check for startups. Scan a **live web app** (DAST) or a **codebase** (SAST + secrets + dependencies), then our **AI agent reasons over every finding: drops the false alarms, writes the fix, re-scans to prove it, and tells you the attack story in plain words**.

<p>
  <img src="Presentation/assets/Untitled-removebg-preview.png" height="90" alt="NVIDIA" />
  <img src="Presentation/assets/3-removebg-preview.png" height="90" alt="NVIDIA Nemotron 3 Ultra" />
</p>

**Built for the GOMYCODE x NVIDIA hackathon — AI reasoning by NVIDIA Nemotron** (via the NVIDIA NIM API, with a self-hosted vLLM option so code never leaves your infrastructure).

## Live demo (2 minutes, no setup)

No API keys, no waiting: open the agent page with the recorded run and watch the full loop replay — triage verdicts with confidence, proposed diffs with verified badges, ready/not-ready verdict, attack story.

- Dashboard: `http://127.0.0.1:8000` — Web / Codebase / AI-provider tabs
- Agent page: `/agent?demo=1` — instant replay of a real recorded run (no backend needed)
- Full run: `POST /api/agent-scan {"repo_url": "https://github.com/OWASP/NodeGoat"}` — our reference target: **215 findings** (18 critical / 104 high / 78 medium / 15 low, 87 dev-only)

> Never demo a live web scan (up to 20 min) — the recorded web output and the NodeGoat codebase run are the jury path.

## How the AI agent works

Fixed backbone, AI decides inside each step — raw Python loop, no LangGraph/CrewAI:

1. **Scan** — semgrep + gitleaks + OSV (codebase) or Nmap/ZAP/Nuclei/Nikto/testssl/headers (web)
2. **Prefilter (no AI)** — drops dev-only deps, test fixtures and duplicates first, so 215 findings become ~30 sent to the model (5 per call, ~40 lines of code each)
3. **Triage (Nemotron)** — every finding gets `real / false_positive / review` + confidence + reason; rules win over the model on highs, and the run is never `ready` with unconfirmed criticals
4. **Fix + verify** — patch is written on a copy, the fired rule is re-run: `verified=true` only when a re-scan actually passes (OSV/ZAP findings honestly stay unverified)
5. **Story** — findings chained into how an attacker would break in, plus a ready/not-ready ship verdict with blockers

## Measured, not claimed

| Signal | Result | Where |
|---|---|---|
| Reference scan (OWASP NodeGoat) | 215 findings: 18 crit / 104 high / 78 med / 15 low | demo data + replay |
| Triage + eval harness | 31 pytest pass | `hack/friend-a-triage` |
| Labelled eval set | 22 findings | `eval/`, `docs/results.md` |
| ZAP repair (was 1/20 targets, orphan scans) | per-target isolation + budget caps, verified back-to-back on Juice Shop | `web_scanners` |
| Model accountability | every call logs model, latency, tokens (never keys) | `app/ai_core.py` on `hack/islam-agent` |

## Responsible AI

- Secrets redacted before any code reaches a cloud model; small windows, never whole files
- Fallback chain (second provider, then non-AI result) — the agent stops fixing instead of hallucinating when AI is down
- Patches are suggestions a human applies; scans are read-only, consent-signed, SSRF-guarded
- Fully local option: Ollama / LM Studio, zero data leaves the machine

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
| `GET` | `/health` | Health check |

If `API_KEY` is set in `.env`, send header `X-API-Key: <key>` on every `/api/*` call.

Key env vars: `ZAP_API_KEY`, `ALLOW_PRIVATE_TARGETS` (lab scans only), `SCAN_MAX_PARALLEL`, `OSV_MAX_GROUPS` (default 300), `AI_PROVIDER/BASE_URL/API_KEY/MODEL`, `AI_REVIEW_MAX_FILES/BYTES`, `GIT/GITLEAKS/SEMGREP/OSV_BIN`. See `.env.example` for the full list.

## Project structure

```
app/
├── main.py               # FastAPI app + routes + text reports
├── config.py             # Settings from .env
├── models.py             # ScanJob, RepoScanJob, Finding (cwe/owasp/cvss), AI models
├── pipeline.py           # Web scanner orchestration + finalize/pause
├── repo_pipeline.py      # Clone -> scanners -> optional AI + summary
├── normalize.py          # Severity maps, prioritize, cross-scanner dedupe
├── cvss.py               # Local CVSS v3.1 calculator (OSV vectors)
├── ai.py                 # BYO AI (any OpenAI-compatible provider)
├── ai_review.py          # Two-phase nominate+batch code review
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
    ├── index.html        # Dashboard (web + codebase + AI tabs, picker)
    ├── scan.html         # Results (counts, fix-first, filters, reports)
    ├── status.html       # Live status + activity feed
    ├── logo.png          # OctoSec Labs logo + favicon
    └── fonts/            # Space Grotesk + JetBrains Mono (self-hosted, CSP-safe)
semgrep-rules/            # Custom logic-flaw rules (NoSQLi/IDOR/redirect/SSRF/XSS)
data/scans/ data/repos/   # Results + clones (gitignored)
scan_toolkit/          # Mobile app security assessment toolkit (CLI, local-first)
                       # — Phase 1 scaffold: ORM models + CLI stubs. See scan_toolkit/README.md.
tests/                 # pytest suite
data/                  # Local data — DB + per-engagement artifacts (gitignored)
```

## Known limits (honest)

- Static scans catch secrets, known CVEs and risky sinks — business-logic flaws (authz/IDOR across files) need the AI pass or manual review. A clean static result does not mean secure (also stated on the dashboard).
- OSV scope analysis is name-level: a package reachable from both prod and dev counts as runtime.
- OSV needs network for its database; groups capped at `OSV_MAX_GROUPS`.
- Gitleaks evidence stores a redacted secret prefix in `job.json`.

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

Tooling under evaluation: `androguard` (manifest/dex parsing) + `apksigner`/`keytool` (cert info), same scanner interface (`ApkScanner`), same Finding model (adds `cwe`/`owasp` where mappings exist), same dedupe/summary/report pipeline. Storage: `data/apks/` (gitignored), original APK hashed (SHA-256) and retained per-scan with size caps.

## Contributing

1. Fork the repo
2. Create a feature branch (`feature/...`)
3. Make changes and test against a local target (DVWA/NodeGoat for web+codebase)
4. Open a PR

## License

MIT
