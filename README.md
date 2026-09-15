# OctoScan by OctoSec Labs

Pre-launch security check for Algerian startups. Orchestrates Nmap, OWASP ZAP, and testssl.sh into a unified scan, normalizes their output, and shows prioritized findings on a simple dashboard.

## What it does

- Scans a target URL with **Nmap** (ports/services), **OWASP ZAP** (web vulnerabilities), **testssl.sh** (TLS/SSL config), **headers** (security headers + cookie flags), **Nikto** (known-path/CGI misconfigurations) and **Nuclei** (thousands of CVE/misconfiguration/exposure templates, always full-depth)
- Re-examines every discovered URL for **exposed sensitive files** (`.kdbx`, `.env`, `.bak`, keys, DB dumps…) as their own high-severity findings
- Actively probes well-known paths (`/.git/HEAD`, `/.git/config`, `/.env`, `/.DS_Store`) with content-signature verification, so exposures are caught even when no crawler discovers them
- Normalizes all findings into one consistent format
- Prioritizes by severity and shows results in a web dashboard
- Exports results as JSON or plain-text report

## Prerequisites

| Tool | Install | Notes |
|------|---------|-------|
| Nmap | `sudo apt install nmap` | Path: `/usr/bin/nmap` |
| Nikto | `sudo apt install nikto` | Path: `/usr/bin/nikto`, bounded with `-maxtime 240s -Tuning x6` |
| Nuclei | [projectdiscovery.io](https://github.com/projectdiscovery/nuclei#installation) + `nuclei -update-templates` | Path: `/usr/bin/nuclei`, full template set, JSONL output, severity gate via `NUCLEI_SEVERITY` (default `critical,high,medium,low`) |
| OWASP ZAP | Download from [zaproxy.org](https://www.zaproxy.org/download/) | Extract to `resources/zaproxy/`, run with `-daemon` |
| testssl.sh | `git clone https://github.com/drwetter/testssl.sh.git resources/testssl.sh` | Run `resources/testssl.sh/testssl.sh` or set `TESTSSL_BIN` |
| Gitleaks | `sudo apt install gitleaks` or build from source | Reserved for Phase 2 source scans |
| Dependency-Check | `sudo apt install dependency-check` or download from [OWASP](https://owasp.org/www-project-dependency-check/) | Reserved for Phase 2 |

> **Note:** `resources/` is gitignored — each tool must be installed separately. |

```bash
# 1. Clone the repo
git clone https://github.com/<your-org>/startup-mvp.git
cd startup-mvp

# 2. Create virtualenv
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env and set API_KEY if you want auth enabled

# 5. Start ZAP daemon (authenticated — never disablekey=true)
# 4g heap (1g OOM-crashed Juice Shop 2026-09-13), offline flags stop the
# "ZAP is Out of Date" passive rule hanging 60s/url with no internet.
ZAP_API_KEY="$(openssl rand -hex 32)"; echo "ZAP_API_KEY=$ZAP_API_KEY" >> .env
java -Xmx4g -jar /usr/share/zaproxy/zap-2.17.0.jar \
  -daemon -port 8090 -host 127.0.0.1 -newsession clean \
  -config api.key=$ZAP_API_KEY -config api.disablekey=false \
  -config autoupdate.checkOnStart=false -config callhome.callHome=false

# 6. Start the API
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000

## API

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scans` | Start a scan. Body: `{"target_url": "https://example.com"}` |
| `GET` | `/api/scans` | List all scans |
| `GET` | `/api/scans/{id}` | Get scan details |
| `GET` | `/api/scans/{id}/export` | Download scan as JSON |
| `GET` | `/api/scans/{id}/report` | Download scan as plain-text report |
| `POST` | `/api/scans/{id}/ai-analyze` | AI triage of a URL scan (needs AI config) |
| `POST` | `/api/repo-scans` | Scan a codebase. Body: `{"repo_url": "https://github.com/org/repo", "branch": null, "include_ai": false}` |
| `GET` | `/api/repo-scans` | List repo scans |
| `GET` | `/api/repo-scans/{id}` | Get repo scan details |
| `POST` | `/api/repo-scans/{id}/ai-analyze` | AI triage of a repo scan |
| `GET` | `/api/ai/config` | AI provider config (key masked) |
| `PUT` | `/api/ai/config` | Save AI config. Body: `{"provider": "openai", "base_url": ".../v1", "api_key": "...", "model": "gpt-4o-mini"}` |
| `POST` | `/api/ai/test` | Test AI connection |
| `GET` | `/health` | Health check |

If `API_KEY` is set in `.env`, include header `X-API-Key: <your-key>` when calling `POST /api/scans`.

## Project structure

```
app/
├── main.py           # FastAPI app + routes
├── config.py         # Settings from .env
├── models.py         # ScanJob, RepoScanJob, Finding, Severity, AI models
├── ai.py             # BYO AI (any OpenAI-compatible provider)
├── repo.py           # Safe https repo clone + file caps
├── repo_pipeline.py  # Clone -> Gitleaks/Semgrep -> optional AI
├── repo_store.py     # Repo job persistence (data/repos/)
├── pipeline.py       # Parallel scanner execution
├── normalize.py      # Severity mapping + prioritization
├── sensitive.py      # Sensitive-file exposure post-pass over discovered URLs
├── store.py          # JSON file persistence
├── scanners/
│   ├── base.py       # Base URL scanner class
│   ├── source_base.py    # Base source scanner class
│   ├── source_gitleaks.py # Secrets (binary or builtin fallback)
│   ├── source_semgrep.py  # SAST (binary or heuristic fallback)
│   ├── source_builtin.py  # Builtin secret regex fallback
│   ├── nmap_scanner.py
│   ├── zap_scanner.py
│   ├── testssl_scanner.py
│   ├── headers_scanner.py
│   ├── nikto_scanner.py
│   └── nuclei_scanner.py   # CVE/misconfig templates (full run, JSONL)
│   └── stubs.py      # Dependency-Check placeholder
└── static/
    └── index.html    # Dashboard (URL + repo + AI config)

data/scans/           # Scan results (gitignored)
data/repos/           # Repo clones + results (gitignored)
```

## Contributing

1. Fork the repo
2. Create a feature branch
3. Make changes and test against a local target
4. Open a PR

## License

MIT
