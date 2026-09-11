# Security Precheck

Pre-launch security check for Algerian startups. Orchestrates Nmap, OWASP ZAP, and testssl.sh into a unified scan, normalizes their output, and shows prioritized findings on a simple dashboard.

## What it does

- Scans a target URL with **Nmap** (ports/services), **OWASP ZAP** (web vulnerabilities), **testssl.sh** (TLS/SSL config), **headers** (security headers + cookie flags) and **Nikto** (known-path/CGI misconfigurations)
- Normalizes all findings into one consistent format
- Prioritizes by severity and shows results in a web dashboard
- Exports results as JSON or plain-text report

## Prerequisites

| Tool | Install | Notes |
|------|---------|-------|
| Nmap | `sudo apt install nmap` | Path: `/usr/bin/nmap` |
| Nikto | `sudo apt install nikto` | Path: `/usr/bin/nikto`, bounded with `-maxtime 240s -Tuning x6` |
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

# 5. Start ZAP daemon
java -Xmx512m -jar /usr/share/zaproxy/zap-2.17.0.jar \
  -daemon -port 8090 -host 127.0.0.1 \
  -config api.key=test -config api.disablekey=true

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
| `GET` | `/health` | Health check |

If `API_KEY` is set in `.env`, include header `X-API-Key: <your-key>` when calling `POST /api/scans`.

## Project structure

```
app/
├── main.py           # FastAPI app + routes
├── config.py         # Settings from .env
├── models.py         # ScanJob, Finding, Severity
├── pipeline.py       # Parallel scanner execution
├── normalize.py      # Severity mapping + prioritization
├── store.py          # JSON file persistence
├── scanners/
│   ├── base.py       # Base scanner class
│   ├── nmap_scanner.py
│   ├── zap_scanner.py
│   ├── testssl_scanner.py
│   ├── headers_scanner.py
│   └── nikto_scanner.py
│   └── stubs.py      # Gitleaks + Dependency-Check placeholders
└── static/
    └── index.html    # Dashboard

data/scans/           # Scan results (gitignored)
```

## Contributing

1. Fork the repo
2. Create a feature branch
3. Make changes and test against a local target
4. Open a PR

## License

MIT
