# scan_toolkit — Mobile App Security Assessment Toolkit

Local-first internal toolkit for running mobile app vulnerability assessments
as direct client engagements. Lives alongside the web scanner (`app/`) in this
repo on the `mobile-app-scanning` branch but is a **fully independent tool**.

Deterministic scanners (Semgrep, MobSF, OSV/Grype, mitmproxy, OWASP ZAP)
produce findings; LLM agents are layered on top **only** to correlate,
prioritize, and write reports — the LLM never invents findings.

`scan_toolkit` is built incrementally in phases. Phases 1–7 are implemented
(static/SCA/API pipelines + agents, intake, SQLite job queue); dynamic
analysis (Phase 8), correlation (9), reporting (10), and status/polish (11)
remain. See the root README for the current phase table and workflows.

## Layout

```
scan_toolkit/
├── __init__.py      package docstring + __version__
├── __main__.py      python -m scan_toolkit entrypoint
├── main.py          Typer CLI root (owns the scan-toolkit command)
├── config.py        Settings — SCAN_TOOLKIT_* env vars / root .env
├── db.py            SQLAlchemy engine, session factory, init_db()
├── models.py        Engagement, Finding, AttackChain ORM models + to_dict()
└── cli/
    ├── intake.py    Phase 2 (stub)
    ├── run.py       Phase 3+ (stub)
    ├── status.py    Phase 11 (stub)
    └── report.py    Phase 10 (stub)
tests/               pytest suite (in-memory SQLite, never touches data/)
```

## Usage

Phase 1 ships a CLI skeleton — the four subcommands are stubs that report
which phase implements them:

```bash
# From the repo root — zero install:
python -m scan_toolkit --help
python -m scan_toolkit intake

# After `pip install -e .` (optional) the same commands are `scan-toolkit ...`.
```

## Configuration

All values come from the root `.env` (template: `.env.example`) with a
`SCAN_TOOLKIT_` prefix, so they never collide with the web app's vars. Never
hardcode credentials or tool paths.

| Variable | Default | Notes |
|---|---|---|
| `SCAN_TOOLKIT_DATA_DIR` | `./data` | Local data + DB + per-engagement artifacts |
| `SCAN_TOOLKIT_DB_URL` | *(derived)* | `sqlite+pysqlite:///<data_dir>/toolkit.db` |
| `SCAN_TOOLKIT_ANTHROPIC_API_KEY` | *(empty)* | LLM agent key (Phase 4) |
| `SCAN_TOOLKIT_MAX_CONCURRENT_DYNAMIC_JOBS` | `2` | Dynamic job queue cap (Phase 6) |
| `SCAN_TOOLKIT_APKTOOL_BIN` / `_JADX_BIN` / `_SEMGREP_BIN` | tool name | Reserved, Phase 3 |
| `SCAN_TOOLKIT_MOBSF_BASE_URL` / `_MOBSF_API_KEY` | localhost:8000 | MobSF service (Phase 3) |
| `SCAN_TOOLKIT_ZAP_BASE_URL` / `_ZAP_API_KEY` | localhost:8090 | ZAP daemon (Phase 7) |
| `SCAN_TOOLKIT_MITMDUMP_BIN` | `mitmdump` | Capture helper — HAR files are the stage input (Phase 7) |

## Data model

`Engagement` → `Finding` (many) and `AttackChain` (many), stored in SQLite via
SQLAlchemy. `Finding.related_finding_ids` and `AttackChain.finding_ids` are
soft references (JSON lists of ids) rather than foreign keys, because they can
cross rows/engagements. `to_dict()` on every model returns exactly the schema
documented in the spec — that dict is the interchange contract consumed by the
LLM normalizer in later phases.

## Tests

```bash
python -m pytest tests/ -q
```

Tests use an in-memory SQLite DB; running them never writes to `data/`.