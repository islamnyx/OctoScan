# Submission — scan-toolkit

## Project Story (≤150 words)

Mobile penetration testers spend hours manually reviewing decompiled APK source
for recurring vulnerability patterns — weak crypto, hardcoded secrets, insecure
storage — before they can write a single line of the client report.
scan-toolkit automates that first pass.

You hand it an APK. It decompiles the app with jadx, runs Semgrep against the
Java source using a focused OWASP MASTG-aligned ruleset, then sends the raw
finding evidence to an LLM agent for triage — severity, CWE mapping,
remediation, affected component — all in structured JSON, all human-reviewable
before a single word reaches the client. A second LLM pass writes the full
Markdown report from confirmed findings only.

Everything runs locally. The APK never leaves the analyst's machine. The next
step is adding dynamic analysis (Frida instrumentation) and the SCA pipeline
(OSV.dev CVE matching on extracted dependencies) to the demo scope.

**Tech:** Python, Typer CLI, SQLite/SQLAlchemy, Semgrep, jadx, apktool,
OpenCode Zen (space-bunny-free model), httpx, reportlab, python-docx.

---

## AI / Tool Disclosure

**What this project does — honest description for reviewers:**

### Real AI — verified live during the hackathon

- **Static Analysis Agent** (`scan_toolkit/agents/static.py`): makes a real
  HTTP POST to `https://opencode.ai/zen/v1/chat/completions` using the
  `space-bunny-free` model via the OpenCode Zen API.  Input: normalized
  Semgrep findings in structured JSON.  Output: severity, CWE, remediation,
  affected component — validated against a strict JSON schema before being
  written to the database.  Not hardcoded.  Not mocked.  Verified live with
  the OWASP UnCrackable Level 1 APK producing `CWE-327 / AES-ECB` findings.

- **Correlation Agent** (`scan_toolkit/agents/correlation.py`): real LLM call,
  deduplicates findings across agents and builds attack chains.

- **Report Agent** (`scan_toolkit/agents/report.py`): real LLM call that
  writes the full client-ready Markdown assessment from confirmed findings.
  Verified live — produced a 3,000+ word report with accurate remediation
  guidance.  The `_write_empty()` fallback path was NOT triggered; confirmed
  by the `INFO: Generating report` log timestamp.

### Real deterministic tools — verified working

- **jadx 1.5.6**: decompiles the APK to Java source (verified — 6 .java files
  from UnCrackable Level 1).
- **apktool 3.0.3**: decodes APK resources and smali (verified — ran without
  errors).
- **Semgrep 1.178.0**: static analysis against 4 bundled OWASP Android rules
  (verified — found 2 raw findings, CWE-327, in `sg/vantagepoint/a/a.java`).
- **OSV.dev API**: real HTTP client for SCA dependency CVE lookup — working
  code, architecture validated by 251 passing tests, not exercised in today's
  demo (no build.gradle available for the crackme APK).

### Not active in today's demo — present in the architecture, honest about it

- **MobSF**: real runner code (`tools/mobsf.py`), now with a real health
  check — returns `available=False` when not running.  Not demoed because
  MobSF requires a Docker service not present in this environment.
- **ZAP / mitmproxy** (API stage, Phase 7): real code, requires a running ZAP
  daemon and captured HAR traffic files.  Not demoed — no live test backend.
- **Grype 0.119.0** (SCA): installed, vulnerability DB current (v6.1.9).
  Runs clean against both test APKs and reports 0 CVEs — a legitimate
  result (neither APK ships dependency manifests, so OSV has nothing to
  query and Grype matches nothing in the decoded tree).  Pipeline proven
  working; needs an app with known-vulnerable bundled libs to show hits.
- **Frida / emulator** (dynamic stage, Phase 8): requires Android emulator
  hardware.  Not installed or demoed.

### Stubs — not reachable from demo path

- `app/scanners/stubs.py` (`GitleaksScanner`, `DependencyCheckScanner`):
  hardcoded placeholder output.  These are in the `app/` web URL scanner (a
  separate tool in the same repo), **not imported anywhere**, and completely
  unreachable from the `scan-toolkit` CLI demo path.  Confirmed by grep.

### Test infrastructure

- 251 tests, all passing.  All external calls (LLM, MobSF, ZAP, OSV) are
  mocked in tests via `httpx.MockTransport` and `unittest.mock`.  The live
  LLM runs only in production; tests never call the real API.

