# Triage eval (Friend A) — real numbers only

> Status: **labels done (22), live-model run pending**. Scans exist on this
> machine (`data/repos/43d3ad8721764e6e` NodeGoat,
> `data/repos/8a617195bea940e6` Juice Shop); no provider is configured yet
> (`.env` `AI_BASE_URL`/`AI_MODEL` empty — see `TO_DO.md` §1, reprompt when
> the Brev host/tag or NVIDIA key is ready). This file will be overwritten
> by `eval/run_triage.py` with measured accuracy, false-positive rate,
> confusion table, median latency, tokens (from `data/ai_calls.jsonl`) and
> model id. No numbers are invented here.

## Inputs (measured, this machine)
- NodeGoat `43d3ad8721764e6e`: 111 files, 14 findings (9 gitleaks + 4 semgrep
  heuristic + 1 osv-unavailable-info). No semgrep/gitleaks/osv binaries on
  this box → builtin-heuristic fallback (Islam's box: 215 with real binaries).
- Juice Shop `8a617195bea940e6`: 1298 files, 34 findings (20 gitleaks + 13
  semgrep heuristic + 1 osv-unavailable-info).
- Labels `eval/labels.json`: 22 (12 NodeGoat: 7 real + 5 FP; 10 Juice Shop:
  6 real + 4 FP). NodeGoat shortfall 12-not-20: only 12 evaluable findings
  exist here (2 info); all are labelled — see `TO_DO.md` §2 for the rationale
  per finding.
- Prefilter sanity (no AI): NodeGoat 14 → 10 kept (drops 2 fixtures + 2 info);
  Juice Shop 34 → 28 kept. Verified via `prefilter()`.

## Method
- Labels: `eval/labels.json` — 20 NodeGoat + 10 Juice Shop findings,
  `finding_id -> real|false_positive` (hand-labelled from the scans above).
- Prefilter: `prefilter(findings, limit=30)` (drop `raw.scope == "dev"`,
  `raw.likely_test_fixture`, severity info, scanner `ai-code-review`;
  keep `prioritize()` order).
- Triage: `triage(findings, workdir)`, 5 findings per `call_json` call
  (`purpose=triage`), `AIError -> review/0.0`.
- Metrics: accuracy = exact match on real|false_positive (review counts as
  wrong); FP rate = actual-FP called real / all actual-FP; latency/tokens
  from `data/ai_calls.jsonl` entries with `purpose=triage` since run start.

## How to reproduce
```bash
.venv/bin/python eval/run_triage.py
# optional overrides:
.venv/bin/python eval/run_triage.py --nodegoat <id> --juiceshop <id> --limit 30
```
Requires a configured provider (`.env`: `AI_PROVIDER`/`AI_BASE_URL`/
`AI_API_KEY`/`AI_MODEL`, or `data/ai_config.json` profile). The script
refuses to write metrics when no provider is reachable.
