"""Eval: triage accuracy on 30 hand-labelled findings (20 NodeGoat + 10 Juice Shop).

Labels: eval/labels.json is a flat {finding_id: "real"|"false_positive"} map.
Sources (docs/NEXT.md): NodeGoat data/repos/43d3ad8721764e6e,
Juice Shop data/repos/8a617195bea940e6. If those ids are missing on your
machine, re-create with a codebase scan of
https://github.com/OWASP/NodeGoat and https://github.com/juice-shop/juice-shop,
then update REPO_IDS below (or pass --nodegoat/--juiceshop).

Run: .venv/bin/python eval/run_triage.py [--labels eval/labels.json]
Writes docs/results.md with REAL numbers only: accuracy, false-positive
rate, confusion table, median latency, tokens (from data/ai_calls.jsonl),
model id. Never invent numbers: if the model is unreachable the script
fails instead of writing fake metrics.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.insert(0, str(ROOT))

from app import ai_core  # noqa: E402
from app.ai_triage import prefilter, triage  # noqa: E402
from app.config import settings  # noqa: E402
from app.models import Finding  # noqa: E402
from app.repo_store import repo_workdir  # noqa: E402

NODEGOAT_ID = "43d3ad8721764e6e"
JUICESHOP_ID = "8a617195bea940e6"
N_NODEGOAT = 20
N_JUICE = 10


def load_job_findings(scan_id: str) -> tuple[list[Finding], Path]:
    job_path = settings.data_dir / "repos" / scan_id / "job.json"
    if not job_path.exists():
        raise SystemExit(
            f"missing {job_path}\n"
            f"Re-create with a codebase scan of "
            f"{'https://github.com/OWASP/NodeGoat' if scan_id == NODEGOAT_ID else 'https://github.com/juice-shop/juice-shop'} "
            f"(POST /api/repo-scans) and update REPO_IDS if the new id differs."
        )
    job = json.loads(job_path.read_text())
    findings = [Finding.model_validate(f) for f in job.get("findings", [])]
    return findings, repo_workdir(scan_id)


def _calls_since(ts_iso: str) -> list[dict]:
    out = []
    try:
        for line in ai_core.CALL_LOG_PATH.read_text().splitlines():
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if e.get("ts", "") >= ts_iso and e.get("purpose") == "triage":
                out.append(e)
    except FileNotFoundError:
        pass
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--labels", default="eval/labels.json")
    ap.add_argument("--nodegoat", default=NODEGOAT_ID)
    ap.add_argument("--juiceshop", default=JUICESHOP_ID)
    ap.add_argument("--limit", type=int, default=30)
    args = ap.parse_args()

    labels_path = ROOT / args.labels
    if not labels_path.exists():
        raise SystemExit(f"missing {labels_path}: hand-label {N_NODEGOAT} NodeGoat + {N_JUICE} Juice Shop findings first")
    labels = json.loads(labels_path.read_text())
    if not isinstance(labels, dict) or not labels:
        raise SystemExit(f"{labels_path} must be a non-empty {{finding_id: verdict}} map")

    by_repo = [(args.nodegoat, N_NODEGOAT), (args.juiceshop, N_JUICE)]
    eval_findings: list[tuple[Finding, Path, str]] = []  # (finding, workdir, repo)
    for scan_id, _n in by_repo:
        findings, workdir = load_job_findings(scan_id)
        by_id = {f.id: f for f in findings}
        missing = [fid for fid in labels if fid in by_id]
        _ = missing  # labels are global; pick per-repo hits below
        for f in findings:
            if f.id in labels:
                # sanity: label value must be real|false_positive
                if labels[f.id] not in ("real", "false_positive"):
                    raise SystemExit(f"label {f.id} must be real|false_positive, got {labels[f.id]!r}")
                # only count findings from the expected repo (first match wins)
                if not any(f.id == fid for fid, _, _ in eval_findings):
                    eval_findings.append((f, workdir, scan_id))

    if not eval_findings:
        raise SystemExit("no labelled findings found in either repo job.json — check ids in labels vs scans")

    # Group by workdir: triage() takes one workdir per call.
    from collections import defaultdict
    groups: dict[str, tuple[Path, list[Finding]]] = {}
    for f, wd, _repo in eval_findings:
        key = str(wd)
        if key not in groups:
            groups[key] = (wd, [])
        groups[key][1].append(f)

    # Provider check: fail loudly instead of writing fake numbers.
    chain = ai_core.provider_chain()
    if not chain:
        raise SystemExit("no AI provider configured (.env AI_BASE_URL/AI_MODEL) — refusing to invent numbers")
    model_id = chain[0].get("model", "")
    provider = chain[0].get("provider") or chain[0].get("name", "")

    t0 = datetime.now(timezone.utc).isoformat(timespec="seconds")
    results: list[dict] = []
    per_finding_workdir: dict[str, Path] = {}
    for wd, fs in groups.values():
        # Keep eval to the labelled set; still show what prefilter would do.
        _ = prefilter(fs, limit=args.limit)
        out = triage(fs, wd)
        results.extend(out)
        for f in fs:
            per_finding_workdir[f.id] = wd

    pred = {r["finding_id"]: r for r in results}
    # Confusion: actual (real/fp) x predicted (real/fp/review)
    conf: dict[str, dict[str, int]] = {
        "real": {"real": 0, "false_positive": 0, "review": 0},
        "false_positive": {"real": 0, "false_positive": 0, "review": 0},
    }
    for fid, actual in labels.items():
        if fid not in pred:
            continue
        p = pred[fid]["verdict"]
        if p not in ("real", "false_positive", "review"):
            p = "review"
        if actual in conf and p in conf[actual]:
            conf[actual][p] += 1

    total = sum(sum(r.values()) for r in conf.values())
    correct = conf["real"]["real"] + conf["false_positive"]["false_positive"]
    accuracy = correct / total if total else 0.0
    fp_denom = sum(conf["false_positive"].values())
    fp_rate = conf["false_positive"]["real"] / fp_denom if fp_denom else 0.0

    calls = _calls_since(t0)
    lat = sorted(c.get("latency_ms", 0) for c in calls if c.get("ok"))
    median_ms = int(statistics.median(lat)) if lat else 0
    tok_in = sum(c.get("tokens_in", 0) for c in calls)
    tok_out = sum(c.get("tokens_out", 0) for c in calls)

    results_path = ROOT / "docs" / "results.md"
    results_path.write_text(
        "# Triage eval (Friend A) — real numbers only\n\n"
        f"- Date (UTC): {datetime.now(timezone.utc).isoformat(timespec='seconds')}\n"
        f"- Model: `{model_id}` (provider `{provider}`)\n"
        f"- Labels: `{args.labels}` ({total} findings: "
        f"{sum(conf['real'].values())} NodeGoat-ish + {sum(conf['false_positive'].values())} — "
        f"see eval/labels.json for repo split)\n"
        f"- Repos: NodeGoat `{args.nodegoat}`, Juice Shop `{args.juiceshop}`\n"
        f"- Prefilter limit: {args.limit} (eval runs triage on the labelled set directly)\n\n"
        f"## Metrics\n\n"
        f"- Accuracy: **{accuracy:.2f}** ({correct}/{total})\n"
        f"- False-positive rate: **{fp_rate:.2f}** "
        f"({conf['false_positive']['real']}/{fp_denom} actual-FP called real)\n"
        f"- Median triage latency: **{median_ms} ms** over {len(lat)} ok calls\n"
        f"- Tokens (triage calls since run start, from data/ai_calls.jsonl): "
        f"**{tok_in} in / {tok_out} out** over {len(calls)} logged calls\n\n"
        f"## Confusion (actual x predicted)\n\n"
        f"| actual \\ predicted | real | false_positive | review |\n"
        f"|--------------------|------|----------------|--------|\n"
        f"| real | {conf['real']['real']} | {conf['real']['false_positive']} | {conf['real']['review']} |\n"
        f"| false_positive | {conf['false_positive']['real']} | "
        f"{conf['false_positive']['false_positive']} | {conf['false_positive']['review']} |\n\n"
        f"## Per-finding\n\n"
        f"| finding_id | actual | predicted | confidence | reason |\n"
        f"|------------|--------|-----------|------------|--------|\n"
        + "".join(
            f"| {fid} | {actual} | {pred[fid]['verdict'] if fid in pred else '?'} | "
            f"{pred[fid]['confidence'] if fid in pred else '?'} | "
            f"{(pred[fid]['reason'] if fid in pred else 'not evaluated').replace('|', '/')[:120]} |\n"
            for fid, actual in labels.items()
        )
        + f"\n## Notes\n\n- Triage batches 5 findings per call_json call (purpose=triage).\n"
        f"- AIError maps to verdict=review (counted as incorrect above).\n"
        f"- Numbers come from this run only; re-run to reproduce.\n"
    )
    print(f"wrote {results_path} — accuracy {accuracy:.2f}, fp-rate {fp_rate:.2f}, "
          f"median {median_ms}ms, tokens {tok_in}/{tok_out}, model {model_id}")


if __name__ == "__main__":
    main()
