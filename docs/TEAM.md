# Team board: who owns what (edit this first thing at 11:15)

Rule: one owner per file. Only the owner edits it. Everyone else asks via "Requests".

| Person | Tool | Branch | Owns (files) | Task |
|---|---|---|---|---|
| Islam | Claude Code | hack/islam-core | app/ai_fix.py, app/models.py, app/main.py | AI engine + API contract + merges |
| ? | Antigravity | hack/?-ui | app/static/fix.js, app/static/scan.html | Dashboard UI for AI results |
| ? | OpenCode | hack/?-eval | eval/*, docs/results.md | Labelled test set + measured numbers |
| ? | any | hack/?-docs | docs/project-card.md, docs/disclosure.md, video | Submission + 90 s video |

## API contract (frozen at 11:45; change only via integrator)
- `POST /api/repo-scans/{id}/ai-fix` -> starts AI fix job for top findings
- `GET  /api/repo-scans/{id}/ai-fix` -> `[{finding_id, verdict, confidence, reasoning, patch, verified, model, latency_ms}]`
  (the UI person builds against a fake JSON file with this shape until the endpoint is merged)

## Sync points (integrator merges into main, everyone pulls)
- 11:45  contract + skeletons merged
- 13:00  first working vertical slice
- 15:30  feature freeze (merge everything, run smoke test)
- 17:00  final: submission links checked

## Requests (need a change in a file you don't own? write it here)
-
