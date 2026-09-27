# TO-DO (Friend A eval — live-model run still open)

## 1. Provider (blocked: no Brev host/tag, no NVIDIA key yet)
- [ ] Brev/Ollama: get reachable base URL + exact Qwen3 tag from teammate #1
      (`ollama list` on the Brev server). Confirm `OLLAMA_HOST=0.0.0.0` on the
      server so it accepts external connections.
- [ ] Verify before finalizing: `curl <AI_BASE_URL>/v1/models`
- [ ] Set in gitignored `.env` (never commit, never paste `nvapi-...` in chat):
      `AI_PROVIDER=ollama`, `AI_BASE_URL=http://<brev-host>:11434/v1`,
      `AI_MODEL=<exact tag from ollama list>`
- [ ] Fallback alternative (docs/NEXT.md §0): free key at build.nvidia.com,
      `AI_PROVIDER=nvidia`, `AI_BASE_URL=https://integrate.api.nvidia.com/v1`,
      `AI_API_KEY=nvapi-...`, `AI_MODEL=<exact id from the model page>`
- [ ] Check: `.venv/bin/python -c "from app import ai_core; print(ai_core.call_text([{'role':'user','content':'Reply ok'}], max_tokens=200))"`
- [ ] If repo is public/shared: keep real host only in local `.env`, use
      `http://<BREV_HOST>:11434/v1` placeholder in any committed doc.

## 2. Labels (done: 22/30 — shortfall documented)
- `eval/labels.json` holds 12 NodeGoat + 10 Juice Shop verdicts
  (`finding_id -> real|false_positive`), hand-labelled from code windows.
- NodeGoat shortfall (12 not 20): this box has no semgrep/gitleaks/osv
  binaries, so scans fall back to builtin heuristics → 14 findings total
  (2 info) vs 215 on Islam's box. All 12 evaluable findings are labelled:
  real = DAO NoSQL/plaintext-password, hardcoded cookie/crypto/ZAP secrets,
  `eval(req.body.*)` in contributions.js; false_positive = Gruntfile exec
  heuristics, livereload `document.write` in dev config, tutorial/test fixtures.
- Juice Shop 10/10: real = RSA private key in `lib/insecurity.ts`, leaked-key
  IaC challenge snippets, fileUpload deserialization surface, NoSQL
  `likeProductReviews`, query-param `changePassword`; false_positive =
  datacreator/login/spec fixtures + `codingChallenges` heuristic misfire.
- [ ] If semgrep binary becomes available: re-scan, extend to 20+10, re-run.

## 3. Live eval (blocked on §1)
- [ ] `.venv/bin/python eval/run_triage.py` (writes `docs/results.md` with
      accuracy, FP rate, confusion table, median latency, tokens, model id)
- [ ] Commit `eval/labels.json` + `docs/results.md` + progress entry, push
      `hack/friend-a-triage`, tell Islam.
