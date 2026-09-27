# friend-a - progress log (hackathon 27 Sep 2026)

## 14:05 - Triage + prefilter + tests (hack/friend-a-triage)
- Done: `app/ai_triage.py` (locate/prefilter/code_window/triage, 5 per call_json, AIError->review), `tests/test_ai_triage.py` (11 tests, stubbed call_json), `eval/run_triage.py` (real-model eval -> docs/results.md)
- State: works — `.venv/bin/python -m pytest tests -q` 31 passed (20 existing + 11 new)
- Next: codebase scans for NodeGoat + Juice Shop (binaries missing on this box, builtin fallback only), hand-label 20+10 in eval/labels.json, live eval with Brev/Ollama Qwen3 model, fill docs/results.md with real numbers
- Decisions: contracts from docs/NEXT.md §2 exactly; model only via app.ai_core.call_json (purpose=triage, max_tokens=1500); prefilter keeps prioritize() order; code_window clamps edges, blocks traversal; eval groups by workdir, refuses to invent numbers when no provider is configured
