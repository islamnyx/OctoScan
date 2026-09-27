# islam - progress log (hackathon 27 Sep 2026)

## 01:15 - Environment ready
- Done: setup script ran; semgrep, gitleaks, osv-scanner installed; NodeGoat scan saved as demo data (215 findings)
- State: works (smoke test passed)
- Next: verify with Claude Code, push hack/setup, get NVIDIA API key
- Decisions: omniroute proxy settings parked; team rules in AGENTS.md; ownership in docs/TEAM.md

## 12:02 - AI-layer fixes + ai_core (branch hack/islam-core, b6dd720)
- Done: new app/ai_core.py (call_json/call_text: <think>+fence strip, pydantic + 1 repair retry, provider fallback chain incl. .env AI_*, secret redaction on every message, call log data/ai_calls.jsonl + stats()); ai.chat_complete delegates to it; analyze_findings validated JSON + non-AI fallback; balanced digest (NodeGoat: 19 osv/19 semgrep/2 gitleaks, 0 dev-only); ai_review nomination fix + numbered ~30-line code windows (8 KB/file cap); NVIDIA + Brev presets (ai.py, index.html)
- State: works offline — 17 pytest pass (.venv/bin/python -m pytest tests -q), app smoke OK; NOT yet tested live: no AI provider configured on this machine
- Next: add NVIDIA key + model id via dashboard, live smoke of call_json; then pre-filter -> triage
- Decisions: call_json contract as in HANDOFF §3 (+ meta attempts/redactions); structured output (json_schema) only for provider "brev"/"vllm"; problem 7 (/ai-analyze blocking) handled by the background-thread agent, old endpoint unchanged; pytest in requirements-dev.txt
