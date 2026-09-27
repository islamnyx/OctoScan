# Demo Script — scan-toolkit (90-second clean take)

**Pre-warm steps (do BEFORE hitting record):**
1. `cd ~/Desktop/startup-mvp && source .venv/bin/activate`
2. Delete any leftover test engagements: `python -m scan_toolkit status` (just to confirm DB is live)
3. Open a terminal at font size 16+ — make sure the output fits on screen
4. The APK is already at `test-fixtures/UnCrackable-Level1.apk`

---

## Take script (type slowly, pause between commands)

```bash
# Step 1 — Create engagement
scan-toolkit intake create \
  --client "ACME Corp" \
  --platform android \
  --confirm-scope \
  --binary test-fixtures/UnCrackable-Level1.apk

# Pause — point to the engagement ID printed.  Set it:
export EID=<id printed above>

# Step 2 — Validate and move to scanning
scan-toolkit intake validate $EID

# Step 3 — Run static analysis (decompile + Semgrep + LLM triage)
# This takes ~30s.  Narrate: "apktool decodes, jadx decompiles to Java,
# Semgrep finds CWE-327.  The LLM agent is now triaging the raw findings."
scan-toolkit run --engagement $EID --stage static --analyze

# Step 4 — Human review gate (list then confirm)
scan-toolkit review --engagement $EID
scan-toolkit review --engagement $EID --confirm <finding-id>

# Step 5 — Correlation pass
scan-toolkit correlate --engagement $EID

# Step 6 — Generate report (LLM writes full Markdown)
# Narrate: "The Report Agent produces a client-ready assessment now."
scan-toolkit report --engagement $EID --format md

# Step 7 — Show the report
cat data/engagements/$EID/reports/report-*.md
```

---

## Talking points while waiting for LLM calls

- "The LLM gets the raw Semgrep findings in structured JSON — no hallucination, only findings the tool actually flagged."
- "The human review gate is enforced in code — the report command refuses to run until findings are explicitly confirmed."
- "The pipeline is local-first: your APK never leaves the machine. LLM only sees normalized finding data, not the full APK."
- "The same pipeline works for IPA files with the same commands — just `--platform ios`."

---

## Backup: if LLM is slow during recording
Pre-run the whole pipeline before hitting record, then just `cat` the outputs for the camera.
The report is already at `data/engagements/9dda45bffc5c/reports/report-20260926.md`
