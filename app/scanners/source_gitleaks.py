"""Gitleaks wrapper (Phase 2).

Tries `gitleaks detect --source repo --report-format json`;
falls back to builtin-secrets when the binary is missing so
repo scans work on laptops without extra installs.
"""
from __future__ import annotations

import json
import subprocess

from app.config import ROOT, settings
from app.models import Finding, Severity
from app.scanners.source_base import SourceScanner
from app.scanners.source_builtin import BuiltinSecretsScanner

SEV_BY_TAG = (("high", Severity.high), ("medium", Severity.medium))


class GitleaksScanner(SourceScanner):
    name = "gitleaks"

    def _fallback(self, note: str) -> list[Finding]:
        base = BuiltinSecretsScanner(self.repo_path, self.repo_url).run()
        out: list[Finding] = []
        for f in base:
            if f.title.startswith("No hardcoded secrets"):
                out.append(f.model_copy(update={
                    "scanner": self.name,
                    "title": "No secrets found (gitleaks unavailable, builtin pass)",
                    "description": f"{f.description} ({note}).",
                }))
            else:
                out.append(f.model_copy(update={"scanner": self.name}))
        return out

    def run(self) -> list[Finding]:
        out = self.repo_path / ".gitleaks-report.json"
        cfg = ROOT / ".gitleaks.toml"
        cmd = [
            settings.gitleaks_bin, "detect",
            "--source", str(self.repo_path),
            "--report-format", "json",
            "--report-path", str(out),
            "--no-git",
        ]
        if cfg.exists():
            cmd += ["--config", str(cfg)]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        except FileNotFoundError:
            return self._fallback("gitleaks binary not found")
        except subprocess.TimeoutExpired:
            raise RuntimeError("gitleaks timed out")
        if not out.exists():
            return self._fallback("gitleaks produced no report")
        try:
            items = json.loads(out.read_text() or "[]")
        except Exception:
            return self._fallback("gitleaks output unparseable")
        findings: list[Finding] = []
        for it in items if isinstance(items, list) else []:
            if not isinstance(it, dict):
                continue
            rule = str(it.get("RuleID") or it.get("Description") or "secret")
            path = self._rel(str(it.get("File") or ""))
            sev = Severity.medium
            tags = " ".join(it.get("Tags") or []).lower()
            for tag, s in SEV_BY_TAG:
                if tag in tags:
                    sev = s
            findings.append(
                Finding(
                    scanner=self.name,
                    title=f"Gitleaks {rule} in {path}",
                    severity=sev,
                    description=str(it.get("Description") or rule)[:400],
                    evidence=str(it.get("Secret") or "")[:40] + "…",
                    location=f"{self.repo_url}#{path}:{it.get('StartLine') or ''}",
                    recommendation="Remove secret, rotate it, purge from git history.",
                    raw={"rule": rule, "file": path},
                )
            )
            if len(findings) >= 100:
                break
        if not findings:
            findings.append(
                Finding(
                    scanner=self.name,
                    title="No secrets found (gitleaks)",
                    severity=Severity.info,
                    description="Gitleaks completed without matches.",
                    location=self.repo_url or str(self.repo_path),
                )
            )
        return findings
