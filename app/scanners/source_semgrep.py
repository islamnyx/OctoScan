"""Semgrep wrapper (Phase 2).

Tries `semgrep --config auto --json`; falls back to a small
dangerous-pattern heuristic so repo scans work without installs.
"""
from __future__ import annotations

import json
import re
import subprocess

from app.config import settings
from app.models import Finding, Severity
from app.repo import iter_repo_files
from app.scanners.source_base import SourceScanner

HEURISTICS: list[tuple[str, re.Pattern[str], Severity, str]] = [
    ("SQL string concatenation",
     re.compile(r"(SELECT|INSERT|UPDATE|DELETE).{0,40}\+\s*\w|f['\"].*(SELECT|WHERE)", re.I | re.S),
     Severity.medium, "Possible SQL injection. Use parameterized queries."),
    ("Hardcoded crypto bypass",
     re.compile(r"(verify\s*=\s*False|CERT_NONE|InsecureSkipVerify|TLSClientConfig\s*:\s*&tls\.Config\{\})"),
     Severity.high, "TLS verification disabled. Re-enable and pin CA."),
    ("Shell injection sink",
     re.compile(r"(os\.system|subprocess\.(call|Popen|run)\s*\(.*shell\s*=\s*True|child_process\.exec)"),
     Severity.medium, "Shell execution with possible user input. Avoid shell=True."),
    ("Weak crypto",
     re.compile(r"\b(MD5|SHA1|DES|RC4)\b"),
     Severity.low, "Weak crypto primitive. Prefer SHA-256+/AES-GCM/bcrypt."),
]

CODE_EXTS = {".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".rb", ".php"}


class SemgrepScanner(SourceScanner):
    name = "semgrep"

    def run(self) -> list[Finding]:
        try:
            return self._via_binary()
        except FileNotFoundError:
            return self._via_heuristics("semgrep binary not found, heuristic pass")
        except RuntimeError as exc:
            if "not found" in str(exc).lower():
                return self._via_heuristics(str(exc))
            raise

    def _via_binary(self) -> list[Finding]:
        out = self.repo_path / ".semgrep.json"
        cmd = [
            settings.semgrep_bin, "--config", "auto",
            "--json", "--output", str(out), "--quiet",
            str(self.repo_path),
        ]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        except FileNotFoundError:
            raise RuntimeError("semgrep binary not found")
        if not out.exists():
            return self._via_heuristics("semgrep produced no output")
        try:
            data = json.loads(out.read_text())
            results = data.get("results", [])
        except Exception:
            return self._via_heuristics("semgrep output unparseable")
        findings: list[Finding] = []
        for r in results[:100]:
            if not isinstance(r, dict):
                continue
            check = str(r.get("check_id", "semgrep"))
            path = str(r.get("path", ""))
            sev_raw = str((r.get("extra") or {}).get("severity", "INFO")).upper()
            sev = {"ERROR": Severity.high, "WARNING": Severity.medium}.get(sev_raw, Severity.low)
            findings.append(
                Finding(
                    scanner=self.name,
                    title=f"Semgrep {check} in {path}",
                    severity=sev,
                    description=str((r.get("extra") or {}).get("message") or check)[:500],
                    evidence=str(r.get("extra") or {}).get("lines", "")[:300],
                    location=f"{self.repo_url}#{path}:{r.get('start', {}).get('line', '')}",
                    recommendation="Review the flagged pattern and apply the rule's fix.",
                    raw={"check": check, "file": path},
                )
            )
        if not findings:
            findings.append(Finding(
                scanner=self.name, title="No SAST findings (semgrep)",
                severity=Severity.info,
                description="Semgrep completed without matches.",
                location=self.repo_url or str(self.repo_path),
            ))
        return findings

    def _via_heuristics(self, note: str) -> list[Finding]:
        findings: list[Finding] = []
        for path in iter_repo_files(self.repo_path):
            if path.suffix.lower() not in CODE_EXTS:
                continue
            try:
                text = path.read_text(errors="ignore")
            except Exception:
                continue
            rel = str(path.relative_to(self.repo_path))
            for title, rx, sev, rec in HEURISTICS:
                if rx.search(text):
                    findings.append(Finding(
                        scanner=self.name,
                        title=f"{title} in {rel} (heuristic)",
                        severity=sev, description=f"{title} pattern in {rel}. {note}.",
                        location=f"{self.repo_url}#{rel}" if self.repo_url else rel,
                        recommendation=rec, raw={"file": rel, "heuristic": title},
                    ))
                    break
            if len(findings) >= 50:
                break
        if not findings:
            findings.append(Finding(
                scanner=self.name, title="No SAST patterns (heuristic)",
                severity=Severity.info,
                description=f"Heuristic SAST pass clean. {note}.",
                location=self.repo_url or str(self.repo_path),
            ))
        return findings
