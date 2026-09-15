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
from app.repo import is_vendored, iter_repo_files
from app.scanners.source_base import SourceScanner

HEURISTICS: list[tuple[str, re.Pattern[str], Severity, str]] = [
    # SQL: keyword followed by concat/interpolation into the string.
    # (Old pattern `f'.*SELECT'` matched plain JS strings -> jquery FPs.)
    ("SQL injection via string building",
     re.compile(
         r"\b(SELECT|INSERT|UPDATE|DELETE)\b[^\"';]{0,80}[\"']\s*[.\+]|"
         r"[\"'][^\"']*\b(SELECT|INSERT|UPDATE|DELETE)\b[^\"']*\$\w+|"
         r"f[\"'][^\"']*\b(SELECT|INSERT|UPDATE|DELETE)\b",
         re.I),
     Severity.high, "SQL query built by concatenation/interpolation. Use parameterized queries."),
    ("OS command injection",
     re.compile(
         r"(shell_exec|exec|system|passthru|popen|proc_open)\s*\([^)]*['\"][^)]*[.\+]|"
         r"(shell_exec|exec|system|passthru|popen|proc_open)\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)|"
         r"os\.system\s*\(|os\.popen\s*\(",
         re.I),
     Severity.high, "OS command built from variables. Use fixed argv lists / escapeshellarg."),
    ("Dynamic file inclusion",
     re.compile(r"\b(include|require)(_once)?\s*\(?\s*\$", re.I),
     Severity.high, "File path from a variable (LFI/RFI). Allow-list include paths."),
    ("Reflected XSS sink",
     re.compile(
         r"(echo|print)\s+[^;]*(\$_(GET|POST|REQUEST|COOKIE)|\$\w+\s*\.\s*\$_)|"
         r"innerHTML\s*=|document\.write\s*\(",
         re.I),
     Severity.medium, "User input echoed/inserted into HTML without escaping."),
    ("Open redirect",
     re.compile(
         r"header\s*\(\s*['\"]Location\s*:.*\$|window\.location(\.href)?\s*=|redirect\s*\(\s*(request\.|request\.GET)",
         re.I),
     Severity.medium, "Redirect target from user input. Validate against an allow-list."),
    ("Unvalidated file upload",
     re.compile(r"move_uploaded_file\s*\(", re.I),
     Severity.high, "Uploaded file stored without type/extension validation. Restrict and rename."),
    ("Insecure deserialization",
     re.compile(r"\bunserialize\s*\(|pickle\.loads\s*\(|yaml\.load\s*\((?!.*Loader)|new\s+\w+\s*\(\s*\$_", re.I),
     Severity.high, "Deserializing untrusted data enables object injection / RCE."),
    ("Hardcoded crypto bypass",
     re.compile(r"(verify\s*=\s*False|CERT_NONE|InsecureSkipVerify|TLSClientConfig\s*:\s*&tls\.Config\{\})"),
     Severity.high, "TLS verification disabled. Re-enable and pin CA."),
    ("Shell injection sink",
     re.compile(r"(subprocess\.(call|Popen|run)\s*\(.*shell\s*=\s*True|child_process\.exec)"),
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
            path = self._rel(str(r.get("path", "")))
            extra = r.get("extra")
            if not isinstance(extra, dict):
                extra = {}
            sev_raw = str(extra.get("severity", "INFO")).upper()
            sev = {"ERROR": Severity.high, "WARNING": Severity.medium}.get(sev_raw, Severity.low)
            start = r.get("start")
            line = start.get("line", "") if isinstance(start, dict) else ""
            findings.append(
                Finding(
                    scanner=self.name,
                    title=f"Semgrep {check} in {path}",
                    severity=sev,
                    description=str(extra.get("message") or check)[:500],
                    evidence=str(extra.get("lines", ""))[:300],
                    location=f"{self.repo_url}#{path}:{line}",
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
            # Vendored trees (static/, migrations/, *.min.js, jquery etc.)
            # matched the SQL-concat regex on string literals -> 13 pure
            # FPs on django.nV. First-party code only.
            if is_vendored(path, self.repo_path):
                continue
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
