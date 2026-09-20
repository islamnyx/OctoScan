"""Builtin secret scan (no binary needed).

Always-available fallback + complement to Gitleaks: regexes for
private keys, AWS-style tokens, generic api_key/password assignments.
Capped output, redacted evidence, fail-open per-file.
"""
from __future__ import annotations

import re

from app.models import Finding, Severity
from app.repo import is_vendored, iter_repo_files
from app.scanners.secret_context import (
    FIXTURE_NOTE,
    downgrade_for_fixture,
    is_likely_test_fixture,
)
from app.scanners.source_base import SourceScanner

TEXT_EXTS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".rb", ".php",
    ".env", ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf",
    ".sh", ".tf", ".tsx", ".html", ".xml", ".properties",
}

RULES: list[tuple[str, re.Pattern[str], Severity, str]] = [
    ("Private key block",
     re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"),
     Severity.high, "Private key material committed. Rotate and purge from history."),
    ("AWS access key",
     re.compile(r"AKIA[0-9A-Z]{16}"),
     Severity.high, "AWS key committed. Revoke immediately, use env/secret manager."),
    ("Generic secret assignment",
     re.compile(r"(?i)(api[_-]?key|secret|passwd|password|aws_secret|github_token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-./+]{12,}"),
     Severity.medium, "Probable hardcoded secret. Move to env/secret manager and rotate."),
    ("Dangerous eval/exec",
     re.compile(r"\b(eval|exec)\s*\("),
     Severity.low, "Dynamic code execution. Validate input or remove."),
]

ALLOW_RE = re.compile(r"(?i)example|placeholder|test|changeme|<your-|dummy|fake")

# Values that are code references, not committed secrets
# (settings.api_key, os.getenv(...), config.x, process.env.X).
CODE_REF_RE = re.compile(
    r"(?i)(settings\.|os\.environ|os\.getenv|getenv\s*\(|config\.|process\.env|env\.get|env\[)"
)


def _is_text(path) -> bool:
    if path.suffix.lower() in TEXT_EXTS:
        return True
    return path.name in ("Dockerfile", "Makefile") or path.suffix == ""


class BuiltinSecretsScanner(SourceScanner):
    name = "builtin-secrets"

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for path in iter_repo_files(self.repo_path):
            # Vendored trees (static/, *.min.js, jquery…) match generic
            # regexes on library code — first-party code only, same as
            # the semgrep heuristic pass.
            if is_vendored(path, self.repo_path):
                continue
            if not _is_text(path):
                continue
            try:
                text = path.read_text(errors="ignore")
            except Exception:
                continue
            rel = str(path.relative_to(self.repo_path))
            for title, rx, sev, rec in RULES:
                try:
                    m = rx.search(text)
                except Exception:
                    continue
                if not m:
                    continue
                snippet = m.group(0)[:80]
                context = text[max(0, m.start() - 40):m.end() + 40]
                if CODE_REF_RE.search(snippet) or CODE_REF_RE.search(context):
                    continue
                # Test/teaching fixtures: keep the finding but flag +
                # down-rank instead of dropping (auditors like full lists).
                fixture = bool(ALLOW_RE.search(context) or ALLOW_RE.search(snippet))
                if not fixture:
                    fixture = is_likely_test_fixture(rel, snippet, context)
                sev_eff = downgrade_for_fixture(sev) if fixture else sev
                findings.append(
                    Finding(
                        scanner=self.name,
                        title=f"{title} in {rel}" + (" [likely test fixture]" if fixture else ""),
                        severity=sev_eff,
                        description=f"Pattern '{title}' matched in {rel}." + (f" {FIXTURE_NOTE}" if fixture else ""),
                        evidence=snippet[:120],
                        location=f"{self.repo_url}#{rel}" if self.repo_url else rel,
                        recommendation=rec + (" If this is lesson/test code, confirm before rotating." if fixture else ""),
                        raw={"file": rel, "rule": title, "likely_test_fixture": fixture},
                    )
                )
                if len(findings) >= 100:
                    return findings
        if not findings:
            findings.append(
                Finding(
                    scanner=self.name,
                    title="No hardcoded secrets found (builtin)",
                    severity=Severity.info,
                    description="Builtin regex pass found no secret patterns.",
                    location=self.repo_url or str(self.repo_path),
                )
            )
        return findings
