import json
import subprocess

from app.config import settings
from app.models import Finding, Severity
from app.normalize import clean_cwe
from app.scanners.base import BaseScanner, assert_target_reachable


NUCLEI_SEVERITY_MAP = {
    "critical": Severity.critical,
    "high": Severity.high,
    "medium": Severity.medium,
    "low": Severity.low,
    "info": Severity.info,
    "unknown": Severity.info,
}


def _nuclei_severity(raw: str | None) -> Severity:
    return NUCLEI_SEVERITY_MAP.get((raw or "info").strip().lower(), Severity.info)


# Recon-class templates run hot in stock Nuclei, but an unauthenticated
# metrics read exposes internals (job names, runtime config) — keep at
# medium so it stays actionable (Oct 2026: reverted the low downgrade;
# a 26 KB /metrics body is fingerprinting fuel, not noise).
NUCLEI_SEVERITY_OVERRIDES: dict[str, Severity] = {}


def _template_class(template_id: str, matcher: str) -> str | None:
    """Finding class for the central OWASP table (app/owasp.py)."""
    tid = (template_id or "").lower()
    if tid in ("prometheus-metrics", "prometheus-metrics-detect"):
        return "metrics-exposure"
    if tid == "http-missing-security-headers":
        return "missing-security-header"
    if "cors" in tid:
        return "cors"
    if "sqli" in tid or "sql-injection" in tid:
        return "sqli"
    if "xss" in tid:
        return "xss"
    if "cve-" in tid or tid.startswith("cve"):
        return "vulnerable-library"
    return None


def _req_resp_snippets(item: dict) -> tuple[str, str]:
    """Bounded request/response excerpts from a Nuclei match (never raises)."""
    try:
        req = str(item.get("request") or "")
        request = " ".join(req.split())[:500]
    except Exception:
        request = ""
    try:
        resp = str(item.get("response") or "").replace("\r", "")
        _, _, body = resp.partition("\n\n")
        response = " ".join(body.split())[:500]
    except Exception:
        response = ""
    return request, response


def _response_evidence(response: str) -> str:
    """One-line wire summary: `HTTP 200 text/plain (26516 B): # HELP ...`.

    Nuclei captures the full request/response per match; quoting the
    status, content type, size and first body lines beats an empty
    evidence field or a bare matcher name.
    """
    try:
        text = (response or "").replace("\r", "")
        head, _, body = text.partition("\n\n")
        lines = [ln for ln in head.split("\n") if ln.strip()]
        status = lines[0].replace("HTTP/1.1 ", "HTTP ").replace("HTTP/1.0 ", "HTTP ") if lines else "HTTP ?"
        ctype = ""
        size = len(text.encode("utf-8", "ignore"))
        for ln in lines[1:]:
            if ln.lower().startswith("content-type:"):
                ctype = ln.split(":", 1)[1].strip().split(";")[0][:40]
                break
        snippet = " ".join(body.split())[:160]
        parts = [status]
        if ctype:
            parts.append(ctype)
        parts.append(f"({size} B)")
        if snippet:
            parts.append(snippet)
        return " ".join(parts)[:300]
    except Exception:
        return ""


# Specific fixes for high-signal exposure templates (generic boilerplate
# otherwise). Keyed by template-id.
TEMPLATE_FIX: dict[str, str] = {
    "prometheus-metrics": (
        "Do not expose /metrics unauthenticated: bind it to localhost, "
        "gate it behind auth, or drop unneeded collectors — version and "
        "runtime series aid targeted attacks."
    ),
    "swagger-api": (
        "A public Swagger UI documents every route for attackers: restrict "
        "/api-docs to internal networks or require auth, and do not ship "
        "spec files with production builds."
    ),
}


class NucleiScanner(BaseScanner):
    name = "nuclei"

    ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "info"}

    def _severity_filter(self) -> list[str]:
        raw = (settings.nuclei_severity or "").strip().lower()
        if not raw:
            return []
        wanted = [s.strip() for s in raw.replace(";", ",").split(",") if s.strip()]
        # Fail-closed on typo: unknown token = loud error, not silent full run.
        unknown = [s for s in wanted if s not in self.ALLOWED_SEVERITIES]
        if unknown:
            raise RuntimeError(
                f"invalid NUCLEI_SEVERITY {unknown}: use comma list of {sorted(self.ALLOWED_SEVERITIES)}"
            )
        # De-dupe, keep canonical order critical→info.
        order = ["critical", "high", "medium", "low", "info"]
        return [s for s in order if s in wanted]

    def run(self) -> list[Finding]:
        out_path = self.workdir / "nuclei.jsonl"
        severities = self._severity_filter()
        cmd = [
            settings.nuclei_bin,
            "-u",
            self.target_url,
            "-jsonl",
            "-o",
            str(out_path),
            "-silent",
            "-nc",
            "-fr",  # follow redirects
            "-timeout",
            "10",
            "-retries",
            "1",
        ]
        if severities:
            cmd += ["-severity", ",".join(severities)]
        # Target-safe throttling (see config): full depth, bounded pressure.
        cmd += [
            "-rate-limit", str(settings.nuclei_rate_limit),
            "-concurrency", str(settings.nuclei_concurrency),
            "-bulk-size", str(settings.nuclei_bulk_size),
        ]
        exclude = [t.strip() for t in (settings.nuclei_exclude_tags or "").split(",") if t.strip()]
        if exclude:
            cmd += ["-exclude-tags", ",".join(exclude)]
        # Authenticated scans (v1): session injection via custom headers.
        if self.auth:
            for h, v in self.auth_headers().items():
                cmd += ["-H", f"{h}: {v}"]
            cookie = self.auth_cookie_header()
            if cookie:
                cmd += ["-H", f"Cookie: {cookie}"]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=settings.scan_timeout_seconds,
        )
        combined = (proc.stdout or "") + (proc.stderr or "")
        if "no templates found" in combined.lower() or "templates not installed" in combined.lower():
            return [
                Finding(
                    scanner=self.name,
                    title="Nuclei templates not installed",
                    severity=Severity.info,
                    description="Nuclei ran but no templates are installed. Run `nuclei -update-templates` on the scanner host.",
                    location=self.target_url,
                )
            ]
        if not out_path.exists():
            raise RuntimeError(f"nuclei produced no output: {(proc.stderr or proc.stdout or 'empty')[-200:]}")
        seen: set[tuple[str, str, str]] = set()
        findings = self._parse(out_path, seen)
        # Second pass: exposure/misconfiguration templates at ALL
        # severities. The main pass gates on severity (info excluded), so
        # genuine exposure signals (public Swagger UI, metrics pages)
        # would otherwise stay invisible. Tag-scoped, throttled, merged
        # into the same dedupe set.
        findings += self._exposure_pass(seen)
        if not findings:
            # Empty output is ambiguous: clean target OR nuclei never reached
            # it (unreachable target also yields a 0-byte file). Disambiguate
            # with a cheap probe so a down target can't masquerade as clean.
            assert_target_reachable(self.target_url)
            findings.append(
                Finding(
                    scanner=self.name,
                    title="No Nuclei findings",
                    severity=Severity.info,
                    description="Nuclei completed its full template run without matches.",
                    location=self.target_url,
                )
            )
        return findings

    def _exposure_pass(self, seen: set[tuple[str, str, str]]) -> list[Finding]:
        """Tag-scoped second run (exposure + misconfiguration, any severity)."""
        tags = [t.strip() for t in (settings.nuclei_extra_tags or "").split(",") if t.strip()]
        if not tags:
            return []
        out_path = self.workdir / "nuclei-exposure.jsonl"
        cmd = [
            settings.nuclei_bin, "-u", self.target_url, "-jsonl", "-o", str(out_path),
            "-silent", "-nc", "-fr", "-timeout", "10", "-retries", "1",
            "-tags", ",".join(tags),
            "-severity", ",".join(
                s.strip() for s in (settings.nuclei_extra_severities or "info").split(",") if s.strip()
            ),
            "-rate-limit", str(settings.nuclei_rate_limit),
            "-concurrency", str(settings.nuclei_concurrency),
            "-bulk-size", str(settings.nuclei_bulk_size),
        ]
        if self.auth:
            for h, v in self.auth_headers().items():
                cmd += ["-H", f"{h}: {v}"]
            cookie = self.auth_cookie_header()
            if cookie:
                cmd += ["-H", f"Cookie: {cookie}"]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=settings.scan_timeout_seconds)
        except Exception as exc:
            self._activity(f"nuclei exposure pass failed (main results kept): {exc}")
            return []
        if not out_path.exists():
            return []
        try:
            return self._parse(out_path, seen, allow_info=True)
        except Exception as exc:
            self._activity(f"nuclei exposure parse failed (main results kept): {exc}")
            return []

    def _parse(self, path, seen: set[tuple[str, str, str]] | None = None,
               allow_info: bool = False) -> list[Finding]:
        findings: list[Finding] = []
        if seen is None:
            seen = set()
        # Defense-in-depth: enforce the severity gate on parsed output too,
        # so a nuclei build that ignores -severity can't leak info noise in.
        # (The exposure pass sets allow_info: tag-scoped, verified matches
        # only, and info never fails the gate.)
        try:
            allowed = set(self._severity_filter()) or self.ALLOWED_SEVERITIES
        except RuntimeError:
            allowed = self.ALLOWED_SEVERITIES
        if allow_info:
            allowed = allowed | {"info"}
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(item, dict):
                continue
            template_id = str(item.get("template-id") or item.get("templateID") or "")
            info = item.get("info") or {}
            name = info.get("name") or template_id or "Nuclei finding"
            matched_at = item.get("matched-at") or item.get("host") or self.target_url
            matcher = str(item.get("matcher-name") or "")
            key = (template_id, str(matched_at), matcher)
            if key in seen:
                continue
            seen.add(key)
            severity = _nuclei_severity(info.get("severity"))
            tuned_from = None
            override = NUCLEI_SEVERITY_OVERRIDES.get(template_id or "")
            if override is not None and override != severity:
                tuned_from, severity = severity.value, override
            if severity.value not in allowed:
                continue
            cve = info.get("cve-id") or info.get("cveID")
            if isinstance(cve, list):
                cve = cve[0] if cve else None
            classification = info.get("classification") or {}
            raw_cwe = info.get("cwe-id") or info.get("cweID")
            class_cwe = classification.get("cwe-id") or classification.get("cweID")
            cwe_ids: list[str] = []
            for src in (raw_cwe, class_cwe):
                items = src if isinstance(src, list) else [src]
                for entry in items:
                    cid = clean_cwe(entry)
                    if cid and cid not in cwe_ids:
                        cwe_ids.append(cid)
            cwe_list = cwe_ids[:3]
            if not cve:
                class_cve = classification.get("cve-id") or classification.get("cveID")
                if isinstance(class_cve, list):
                    class_cve = class_cve[0] if class_cve else None
                cve = class_cve
            # Measured score from the template beats our severity-bucket
            # estimate (prometheus-metrics ships cvss-score 5.3).
            cvss: float | None = None
            try:
                if classification.get("cvss-score") is not None:
                    cvss = float(classification["cvss-score"])
            except (TypeError, ValueError):
                cvss = None
            refs = info.get("reference") or []
            if isinstance(refs, str):
                refs = [refs]
            extracted = item.get("extracted-results") or []
            evidence = "; ".join(str(e) for e in extracted[:3]) or matcher
            if not evidence and item.get("response"):
                # Exposure findings rarely extract text — quote the wire:
                # status + content type + first body lines.
                evidence = _response_evidence(str(item["response"]))
            recommendation = TEMPLATE_FIX.get(template_id or "") or (
                "Review this Nuclei finding against the affected asset and patch / harden "
                "as indicated by the template references."
            )
            req_snippet, resp_snippet = _req_resp_snippets(item)
            # The stock http-missing-security-headers template reports one
            # match per absent header with the header as matcher-name.
            # Expose it as `header` so normalize._concept merges these with
            # the headers/ZAP/Nikto findings for the same root cause.
            header = matcher if template_id == "http-missing-security-headers" else None
            finding_class = _template_class(template_id, matcher)
            findings.append(
                Finding(
                    scanner=self.name,
                    title=f"Nuclei {template_id}: {name}" if template_id else name,
                    severity=severity,
                    description=str(info.get("description") or name),
                    evidence=evidence[:500],
                    location=str(matched_at),
                    recommendation=recommendation,
                    cve=str(cve) if cve else None,
                    cvss=cvss,
                    cwe=cwe_list,
                    request=req_snippet,
                    response=resp_snippet,
                    raw={
                        "template_id": template_id,
                        "header": header,
                        "finding_class": finding_class,
                        "matcher": matcher or None,
                        "type": item.get("type"),
                        "cwe": str(cwe_list[0]) if cwe_list else None,
                        "references": refs[:5] if isinstance(refs, list) else [],
                        "template_url": item.get("template-url"),
                        "severity_tuned_from": tuned_from,
                        "live_verified": True,
                    },
                )
            )
        return findings
