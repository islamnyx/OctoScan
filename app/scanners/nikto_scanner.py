import ipaddress
import json
import re
import subprocess

import httpx

from app.config import settings
from app.models import Finding, Severity
from app.scanners.base import BaseScanner, assert_target_reachable


# Nikto emits no severity — map by ID/keywords. Header findings (013587)
# duplicate our fast headers scanner, so keep them info-only here.
HEADER_DUP_IDS = {"013587"}
INFO_IDS = {"999990", "007342", "999957", "999956", "999955"}

# Stack-specific checks that are guaranteed false positives on servers
# returning their SPA shell for unknown paths. Verified 2026-09-11:
# GET /JAMonAdmin.jsp on Juice Shop (Node) returns HTTP 200 with a body
# byte-identical to / — there is no Java admin console. Never ship the
# attached CVE claim without a live catch-all check first.
FP_PRONE_IDS = {"007303"}

# Sensitive-file guesses that claim file content was retrieved
# (.htpasswd "Contains authorization information", shell histories).
# Verified 2026-09-11 on Juice Shop: /.htpasswd, /.bash_history and
# /.sh_history all return HTTP 200 with a body byte-identical to /
# (9393 bytes) — the SPA shell, not credentials. Same live catch-all
# check as JAMon applies before that language goes in front of a client.
SENSITIVE_FILE_IDS = {"002739", "002743", "002756"}

HIGH_KEYWORDS = (
    "command execution",
    "remote file inclusion",
    "sql injection",
    "cross-site scripting",
    "directory traversal",
    "path traversal",
    "arbitrary file",
    "arbitrary code",
    "buffer overflow",
    "authentication bypass",
)
MEDIUM_KEYWORDS = (
    "password",
    "backup",
    "config file",
    "directory listing",
    "information disclosure",
    "admin",
    "phpinfo",
    "server-status",
    "server-info",
)


def _smart_truncate(msg: str, limit: int = 100) -> str:
    text = " ".join(msg.split())
    if len(text) <= limit:
        return text
    cut = text[:limit].rsplit(" ", 1)[0] or text[:limit]
    return cut.rstrip(" ,;:.") + "…"


def _recommendation(msg: str, references: str | None) -> str:
    ref = (references or "").strip()
    generic = "Review this Nikto finding and harden the exposed path/config."
    if not ref:
        return generic
    # Nikto often puts a bare CVE id or a docs URL in `references`.
    # Neither is an actionable recommendation on its own.
    if ref.startswith("http"):
        return f"{generic} See: {ref}"
    if ref.upper().startswith("CVE-"):
        cve = ref.split()[0]
        return f"{generic} See https://nvd.nist.gov/vuln/detail/{cve}"
    return f"{generic} Ref: {ref}"


def _severity(vuln_id: str, msg: str) -> Severity:
    vid = str(vuln_id)
    if vid in HEADER_DUP_IDS:
        return Severity.info
    if vid in INFO_IDS:
        return Severity.info
    low_msg = msg.lower().strip().rstrip(".")
    # Nikto heuristic with no detail — keep as info, not low.
    if low_msg == "this might be interesting":
        return Severity.info
    if any(k in low_msg for k in HIGH_KEYWORDS):
        return Severity.high
    if any(k in low_msg for k in MEDIUM_KEYWORDS):
        return Severity.medium
    return Severity.low


class NiktoScanner(BaseScanner):
    name = "nikto"

    def run(self) -> list[Finding]:
        out_base = self.workdir / "nikto"
        # Start fresh: stale output from a previous attempt would be
        # mistaken for this run's results (same class of bug as
        # testssl's --jsonfile append refusal, fixed 2026-09-16).
        for stale in self.workdir.glob("nikto*.json*"):
            try:
                stale.unlink()
            except OSError:
                pass
        # Nikto silently writes empty output when the host resolves to
        # IPv6 first (e.g. `localhost` -> ::1) while the app listens on
        # IPv4. Pin loopback to 127.0.0.1 for the probe only; findings
        # still reference the user-supplied target URL.
        probe_target = self.target_url
        if self.host in ("localhost",):
            probe_target = self.target_url.replace("localhost", "127.0.0.1", 1)
        # -nolookup aborts with "given name" error on hostnames (verified
        # 2026-09-12 on www.enscs.edu.dz). Only use it for literal IPs.
        try:
            ipaddress.ip_address(self.host)
            use_nolookup = True
        except ValueError:
            use_nolookup = self.host in ("localhost",)
            if "127.0.0.1" in probe_target:
                use_nolookup = True
        cmd = [
            settings.nikto_bin,
            "-h",
            probe_target,
            "-Format",
            "json",
            "-o",
            str(out_base),
            "-ask",
            "no",
        ]
        if use_nolookup:
            cmd.append("-nolookup")
        cmd += [
            "-maxtime",
            "240s",
            "-timeout",
            "10",
            "-Tuning",
            "x6",  # all except DoS
        ]
        # Authenticated scans (v1): session injection via extra headers.
        if self.auth:
            for h, v in self.auth_headers().items():
                cmd += ["-Add-header", f"{h}: {v}"]
            cookie = self.auth_cookie_header()
            if cookie:
                cmd += ["-Add-header", f"Cookie: {cookie}"]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=settings.scan_timeout_seconds,
        )
        out_path = self._find_output(out_base)
        if out_path is None or out_path.stat().st_size == 0:
            # JSON report plugin crashed (0-byte file) but stdout usually
            # still carries every finding — parse that instead of failing.
            std_items = self._stdout_items(proc.stdout or "")
            if std_items:
                return self._build_findings(std_items)
            detail = proc.stderr.strip() or proc.stdout.strip() or "no output written"
            try:
                assert_target_reachable(self.target_url)
            except RuntimeError as conn_exc:
                raise RuntimeError(str(conn_exc)) from None
            raise RuntimeError(f"nikto produced no output for {self.target_url}: {detail[-200:]}")
        return self._parse(out_path)

    @staticmethod
    def _find_output(out_base):
        candidates = [
            out_base.with_suffix(".json"),
            out_base.with_name(out_base.name + ".json"),
            out_base.with_name(out_base.name + ".json.json"),
        ]
        for c in candidates:
            if c.exists():
                return c
        matches = sorted(out_base.parent.glob("nikto*.json*"))
        return matches[0] if matches else None

    _root_body: bytes | None = None
    _root_fetched: bool = False

    def _is_spa_catchall(self, url: str) -> bool:
        """True if `url` returns the same body as the scan root.

        SPA servers (Juice Shop included) answer unknown paths with HTTP 200
        + index.html. Nikto reads the 200 as 'path exists'. Byte-compare
        against the root; fail open (False) on any network error.
        """
        try:
            if not self._root_fetched:
                r = httpx.get(self.target_url, follow_redirects=True, timeout=10.0)
                self._root_body = r.content if r.status_code == 200 else None
                self._root_fetched = True
            if self._root_body is None:
                return False
            r = httpx.get(url, follow_redirects=True, timeout=10.0)
            return r.status_code == 200 and r.content == self._root_body
        except Exception:
            return False

    # nikto 2.6's JSON report plugin crashes with a 0-byte file on some
    # findings — verified 2026-09-16: id 999984 (ETag inode leak) kills
    # nikto_report_json.plugin:113 ("allow_blessed" error).
    _STDOUT_RE = re.compile(r"^\+\s*\[(\d+)\]\s*([^\s:]+)\s*:?\s*(.*)$")
    _SEE_RE = re.compile(r"See:\s*(\S+)", re.IGNORECASE)

    @classmethod
    def _stdout_items(cls, text: str) -> list[dict]:
        """Finding dicts from nikto's stdout (`+ [id] path: msg` lines)."""
        items: list[dict] = []
        for line in (text or "").splitlines():
            m = cls._STDOUT_RE.match(line.strip())
            if not m:
                continue
            msg = m.group(3).strip() or "Nikto finding"
            see = cls._SEE_RE.search(msg)
            items.append(
                {
                    "id": m.group(1),
                    "method": "",
                    "url": m.group(2),
                    "msg": msg,
                    "references": see.group(1) if see else "",
                }
            )
        return items

    @staticmethod
    def _json_items(payload) -> list[dict]:
        items: list[dict] = []
        hosts = payload if isinstance(payload, list) else [payload]
        for host in hosts:
            vulns = host.get("vulnerabilities", host) if isinstance(host, dict) else []
            if isinstance(vulns, dict):
                vulns = [vulns]
            if not isinstance(vulns, list):
                continue
            for item in vulns:
                if isinstance(item, dict):
                    items.append(item)
        return items

    def _parse(self, path) -> list[Finding]:
        return self._build_findings(self._json_items(json.loads(path.read_text())))

    def _build_findings(self, items: list[dict]) -> list[Finding]:
        findings: list[Finding] = []
        speculative_catchall: list[dict] = []
        connect_failures: list[str] = []
        seen: set[tuple[str, str, str, str]] = set()
        for item in items:
            if not isinstance(item, dict):
                continue
            vid = str(item.get("id") or "")
            method = str(item.get("method") or "")
            rel_url = str(item.get("url") or "/")
            msg = str(item.get("msg") or "Nikto finding")
            # Nikto never connected at all — the whole run is void.
            # Previously this became a low "Nikto FAIL" finding and the
            # scan looked like it ran. Raise so the pipeline retries
            # once and otherwise records a visible error.
            if vid == "FAIL" and "unable to connect" in msg.lower():
                connect_failures.append(msg)
                continue
            # Same id can repeat for different messages (e.g. one
            # 013587 per missing header) — include msg in the key.
            key = (vid, method, rel_url, msg)
            if key in seen:
                continue
            seen.add(key)
            location = self.target_url.rstrip("/") + rel_url
            short = _smart_truncate(msg, 100)
            severity = _severity(vid, msg)
            description = msg
            recommendation = _recommendation(msg, item.get("references"))
            is_speculative = msg.lower().strip().rstrip(".") == "this might be interesting"
            needs_catchall_check = (
                vid in FP_PRONE_IDS or vid in SENSITIVE_FILE_IDS or is_speculative
            ) and rel_url != "/"
            is_catchall = self._is_spa_catchall(location) if needs_catchall_check else False
            if is_speculative and is_catchall:
                # Collapse later: one aggregated finding for all
                # catch-all-confirmed guesses, not one row per path.
                speculative_catchall.append(
                    {"nikto_id": vid, "method": method, "url": rel_url, "location": location}
                )
                continue
            fp_note = ""
            if is_catchall and (vid in FP_PRONE_IDS or vid in SENSITIVE_FILE_IDS):
                severity = Severity.info
                fp_note = (
                    " [Likely false positive: this path returns content identical to /. "
                    "The server serves its SPA shell for unknown paths, so no such file "
                    "was actually fingerprinted. Verify manually before acting.]"
                )
                recommendation = (
                    "Likely false positive on SPA catch-all servers — confirm by fetching "
                    "the path and diffing against /. " + recommendation
                )
            findings.append(
                Finding(
                    scanner=self.name,
                    title=f"Nikto {vid}: {short}" if vid else short,
                    severity=severity,
                    description=description + fp_note,
                    evidence=f"{method} {rel_url}".strip(),
                    location=location,
                    recommendation=recommendation,
                    raw={"nikto_id": vid, "method": method, "url": rel_url},
                )
            )
        if speculative_catchall:
            # One row instead of N: guessed filenames all returned the SPA
            # shell (HTTP 200, body identical to /). Genuinely distinct
            # hits (e.g. /ftp/ directory listing) are NOT in this bucket —
            # they failed the catch-all check and stay individual above.
            paths = sorted({e["url"] for e in speculative_catchall})
            locs = sorted({e["location"] for e in speculative_catchall})
            ids = sorted({e["nikto_id"] for e in speculative_catchall if e["nikto_id"]})
            n = len(paths)
            findings.append(
                Finding(
                    scanner=self.name,
                    title=f"Nikto: {n} speculative paths returned non-404 responses (likely SPA catch-all)",
                    severity=Severity.info,
                    description=(
                        f"{n} guessed paths returned HTTP 200 with content identical to /. "
                        "The server serves its SPA shell for unknown paths, so these are "
                        "likely false positives, not real files. Review list: "
                        + ", ".join(paths)
                    ),
                    evidence="GET " + ", ".join(paths),
                    location=self.target_url,
                    recommendation=(
                        "Likely SPA catch-all noise — spot-check one path by diffing against / "
                        "before acting. No action needed if bodies match."
                    ),
                    raw={
                        "nikto_ids": ids,
                        "urls": paths,
                        "affected_urls": locs,
                        "merged_count": n,
                        "merged_concept": "nikto-speculative-paths",
                    },
                )
            )
        if connect_failures and not findings and not speculative_catchall:
            # Probe to sharpen the message (still down vs transient), then
            # raise either way — a run that never connected has no findings.
            try:
                assert_target_reachable(self.target_url)
                detail = "target answers now, so the failure was transient"
            except RuntimeError:
                detail = "target still unreachable"
            raise RuntimeError(
                f"CONNECTION FAILURE: nikto could not connect to {self.target_url}: "
                f"{connect_failures[0]} ({detail})"
            )
        if not findings:
            findings.append(
                Finding(
                    scanner=self.name,
                    title="No Nikto findings",
                    severity=Severity.info,
                    description="Nikto completed without findings.",
                    location=self.target_url,
                )
            )
        return findings
