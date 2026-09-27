"""OWASP ZAP runner — spider + active scan via the ZAP REST API.

Assumes a local ZAP daemon (default http://127.0.0.1:8090, API key optional)::

    zap.sh -daemon -port 8090 -config api.key=<key>

Endpoints used (stable ZAP v2 API):
    GET /JSON/core/view/version/      availability probe
    GET /JSON/spider/action/scan/     start spider, returns {"scan": "<id>"}
    GET /JSON/spider/view/status/     poll until "100"
    GET /JSON/ascan/action/scan/      start active scan
    GET /JSON/ascan/view/status/      poll until "100"
    GET /JSON/core/view/alerts/       fetch findings

Scope note: this is an UNAUTHENTICATED baseline scan.  Authenticated ZAP
scanning (context + auth script per test account) is a documented TODO —
per-role authorization coverage comes from the traffic role diff instead.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

import httpx

from scan_toolkit.intermediate import IRToolOutput
from scan_toolkit.normalize import zap_findings
from scan_toolkit.tools.base import ToolRunner

log = logging.getLogger(__name__)

_RAW_JSON = "zap_alerts.json"
_POLL_INTERVAL_S = 5.0
# Hard cap on spider+ascan polling each (active scans on big APIs take a
# while; the per-invocation tool timeout still applies on top).
_MAX_POLLS = 360


class ZAPRunner(ToolRunner):
    name = "zap"

    def __init__(self, workdir: Path, transport: httpx.BaseTransport | None = None):
        super().__init__(workdir)
        # injectable transport so tests can stub HTTP without a live daemon
        self._transport = transport

    # -- HTTP ------------------------------------------------------------

    def _client(self) -> httpx.Client:
        kwargs: dict[str, Any] = {
            "timeout": self._settings.tool_timeout_seconds,
            "follow_redirects": True,
        }
        if self._transport is not None:
            kwargs["transport"] = self._transport
        params = {}
        if self._settings.zap_api_key:
            params["apikey"] = self._settings.zap_api_key
        return httpx.Client(
            base_url=self._settings.zap_base_url, params=params, **kwargs
        )

    def available(self) -> bool:
        try:
            with self._client() as client:
                resp = client.get("/JSON/core/view/version/")
                return resp.status_code == 200
        except httpx.HTTPError:
            return False

    # -- scan ------------------------------------------------------------

    def run(self, target_url: str) -> IRToolOutput:  # type: ignore[override]
        """Spider + actively scan target_url, return normalized alert findings."""
        if not target_url or not target_url.startswith(("http://", "https://")):
            return IRToolOutput(tool=self.name, errors=[f"invalid target URL: {target_url!r}"])
        try:
            with self._client() as client:
                version = self._version(client)
                spider_id = self._start(client, "spider", target_url)
                self._poll_until_done(client, "spider", spider_id, target_url)
                ascan_id = self._start(client, "ascan", target_url)
                self._poll_until_done(client, "ascan", ascan_id, target_url)
                alerts = self._alerts(client, target_url)
        except httpx.HTTPError as exc:
            return IRToolOutput(tool=self.name, errors=[f"zap request failed: {exc}"])
        except (ValueError, KeyError) as exc:
            return IRToolOutput(tool=self.name, errors=[f"zap unexpected response: {exc}"])
        except TimeoutError as exc:
            return IRToolOutput(tool=self.name, errors=[str(exc)])

        raw_path = self.tool_dir / _RAW_JSON
        raw_path.write_text(json.dumps(alerts, indent=2, default=str))
        return IRToolOutput(
            tool=self.name,
            version=version,
            raw_path=str(raw_path.resolve()),
            findings=zap_findings(alerts),
        )

    # -- internals (split for testability) -------------------------------

    def _version(self, client: httpx.Client) -> str | None:
        resp = client.get("/JSON/core/view/version/")
        resp.raise_for_status()
        return str(resp.json().get("version") or "")[:50] or None

    def _start(self, client: httpx.Client, kind: str, target_url: str) -> str:
        """Start a spider/ascan job, return its scan id."""
        resp = client.get(f"/JSON/{kind}/action/scan/", params={"url": target_url})
        resp.raise_for_status()
        scan_id = str(resp.json().get("scan"))
        if not scan_id or scan_id == "None":
            raise ValueError(f"zap {kind} scan did not return a scan id")
        log.info("ZAP %s started on %s (id=%s)", kind, target_url, scan_id)
        return scan_id

    def _poll_until_done(
        self, client: httpx.Client, kind: str, scan_id: str, target_url: str
    ) -> None:
        for _ in range(_MAX_POLLS):
            resp = client.get(
                f"/JSON/{kind}/view/status/", params={"scanId": scan_id}
            )
            resp.raise_for_status()
            if str(resp.json().get("status")) == "100":
                log.info("ZAP %s on %s finished", kind, target_url)
                return
            time.sleep(_POLL_INTERVAL_S)
        raise TimeoutError(f"zap {kind} scan on {target_url} did not finish in time")

    def _alerts(self, client: httpx.Client, target_url: str) -> list[dict]:
        resp = client.get("/JSON/core/view/alerts/", params={"baseurl": target_url})
        resp.raise_for_status()
        alerts = resp.json().get("alerts", [])
        if not isinstance(alerts, list):
            raise ValueError("zap alerts response has no 'alerts' list")
        return alerts
