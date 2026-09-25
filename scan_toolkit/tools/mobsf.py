"""MobSF REST client — upload APK, trigger scan, fetch the report JSON.

Targets the MobSF v3 API endpoints (assumed: a local MobSF Docker container):
    POST {base}/api/v1/upload   (multipart file, Authorization header)
    POST {base}/api/v1/scan     (form: file_name, hash)
    GET  {base}/api/v1/report_json?hash=<hash>
These are the documented v3 routes; the exact response shape can vary by
version and the normalizer (scan_toolkit.normalize.mobsf_findings) is written
to tolerate that.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import httpx

from scan_toolkit.intermediate import IRToolOutput
from scan_toolkit.normalize import mobsf_findings
from scan_toolkit.tools.base import ToolRunner

_RAW_JSON = "report.json"


class MobsfRunner(ToolRunner):
    name = "mobsf"

    def __init__(self, workdir: Path, transport: httpx.BaseTransport | None = None):
        super().__init__(workdir)
        # injectable transport so tests can stub HTTP without a live service
        self._transport = transport

    def available(self) -> bool:
        # no cheap status ping documented; availability = a live object. Failures
        # during run() are captured as per-tool errors.
        return True

    def _client(self) -> httpx.Client:
        kwargs: dict[str, Any] = {"timeout": self._settings.tool_timeout_seconds, "follow_redirects": True}
        if self._transport is not None:
            kwargs["transport"] = self._transport
        headers = {}
        if self._settings.mobsf_api_key:
            headers["Authorization"] = self._settings.mobsf_api_key
        return httpx.Client(base_url=self._settings.mobsf_base_url, headers=headers, **kwargs)

    def _sha256(self, path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()

    def run(self, apk: Path) -> IRToolOutput:
        try:
            with self._client() as client:
                up = client.post(
                    "/api/v1/upload",
                    files={"file": (apk.name, apk.open("rb"), "application/vnd.android.package-archive")},
                )
                up.raise_for_status()
                upload = up.json()
                file_name = upload.get("file_name") or upload.get("file") or apk.name
                hsh = upload.get("hash") or self._sha256(apk)
                scan = client.post("/api/v1/scan", data={"file_name": file_name, "hash": hsh})
                scan.raise_for_status()
                report = client.get("/api/v1/report_json", params={"hash": hsh})
                report.raise_for_status()
                report_json = report.json()
        except httpx.HTTPError as exc:
            return IRToolOutput(tool=self.name, errors=[f"mobsf request failed: {exc}"])
        except ValueError as exc:
            return IRToolOutput(tool=self.name, errors=[f"mobsf returned non-JSON: {exc}"])

        engine = str(report_json.get("scan_type") or report_json.get("engine_version") or "")[:100]
        raw_path = self.tool_dir / _RAW_JSON
        raw_path.write_text(report_json.dumps() if isinstance(report_json, list) else _json_dumps(report_json))
        return IRToolOutput(
            tool=self.name,
            version=engine or None,
            raw_path=str(raw_path.resolve()),
            findings=mobsf_findings(report_json),
        )


def _json_dumps(obj: Any) -> str:
    import json

    return json.dumps(obj, indent=2, default=str)