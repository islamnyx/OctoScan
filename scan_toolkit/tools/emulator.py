"""Emulator runner — headless AVD boot, APK install, runtime observations.

Flow (orchestrated by ``stages.run_dynamic``)::

    device = runner.boot()          # emulator -avd <name> headless + wait
    runner.install(apk)             # adb install
    ... frida scripts run here (see tools/frida.py) ...
    out = runner.observe(package)   # dumpsys + logcat + manifest surface
    runner.teardown()               # kill the emulator we booted

Every step degrades loudly when binaries are missing — ``available()``
checks for BOTH ``emulator`` and ``adb`` and ``run()`` explains exactly
what to install.  Nothing here is silent: a machine without the Android
SDK produces a failed-but-informative stage, never fake findings.

Assumptions (documented, not hidden):
  * The first emulator instance takes ``emulator-5554`` as its adb id.
  * The AVD (``SCAN_TOOLKIT_DYNAMIC_AVD``) was created once by the analyst:
    ``avdmanager create avd -n toolkit-avd -k "system-images;..."``.
  * frida-server runs on the emulator (analyst pushes it once per AVD).
"""

from __future__ import annotations

import logging
import re
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from scan_toolkit.intermediate import IRToolOutput
from scan_toolkit.normalize import logcat_findings, manifest_exported_findings
from scan_toolkit.tools.base import ToolRunner

log = logging.getLogger(__name__)

_DEFAULT_DEVICE = "emulator-5554"
_BOOT_POLLS = 60
_BOOT_POLL_S = 5.0
_MANIFEST_NS = "{http://schemas.android.com/apk/res/android}"

# logcat secret labels (value on the same line = finding candidate)
_LOG_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|session)\b\s*[:=]\s*\S+"
)
_LOG_URL_RE = re.compile(r"https?://[^\s\"']+")


class EmulatorRunner(ToolRunner):
    name = "emulator"

    def __init__(self, workdir: Path, *, device: str = _DEFAULT_DEVICE):
        super().__init__(workdir)
        self.device = device
        self._booted_here = False

    # -- availability --------------------------------------------------------

    def missing_binaries(self) -> list[str]:
        missing = []
        if self._which(self._settings.emulator_bin) is None:
            missing.append(self._settings.emulator_bin)
        if self._which(self._settings.adb_bin) is None:
            missing.append(self._settings.adb_bin)
        return missing

    def available(self) -> bool:
        return not self.missing_binaries()

    # -- lifecycle -----------------------------------------------------------

    def _adb(self, *args: str):
        binary = self._which(self._settings.adb_bin)
        return self._run_cmd([binary, "-s", self.device, *args])

    def boot(self) -> str:
        """Boot the headless AVD and wait for sys.boot_completed=1."""
        if not self.available():
            raise RuntimeError(
                "emulator/ADB unavailable: missing "
                f"{', '.join(self.missing_binaries())}. Install the Android "
                "SDK command-line tools + platform-tools and create the AVD "
                f"({self._settings.dynamic_avd})."
            )
        emu = self._which(self._settings.emulator_bin)
        log.info("Booting AVD %s headless", self._settings.dynamic_avd)
        self._run_cmd([  # fire-and-forget: the emulator daemonises itself
            emu, "-avd", self._settings.dynamic_avd,
            "-no-window", "-no-audio", "-no-snapshot-save", "-wipe-data",
        ])
        self._booted_here = True
        adb = self._which(self._settings.adb_bin)
        self._run_cmd([adb, "wait-for-device"])
        for _ in range(_BOOT_POLLS):
            proc = self._run_cmd(
                [adb, "-s", self.device, "shell",
                 "getprop", "sys.boot_completed"]
            )
            if proc.stdout.strip() == "1":
                log.info("Emulator %s booted", self.device)
                return self.device
            time.sleep(_BOOT_POLL_S)
        raise RuntimeError(f"emulator {self.device} did not finish booting in time")

    def install(self, apk: Path) -> None:
        proc = self._adb("install", "-r", str(apk.resolve()))
        if proc.returncode != 0 or "Success" not in proc.stdout:
            raise RuntimeError(
                f"adb install failed: {(proc.stderr or proc.stdout).strip()[:300]}"
            )
        log.info("Installed %s on %s", apk.name, self.device)
        # Fresh logcat from here — observations cover the instrumented run only.
        self._adb("logcat", "-c")

    def observe(self, package: str, manifest_path: Path | None = None) -> IRToolOutput:
        """Collect runtime observations -> IR findings.

        * dumpsys package (raw, stored for the LLM/reviewer)
        * logcat since install (cleartext URLs, credential logging)
        * exported components from the apktool-decoded manifest (static
          stage artefact — the runtime-attackable surface for this run)
        """
        findings = []
        errors: list[str] = []

        dumpsys = self._adb("shell", "dumpsys", "package", package)
        dumpsys_path = self.tool_dir / "dumpsys_package.txt"
        dumpsys_path.write_text(dumpsys.stdout or dumpsys.stderr)
        if dumpsys.returncode != 0:
            errors.append("dumpsys package failed — raw output may be empty")

        logcat = self._adb("logcat", "-d")
        logcat_path = self.tool_dir / "logcat.txt"
        logcat_path.write_text(logcat.stdout)
        findings.extend(logcat_findings(scan_logcat_text(logcat.stdout)))

        if manifest_path is not None and manifest_path.exists():
            try:
                components = extract_exported_components(manifest_path)
                findings.extend(manifest_exported_findings(components))
            except ValueError as exc:
                errors.append(f"manifest parse failed: {exc}")
        else:
            errors.append(
                "AndroidManifest.xml unavailable (run the static stage first) — "
                "exported-component enumeration skipped"
            )

        return IRToolOutput(
            tool=self.name,
            raw_path=str(self.tool_dir.resolve()),
            findings=findings,
            errors=errors,
        )

    def teardown(self) -> None:
        """Kill the emulator WE booted (never touch a pre-existing one)."""
        if not self._booted_here:
            return
        try:
            self._adb("emu", "kill")
            log.info("Killed emulator %s", self.device)
        except Exception as exc:  # noqa: BLE001 — best effort cleanup
            log.warning("Emulator teardown failed: %s", exc)
        finally:
            self._booted_here = False

    def run(self, apk: Path, package: str) -> IRToolOutput:  # type: ignore[override]
        """Convenience: boot + install + observe + teardown (no Frida)."""
        try:
            self.boot()
            self.install(apk)
            return self.observe(package)
        except RuntimeError as exc:
            return IRToolOutput(tool=self.name, errors=[str(exc)])
        finally:
            self.teardown()


# ---------------------------------------------------------------------------
# Pure extractors (unit-tested with fixtures — no device needed)
# ---------------------------------------------------------------------------

_COMPONENT_KINDS = ("activity", "service", "receiver", "provider")


def extract_exported_components(manifest_path: Path) -> list[dict]:
    """Parse AndroidManifest.xml -> [{kind, name, exported, permission}].

    `android:exported` is explicit since Android 12; when absent the
    component is exported iff it declares an intent-filter (pre-12 rule).
    Raises ValueError on malformed XML.
    """
    try:
        root = ET.parse(manifest_path).getroot()
    except ET.ParseError as exc:
        raise ValueError(f"{manifest_path.name} is not valid XML: {exc}") from exc

    app = root.find("application")
    if app is None:
        raise ValueError(f"{manifest_path.name} has no <application> element")

    components: list[dict] = []
    for kind in _COMPONENT_KINDS:
        for elem in app.findall(kind):
            name = elem.get(f"{_MANIFEST_NS}name", "?")
            permission = elem.get(f"{_MANIFEST_NS}permission")
            exported_raw = elem.get(f"{_MANIFEST_NS}exported")
            if exported_raw is not None:
                exported = exported_raw.strip().lower() == "true"
            else:
                exported = elem.find("intent-filter") is not None
            components.append({
                "kind": kind,
                "name": name,
                "exported": exported,
                "permission": permission,
            })
    return components


def scan_logcat_text(text: str) -> list[dict]:
    """Scan logcat text -> [{kind, tag, line}] hits.

    Kinds: ``cleartext-url`` (http:// outside loopback), ``credential-in-log``
    (secret label + value on one line).  Values stay in the stored line —
    the agent redaction layer scrubs them before any LLM/report boundary.
    """
    hits: list[dict] = []
    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        tag = line.split()[1] if len(line.split()) > 1 else ""
        for url in _LOG_URL_RE.findall(line):
            host = url.split("/")[2] if "://" in url else ""
            if url.startswith("http://") and host not in (
                    "127.0.0.1", "localhost", "10.0.2.2"):
                hits.append({"kind": "cleartext-url", "tag": tag, "line": line})
                break
        if _LOG_SECRET_RE.search(line):
            hits.append({"kind": "credential-in-log", "tag": tag, "line": line})
    return hits
