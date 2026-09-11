import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

from app.config import settings
from app.models import Finding, Severity
from app.normalize import nmap_port_severity
from app.scanners.base import BaseScanner


class NmapScanner(BaseScanner):
    name = "nmap"

    def run(self) -> list[Finding]:
        xml_path = self.workdir / "nmap.xml"
        cmd = [
            settings.nmap_bin,
            "-sV",
            "-T4",
            "--top-ports",
            "200",
            "-oX",
            str(xml_path),
            self.host,
        ]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=settings.scan_timeout_seconds,
        )
        if proc.returncode != 0 and not xml_path.exists():
            raise RuntimeError(proc.stderr.strip() or "nmap failed")
        if not xml_path.exists():
            return []
        return self._parse(xml_path)

    def _parse(self, xml_path: Path) -> list[Finding]:
        findings: list[Finding] = []
        skipped_self: list[str] = []
        root = ET.parse(xml_path).getroot()
        for port in root.findall(".//port"):
            state = (port.find("state").get("state") if port.find("state") is not None else "")
            if state != "open":
                continue
            service_el = port.find("service")
            service = service_el.get("name", "unknown") if service_el is not None else "unknown"
            product = service_el.get("product", "") if service_el is not None else ""
            version = service_el.get("version", "") if service_el is not None else ""
            method = service_el.get("method", "") if service_el is not None else ""
            try:
                conf = int(service_el.get("conf", "0") or 0) if service_el is not None else 0
            except ValueError:
                conf = 0
            servicefp = service_el.get("servicefp", "") if service_el is not None else ""
            proto = port.get("protocol", "tcp")
            portid = port.get("portid", "")
            # Scanning localhost also sees our own API + ZAP daemon.
            # Those are scan infrastructure, not target attack surface.
            if self._is_self_port(portid):
                skipped_self.append(f"{portid}/{proto}")
                continue
            # Nmap labels unknown ports from its port table (method=table,
            # low conf) — e.g. 3000 as "ppp" — even when its own probe
            # captured an HTTP banner (servicefp contains the Juice Shop
            # HTTP/1.1 200 response). Never present a table guess as fact:
            # if the banner is HTTP or the port is the scanned web target,
            # correct the service and record the guess in raw.
            service_guess = ""
            service_corrected = False
            if method == "table" or (service == "unknown" and conf < 5):
                if "HTTP/1." in servicefp or (
                    portid == str(self.port) and self.scheme in ("http", "https")
                ):
                    service_guess = service
                    service = self.scheme
                    service_corrected = True
            location = f"{self.host}:{portid}/{proto}"
            detail = " ".join(part for part in [service, product, version] if part)
            severity = nmap_port_severity(state, service)
            description = f"Service exposed: {detail or service}."
            if service_corrected:
                description += f" Nmap guessed '{service_guess}' from its port table (conf {conf}); probe banner shows HTTP, corrected."
            findings.append(
                Finding(
                    scanner=self.name,
                    title=f"Open port {portid}/{proto} ({service})",
                    severity=severity,
                    description=description,
                    evidence=location,
                    location=location,
                    recommendation=self._recommendation(service, portid),
                    raw={
                        "port": portid,
                        "protocol": proto,
                        "service": service,
                        "product": product,
                        "method": method,
                        "conf": conf,
                        "service_guess": service_guess or None,
                        "service_corrected": service_corrected,
                    },
                )
            )
        if not findings:
            if skipped_self:
                findings.append(
                    Finding(
                        scanner=self.name,
                        title=f"Only self ports open ({', '.join(skipped_self)}) — skipped",
                        severity=Severity.info,
                        description="Nmap only found the scanner's own API/ZAP ports on loopback; they were excluded as scan infrastructure.",
                        location=self.host,
                        raw={"skipped_self_ports": skipped_self},
                    )
                )
            else:
                findings.append(
                    Finding(
                        scanner=self.name,
                        title="No open ports in top 200",
                        severity=Severity.info,
                        description="Nmap did not report open ports in the top 200 TCP ports.",
                        location=self.host,
                    )
                )
        return findings

    def _is_self_port(self, portid: str) -> bool:
        if self.host not in ("localhost", "127.0.0.1", "::1"):
            return False
        return portid in {str(settings.app_port), str(settings.zap_port)}

    @staticmethod
    def _recommendation(service: str, port: str) -> str:
        risky = {"ftp", "telnet", "rlogin", "vnc"}
        if service in risky:
            return "Disable this service or restrict it behind a firewall / VPN."
        if port in {"80", "443"}:
            return "Keep only required web ports public; hide admin interfaces."
        return "Confirm this port is required. If not, close it or bind it to localhost."
