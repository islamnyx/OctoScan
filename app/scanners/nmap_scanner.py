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
        root = ET.parse(xml_path).getroot()
        for port in root.findall(".//port"):
            state = (port.find("state").get("state") if port.find("state") is not None else "")
            if state != "open":
                continue
            service_el = port.find("service")
            service = service_el.get("name", "unknown") if service_el is not None else "unknown"
            product = service_el.get("product", "") if service_el is not None else ""
            version = service_el.get("version", "") if service_el is not None else ""
            proto = port.get("protocol", "tcp")
            portid = port.get("portid", "")
            location = f"{self.host}:{portid}/{proto}"
            detail = " ".join(part for part in [service, product, version] if part)
            severity = nmap_port_severity(state, service)
            findings.append(
                Finding(
                    scanner=self.name,
                    title=f"Open port {portid}/{proto} ({service})",
                    severity=severity,
                    description=f"Service exposed: {detail or service}.",
                    evidence=location,
                    location=location,
                    recommendation=self._recommendation(service, portid),
                    raw={"port": portid, "protocol": proto, "service": service, "product": product},
                )
            )
        if not findings:
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

    @staticmethod
    def _recommendation(service: str, port: str) -> str:
        risky = {"ftp", "telnet", "rlogin", "vnc"}
        if service in risky:
            return "Disable this service or restrict it behind a firewall / VPN."
        if port in {"80", "443"}:
            return "Keep only required web ports public; hide admin interfaces."
        return "Confirm this port is required. If not, close it or bind it to localhost."
