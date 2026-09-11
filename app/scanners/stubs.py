from app.models import Finding, Severity
from app.scanners.base import BaseScanner


class GitleaksScanner(BaseScanner):
    name = "gitleaks"

    def run(self) -> list[Finding]:
        return [
            Finding(
                scanner=self.name,
                title="Source scan not enabled",
                severity=Severity.info,
                description="Gitleaks runs when a repo is provided. MVP scans are black-box URL only.",
                location=self.target_url,
            )
        ]


class DependencyCheckScanner(BaseScanner):
    name = "dependency-check"

    def run(self) -> list[Finding]:
        return [
            Finding(
                scanner=self.name,
                title="Dependency scan not enabled",
                severity=Severity.info,
                description="OWASP Dependency-Check is reserved for optional source/repo scans.",
                location=self.target_url,
            )
        ]
