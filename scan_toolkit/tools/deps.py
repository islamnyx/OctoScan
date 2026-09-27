"""Dependency extractor — pull third-party library info from a decompiled APK.

Strategies (tried in order, first success wins):
  1. Parse ``build.gradle`` / ``build.gradle.kts`` found by apktool/jadx for
     Maven coordinates (group:artifact:version).
  2. Scan ``lib/`` folders for ``.so`` filenames and ``classes.dex`` for known
     package prefixes (fallback heuristic).
  3. Parse ``META-INF/maven`` POM files embedded in the APK's JAR dependencies.

The output is a list of ``Dependency`` dicts suitable for querying OSV.dev or
feeding to Grype.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Dependency:
    """One third-party library extracted from an APK."""
    name: str                     # e.g. "com.squareup.okhttp3:okhttp"
    version: str | None = None    # e.g. "4.12.0"
    ecosystem: str = "Maven"      # OSV ecosystem identifier
    source: str = ""              # how we found it (gradle, pom, heuristic)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "source": self.source,
        }


# ---------------------------------------------------------------------------
# Gradle dependency parser
# ---------------------------------------------------------------------------

# Matches:  implementation 'group:artifact:version'
#           implementation "group:artifact:version"
#           api("group:artifact:version")
#           compile 'group:artifact:version'
_GRADLE_DEP_RE = re.compile(
    r"""(?:implementation|api|compile|runtimeOnly|compileOnly|testImplementation)\s*"""
    r"""[\(]?\s*['"]([^'"]+:[^'"]+:[^'"]+)['"]\s*[\)]?""",
    re.IGNORECASE,
)

# Matches Kotlin DSL:  implementation("group:artifact:version")
_GRADLE_KTS_RE = re.compile(
    r"""(?:implementation|api|compile|runtimeOnly|compileOnly)\s*\(\s*"""
    r"""['"]([^'"]+:[^'"]+:[^'"]+)['"]\s*\)""",
    re.IGNORECASE,
)


def _parse_gradle(path: Path) -> list[Dependency]:
    """Parse a build.gradle or build.gradle.kts for Maven coordinates."""
    text = path.read_text(errors="replace")
    pattern = _GRADLE_KTS_RE if path.suffix == ".kts" else _GRADLE_DEP_RE
    deps: list[Dependency] = []
    seen: set[str] = set()
    for m in pattern.finditer(text):
        coord = m.group(1).strip()
        parts = coord.split(":")
        if len(parts) >= 3:
            name = f"{parts[0]}:{parts[1]}"
            version = parts[2]
        elif len(parts) == 2:
            name = coord
            version = None
        else:
            continue
        key = f"{name}:{version}"
        if key not in seen:
            seen.add(key)
            deps.append(Dependency(name=name, version=version, source=f"gradle:{path.name}"))
    return deps


# ---------------------------------------------------------------------------
# META-INF/maven POM parser
# ---------------------------------------------------------------------------

_POM_GROUP_RE = re.compile(r"<groupId>\s*([^<]+)\s*</groupId>")
_POM_ARTIFACT_RE = re.compile(r"<artifactId>\s*([^<]+)\s*</artifactId>")
_POM_VERSION_RE = re.compile(r"<version>\s*([^<]+)\s*</version>")


def _parse_pom(path: Path) -> Dependency | None:
    """Parse a pom.xml or pom.properties for a single dependency."""
    if path.name == "pom.properties":
        props: dict[str, str] = {}
        for line in path.read_text(errors="replace").splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                props[k.strip()] = v.strip()
        group = props.get("groupId", "")
        artifact = props.get("artifactId", "")
        version = props.get("version")
        if group and artifact:
            return Dependency(
                name=f"{group}:{artifact}",
                version=version,
                source=f"pom.properties:{path}",
            )
        return None

    # pom.xml
    text = path.read_text(errors="replace")
    group = (_POM_GROUP_RE.search(text) or _empty()).group(1).strip()
    artifact = (_POM_ARTIFACT_RE.search(text) or _empty()).group(1).strip()
    version_m = _POM_VERSION_RE.search(text)
    version = version_m.group(1).strip() if version_m else None
    if group and artifact:
        return Dependency(
            name=f"{group}:{artifact}",
            version=version,
            source=f"pom.xml:{path}",
        )
    return None


class _empty:
    """Placeholder for failed regex match."""
    def group(self, _):
        return ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def extract_dependencies(decompiled_dir: Path) -> list[Dependency]:
    """Extract dependencies from a decompiled APK directory.

    Parameters
    ----------
    decompiled_dir : Path
        Root of the decompiled APK (apktool output, jadx output, or similar).

    Returns
    -------
    list[Dependency]
        Deduplicated list of discovered dependencies.
    """
    deps: list[Dependency] = []
    seen: set[str] = set()

    def _add(d: Dependency) -> None:
        key = f"{d.name}:{d.version}"
        if key not in seen:
            seen.add(key)
            deps.append(d)

    # 1. Gradle files
    for pattern in ("**/build.gradle", "**/build.gradle.kts"):
        for gradle_file in decompiled_dir.rglob(pattern):
            for d in _parse_gradle(gradle_file):
                _add(d)

    # 2. META-INF/maven POMs
    for pom in decompiled_dir.rglob("META-INF/maven/**/pom.xml"):
        d = _parse_pom(pom)
        if d:
            _add(d)
    for props in decompiled_dir.rglob("META-INF/maven/**/pom.properties"):
        d = _parse_pom(props)
        if d:
            _add(d)

    return deps
