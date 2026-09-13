"""Repo fetch for Phase-2 source scans.

Fail-closed: https only, no credentials, host allowlist-adjacent
(public hosts by default; private/loopback need ALLOW_PRIVATE_TARGETS),
shallow clone, timeouts, file/size caps. Never executes repo code.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from fastapi import HTTPException

from app.config import settings

_REPO_RE = re.compile(r"^[A-Za-z0-9._\-/]{1,256}$")
_BRANCH_RE = re.compile(r"^[A-Za-z0-9._\-/]{1,128}$")

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv",
    "__pycache__", ".tox", ".mypy_cache", ".pytest_cache", "dist", "build",
}


def validate_repo_url(repo_url: str) -> str:
    if not repo_url or len(repo_url) > 512:
        raise HTTPException(400, "repo_url must be 1-512 chars")
    repo_url = repo_url.strip()
    try:
        p = urlparse(repo_url)
    except Exception:
        raise HTTPException(400, "unparsable repo_url")
    if p.scheme != "https":
        raise HTTPException(400, "only https repo URLs allowed")
    if p.username or p.password or "@" in (p.netloc or ""):
        raise HTTPException(400, "credentials in repo URL not allowed")
    host = (p.hostname or "").lower()
    if not host or len(host) > 253:
        raise HTTPException(400, "repo URL needs a hostname")
    # Reuse SSRF posture: private targets need explicit lab opt-in.
    if not settings.allow_private_targets:
        import ipaddress
        import socket

        try:
            ip = ipaddress.ip_address(host)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_unspecified:
                raise HTTPException(403, "internal repo host blocked")
        except ValueError:
            try:
                infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
                for info in infos:
                    ip = ipaddress.ip_address(info[4][0])
                    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_unspecified:
                        raise HTTPException(403, "internal repo host blocked")
            except socket.gaierror:
                raise HTTPException(400, "repo hostname does not resolve")
    path = (p.path or "").strip()
    if not path or len(path) > 256 or not _REPO_RE.match(path.strip("/")):
        raise HTTPException(400, "invalid repo path")
    return repo_url


def validate_branch(branch: str | None) -> str | None:
    if branch is None:
        return None
    branch = branch.strip()
    if not branch:
        return None
    if not _BRANCH_RE.match(branch) or branch.startswith("-") or ".." in branch:
        raise HTTPException(400, "invalid branch")
    return branch


def clone_repo(repo_url: str, dest: Path, branch: str | None = None) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    cmd = [settings.git_bin, "clone", "--depth", "1", "--single-branch"]
    if branch:
        cmd += ["--branch", branch]
    cmd += [repo_url, str(dest)]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=settings.repo_clone_timeout_s
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("git clone timed out")
    except FileNotFoundError:
        raise RuntimeError("git binary not found (GIT_BIN)")
    if proc.returncode != 0 or not dest.exists():
        msg = (proc.stderr or proc.stdout or "clone failed").strip()
        raise RuntimeError(f"git clone failed: {msg[-300:]}")
    return dest


def iter_repo_files(root: Path) -> list[Path]:
    out: list[Path] = []
    total_bytes = 0
    for p in sorted(root.rglob("*")):
        if len(out) >= settings.repo_max_files:
            break
        try:
            if not p.is_file() or p.is_symlink():
                continue
            if any(part in SKIP_DIRS for part in p.relative_to(root).parts):
                continue
            if p.stat().st_size > 2 * 1024 * 1024:
                continue
            total_bytes += p.stat().st_size
            if total_bytes > settings.repo_max_bytes:
                break
            out.append(p)
        except Exception:
            continue
    return out
