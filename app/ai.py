"""BYO AI layer (Phase 2).

Any provider exposing an OpenAI-compatible
POST {base_url}/chat/completions endpoint works:
OpenAI, OpenRouter, Together, Groq, Anthropic-proxy,
Google-proxy, Ollama, LM Studio, vLLM, custom gateway.

No SDK deps — plain httpx, so requirements.txt stays minimal.
Keys live in data/ai_config.json (UI-editable) with .env as defaults.
Never log keys.
"""
from __future__ import annotations

import json
from typing import Any

import httpx
from pydantic import BaseModel, Field, field_validator

from app.config import settings
from app.models import AIAnalysis, Finding

CONFIG_PATH = settings.data_dir / "ai_config.json"

# Presets shown in the dashboard dropdown. base_url is editable anyway.
PROVIDER_PRESETS: dict[str, str] = {
    "openai": "https://api.openai.com/v1",
    "openrouter": "https://openrouter.ai/api/v1",
    "together": "https://api.together.xyz/v1",
    "groq": "https://api.groq.com/openai/v1",
    "ollama": "http://localhost:11434/v1",
    "lmstudio": "http://localhost:1234/v1",
    "nvidia": "https://integrate.api.nvidia.com/v1",
    # Our vLLM on an NVIDIA Brev GPU: base URL is per instance (https://<host>/v1).
    "brev": "",
    "custom": "",
}


def _load_store() -> dict:
    """Provider store: {active: name, providers: {name: cfg}}.

    Migrates the legacy single-provider flat format transparently.
    """
    try:
        data = json.loads(CONFIG_PATH.read_text())
    except Exception:
        data = {}
    if not isinstance(data, dict):
        data = {}
    if not isinstance(data.get("providers"), dict):
        name = (data.get("provider") or "").strip()[:64] or "default"
        data = {
            "active": name,
            "providers": {
                name: {
                    "name": name,
                    "provider": name,
                    "base_url": (data.get("base_url") or "").strip(),
                    "api_key": (data.get("api_key") or ""),
                    "model": (data.get("model") or ""),
                }
            },
        }
    if not data.get("providers"):
        data["providers"] = {}
    if not data.get("active") or data["active"] not in data["providers"]:
        data["active"] = next(iter(data["providers"]), "")
    return data


def _write_store(store: dict) -> None:
    active = store["providers"].get(store.get("active") or "", {})
    data = {
        "active": store.get("active", ""),
        "providers": store["providers"],
        # Flattened active provider: legacy readers stay working.
        "provider": active.get("provider", ""),
        "base_url": active.get("base_url", ""),
        "api_key": active.get("api_key", ""),
        "model": active.get("model", ""),
    }
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    # Key on disk with 0600 intent; best-effort on Windows.
    CONFIG_PATH.write_text(json.dumps(data, indent=2))
    try:
        import os

        os.chmod(CONFIG_PATH, 0o600)
    except Exception:
        pass


def list_providers() -> dict:
    store = _load_store()
    out = []
    for name, p in store["providers"].items():
        out.append({
            "name": name,
            "provider": p.get("provider", ""),
            "base_url": p.get("base_url", ""),
            "model": p.get("model", ""),
            "has_key": bool(p.get("api_key")),
            "active": name == store.get("active"),
        })
    return {"active": store.get("active", ""), "providers": out}


def upsert_provider(
    name: str = "",
    provider: str = "",
    base_url: str = "",
    api_key: str = "",
    model: str = "",
    activate: bool = False,
) -> dict:
    """Add or update a provider profile. Empty api_key keeps the stored one."""
    store = _load_store()
    name = (name or "").strip()[:64] or (provider or "").strip()[:64] or "default"
    existing = store["providers"].get(name, {})
    p = {
        "name": name,
        "provider": (provider or existing.get("provider") or name).strip()[:64],
        "base_url": (base_url or existing.get("base_url", "")).strip().rstrip("/")[:512],
        "api_key": (api_key if api_key else existing.get("api_key", ""))[:512],
        "model": (model or existing.get("model", "")).strip()[:128],
    }
    store["providers"][name] = p
    if activate or not store.get("active"):
        store["active"] = name
    _write_store(store)
    return p


def delete_provider(name: str) -> None:
    store = _load_store()
    store["providers"].pop(name, None)
    if store.get("active") == name:
        store["active"] = next(iter(store["providers"]), "")
    _write_store(store)


def activate_provider(name: str) -> dict:
    store = _load_store()
    if name not in store["providers"]:
        raise RuntimeError(f"no such provider: {name}")
    store["active"] = name
    _write_store(store)
    return store["providers"][name]


def load_config() -> dict[str, str]:
    """Active provider's config (backward-compatible flat dict)."""
    store = _load_store()
    p = store["providers"].get(store.get("active") or "", {})
    return {
        "name": p.get("name", ""),
        "provider": p.get("provider", ""),
        "base_url": p.get("base_url", ""),
        "api_key": p.get("api_key", ""),
        "model": p.get("model", ""),
    }


def save_config(provider: str, base_url: str, api_key: str, model: str) -> dict[str, str]:
    """Legacy entry point: upserts under the provider-type name and activates."""
    p = upsert_provider(name=provider or "default", provider=provider,
                        base_url=base_url, api_key=api_key, model=model, activate=True)
    return {k: p.get(k, "") for k in ("provider", "base_url", "api_key", "model")}


def masked(cfg: dict[str, str]) -> dict[str, Any]:
    return {
        "provider": cfg.get("provider", ""),
        "base_url": cfg.get("base_url", ""),
        "model": cfg.get("model", ""),
        "has_key": bool(cfg.get("api_key")),
        "configured": bool(cfg.get("base_url") and cfg.get("model")),
    }


def chat_complete(
    messages: list[dict[str, str]],
    *,
    cfg: dict[str, str] | None = None,
    max_tokens: int | None = None,
    temperature: float = 0.2,
    fallback: bool = True,
    purpose: str = "chat",
) -> str:
    """Free-text completion via app.ai_core: secrets redacted, fallback to
    the other saved providers, every call logged. Raises RuntimeError."""
    from app import ai_core

    text, _meta = ai_core.call_text(
        messages,
        cfg=cfg,
        fallback=fallback,
        max_tokens=max_tokens or settings.ai_max_tokens,
        temperature=temperature,
        purpose=purpose,
    )
    return text


def test_connection(cfg: dict[str, str] | None = None) -> dict[str, Any]:
    cfg = cfg or load_config()
    # No fallback: this tests THIS provider. 256 tokens so reasoning models
    # have room to finish thinking before "ok".
    out = chat_complete(
        [{"role": "user", "content": "Reply with exactly: ok"}],
        cfg=cfg,
        max_tokens=256,
        fallback=False,
        purpose="test-connection",
    )
    return {"ok": True, "reply": out.strip()[:200]}


def list_models(cfg: dict[str, str] | None = None) -> dict[str, Any]:
    """Fetch the provider's model list (OpenAI-compatible GET /models).

    Works for Groq/OpenAI/OpenRouter/Together/Ollama/LM Studio. Used by
    the dashboard's model picker so users never type model ids by hand.
    """
    cfg = cfg or load_config()
    base = (cfg.get("base_url") or "").strip().rstrip("/")
    if not base:
        raise RuntimeError("AI base_url not configured")
    url = base + "/models"
    headers = {}
    if cfg.get("api_key"):
        headers["Authorization"] = f"Bearer {cfg['api_key']}"
    try:
        r = httpx.get(url, headers=headers, timeout=15)
    except Exception as exc:
        raise RuntimeError(f"model list unreachable: {exc}")
    if r.status_code >= 400:
        raise RuntimeError(f"model list failed {r.status_code}: {r.text[:200]}")
    try:
        data = r.json()
    except Exception as exc:
        raise RuntimeError(f"model list bad response: {exc}")
    items = data.get("data") if isinstance(data, dict) else None
    if items is None and isinstance(data, dict):
        items = data.get("models")
    if items is None and isinstance(data, list):
        items = data
    ids: list[str] = []
    entries: list[dict[str, str]] = []
    for m in items or []:
        if isinstance(m, dict):
            mid = m.get("id") or m.get("name") or m.get("model")
            if not mid:
                continue
            mid = str(mid)
            owner = str(m.get("owned_by") or m.get("owner") or "").strip()
            ids.append(mid)
            entries.append({"id": mid, "owner": owner})
        elif isinstance(m, str):
            ids.append(m)
            entries.append({"id": m, "owner": ""})
    # De-dupe by id, keep first owner seen.
    seen: dict[str, str] = {}
    for e in entries:
        seen.setdefault(e["id"], e["owner"])
    entries = [{"id": k, "owner": v} for k, v in sorted(seen.items())]
    return {
        "models": sorted(seen),
        "entries": entries,
        "provider": (cfg.get("provider") or "").strip(),
    }


def _is_low_signal(f: Finding) -> bool:
    raw = f.raw or {}
    return raw.get("scope") == "dev" or bool(raw.get("likely_test_fixture"))


def _digest_pick(findings: list[Finding], limit: int = 40) -> list[Finding]:
    """Balanced sample for the prompt: round-robin across scanners (each
    keeps its priority order), then dev-only deps / test fixtures only fill
    leftover slots. On NodeGoat the plain top 40 was 40/40 OSV; on Juice
    Shop plain round-robin spent 11 slots on gitleaks test fixtures."""
    picked: list[Finding] = []
    for pool in (
        [f for f in findings if not _is_low_signal(f)],
        [f for f in findings if _is_low_signal(f)],
    ):
        by_scanner: dict[str, list[Finding]] = {}
        for f in pool:
            by_scanner.setdefault(f.scanner, []).append(f)
        while len(picked) < limit and any(by_scanner.values()):
            for queue in by_scanner.values():
                if queue and len(picked) < limit:
                    picked.append(queue.pop(0))
    return picked


def _findings_digest(findings: list[Finding], limit: int = 40) -> str:
    picked = _digest_pick(findings, limit)
    lines = [
        f"- [{f.severity.value}] ({f.scanner}) {f.title} @ {f.location} :: {(f.description or '')[:220]}"
        for f in picked
    ]
    if len(findings) > len(picked):
        lines.append(f"... and {len(findings) - len(picked)} more")
    return "\n".join(lines)


ANALYZE_SYSTEM = (
    "You are a pragmatic AppSec reviewer for early-stage startups. "
    "Prioritize exploitability, cut false positives, give concrete fixes "
    "with file/line references when present. Be concise."
)


def analyze_findings(
    target: str,
    findings: list[Finding],
    *,
    cfg: dict[str, str] | None = None,
) -> AIAnalysis:
    cfg = cfg or load_config()
    provider = cfg.get("provider", "")
    model = cfg.get("model", "")
    if not findings:
        return AIAnalysis(
            provider=provider,
            model=model,
            summary=f"No findings for {target} — nothing to triage.",
        )
    from app import ai_core

    if not ai_core.provider_chain(cfg):
        raise RuntimeError("AI base_url/model not configured")
    user = (
        f"Target: {target}\n\nFindings:\n{_findings_digest(findings)}\n\n"
        "Return JSON with keys: summary (2-4 sentences), "
        "prioritized_fixes (array of max 5 concrete steps), "
        "false_positive_notes (1-3 sentences)."
    )
    try:
        reply, meta = ai_core.call_json(
            [
                {"role": "system", "content": ANALYZE_SYSTEM},
                {"role": "user", "content": user},
            ],
            AnalyzeReply,
            cfg=cfg,
            # Free tiers (Groq OTPM 1000) reject bigger asks with a 429.
            max_tokens=min(settings.ai_max_tokens, 900),
            purpose="analyze",
        )
    except ai_core.AIError as exc:
        return _fallback_analysis(target, findings, provider, model, exc)
    return AIAnalysis(
        provider=meta["provider"],
        model=meta["model"],
        summary=reply.summary[:4000],
        prioritized_fixes=[x[:400] for x in reply.prioritized_fixes if x.strip()][:5],
        false_positive_notes=reply.false_positive_notes[:2000],
        raw={k: meta[k] for k in ("latency_ms", "tokens_in", "tokens_out", "fallback_used", "attempts")},
    )


class AnalyzeReply(BaseModel):
    summary: str
    prioritized_fixes: list[str] = Field(default_factory=list)
    false_positive_notes: str = ""

    @field_validator("prioritized_fixes", mode="before")
    @classmethod
    def _fixes_as_text(cls, v: Any) -> Any:
        # Models often return [{"step": ..., "file": ...}]: keep the content.
        if isinstance(v, list):
            return [
                " — ".join(str(x) for x in item.values()) if isinstance(item, dict) else str(item)
                for item in v
            ]
        return v


def _fallback_analysis(
    target: str, findings: list[Finding], provider: str, model: str, exc: Exception
) -> AIAnalysis:
    """Non-AI result when every provider failed: counts + top fixes from the
    scanners' own recommendations, clearly labelled as not AI."""
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    count_txt = ", ".join(f"{n} {sev}" for sev, n in counts.items())
    top = _digest_pick(findings, 5)
    return AIAnalysis(
        provider=provider,
        model=model,
        summary=(
            f"AI unavailable ({str(exc)[:160]}). Rule-based summary for {target}: "
            f"{len(findings)} findings ({count_txt})."
        ),
        prioritized_fixes=[
            f"{f.title}: {(f.recommendation or 'review and remediate')[:250]}" for f in top
        ],
        false_positive_notes="Not assessed: no AI triage ran.",
        raw={"fallback": "non-ai", "error": str(exc)[:300]},
    )
