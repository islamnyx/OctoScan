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
from pathlib import Path
from typing import Any

import httpx

from app.config import ROOT, settings
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


def _endpoint(base_url: str) -> str:
    base = (base_url or "").strip().rstrip("/")
    if not base:
        raise RuntimeError("AI base_url not configured")
    if base.endswith("/chat/completions"):
        return base
    return base + "/chat/completions"


def chat_complete(
    messages: list[dict[str, str]],
    *,
    cfg: dict[str, str] | None = None,
    max_tokens: int | None = None,
    temperature: float = 0.2,
) -> str:
    cfg = cfg or load_config()
    url = _endpoint(cfg.get("base_url", ""))
    model = (cfg.get("model") or "").strip()
    if not model:
        raise RuntimeError("AI model not configured")
    headers = {"Content-Type": "application/json"}
    if cfg.get("api_key"):
        headers["Authorization"] = f"Bearer {cfg['api_key']}"
    payload = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens or settings.ai_max_tokens,
    }
    try:
        r = httpx.post(url, json=payload, headers=headers, timeout=settings.ai_timeout_s)
    except Exception as exc:
        raise RuntimeError(f"AI provider unreachable: {exc}")
    if r.status_code >= 400:
        raise RuntimeError(f"AI provider error {r.status_code}: {r.text[:300]}")
    try:
        data = r.json()
        return data["choices"][0]["message"]["content"] or ""
    except Exception as exc:
        raise RuntimeError(f"AI provider bad response: {exc}")


def test_connection(cfg: dict[str, str] | None = None) -> dict[str, Any]:
    cfg = cfg or load_config()
    out = chat_complete(
        [{"role": "user", "content": "Reply with exactly: ok"}],
        cfg=cfg,
        max_tokens=16,
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


def _findings_digest(findings: list[Finding], limit: int = 40) -> str:
    lines = []
    for f in findings[:limit]:
        lines.append(f"- [{f.severity.value}] {f.title} @ {f.location} :: {(f.description or '')[:220]}")
    if len(findings) > limit:
        lines.append(f"... and {len(findings) - limit} more")
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
    user = (
        f"Target: {target}\n\nFindings:\n{_findings_digest(findings)}\n\n"
        "Return JSON with keys: summary (2-4 sentences), "
        "prioritized_fixes (array of max 5 concrete steps), "
        "false_positive_notes (1-3 sentences)."
    )
    # Retry 429s (review phase drains free-tier OTPM budgets right before
    # this call; the provider's 'try again in Xs' is honored, up to 60s).
    text = None
    import re as _re
    import time as _time

    for attempt in (1, 2, 3):
        try:
            text = chat_complete(
                [
                    {"role": "system", "content": ANALYZE_SYSTEM},
                    {"role": "user", "content": user},
                ],
                cfg=cfg,
                # Free tiers (Groq OTPM 1000) reject bigger asks with
                # guaranteed 429.
                max_tokens=min(settings.ai_max_tokens, 900),
            )
            break
        except RuntimeError as exc:
            if "429" not in str(exc) or attempt == 3:
                raise
            m = _re.search(r"try again in ([\d.]+)s", str(exc))
            _time.sleep(min(float(m.group(1)) + 1.0 if m else 15.0, 60.0))
    summary, fixes, fp_notes = text.strip()[:4000], [], ""
    try:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end > start:
            parsed = json.loads(text[start : end + 1])
            summary = str(parsed.get("summary") or summary)[:4000]
            raw_fixes = parsed.get("prioritized_fixes") or []
            fixes = [str(x)[:400] for x in raw_fixes if str(x).strip()][:5]
            fp_notes = str(parsed.get("false_positive_notes") or "")[:2000]
    except Exception:
        pass
    return AIAnalysis(
        provider=provider,
        model=model,
        summary=summary,
        prioritized_fixes=fixes,
        false_positive_notes=fp_notes,
        raw={"reply_chars": len(text)},
    )


def repo_file_path() -> Path:
    return ROOT / "data" / "ai_config.json"
