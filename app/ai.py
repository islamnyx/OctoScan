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


def _defaults() -> dict[str, str]:
    return {
        "provider": (settings.ai_provider or "").strip()[:64],
        "base_url": (settings.ai_base_url or "").strip().rstrip("/")[:512],
        "api_key": (settings.ai_api_key or "")[:512],
        "model": (settings.ai_model or "").strip()[:128],
    }


def load_config() -> dict[str, str]:
    cfg = _defaults()
    try:
        if CONFIG_PATH.exists():
            disk = json.loads(CONFIG_PATH.read_text())
            if isinstance(disk, dict):
                for k in ("provider", "base_url", "api_key", "model"):
                    v = disk.get(k)
                    if isinstance(v, str) and v.strip():
                        cfg[k] = v.strip()[:512]
                cfg["base_url"] = cfg["base_url"].rstrip("/")
    except Exception:
        pass
    return cfg


def save_config(provider: str, base_url: str, api_key: str, model: str) -> dict[str, str]:
    cfg = {
        "provider": (provider or "").strip()[:64],
        "base_url": (base_url or "").strip().rstrip("/")[:512],
        "api_key": (api_key or "")[:512],
        "model": (model or "").strip()[:128],
    }
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    # Key on disk with 0600 intent; best-effort on Windows.
    try:
        CONFIG_PATH.write_text(json.dumps({k: v for k, v in cfg.items() if k != "api_key" or True}, indent=2))
        try:
            import os

            os.chmod(CONFIG_PATH, 0o600)
        except Exception:
            pass
    except Exception as exc:
        raise RuntimeError(f"cannot persist AI config: {exc}")
    return cfg


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
    text = chat_complete(
        [
            {"role": "system", "content": ANALYZE_SYSTEM},
            {"role": "user", "content": user},
        ],
        cfg=cfg,
    )
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
