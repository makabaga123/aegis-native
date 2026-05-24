from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

try:
    import httpx
except Exception:  # pragma: no cover - optional dependency import guard
    httpx = None  # type: ignore


SECRET_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[MASKED_AWS_ACCESS_KEY]"),
    (re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*['\"]?[^'\"\s]+"), r"\1=[MASKED]"),
    (re.compile(r"eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}"), "[MASKED_JWT]"),
]


def mask_sensitive_text(text: str, max_chars: int = 12000) -> str:
    masked = text[:max_chars]
    for pattern, repl in SECRET_PATTERNS:
        masked = pattern.sub(repl, masked)
    return masked


@dataclass
class LLMResponse:
    provider: str
    model: str
    configured: bool
    content: str
    error: Optional[str] = None


class LLMProvider:
    """OpenAI-compatible LLM provider with DeepSeek/Zhipu/GPT/Ollama presets.

    Runtime configuration is entirely environment-variable based. No key is stored
    in code or config files.
    """

    def __init__(self) -> None:
        self.provider = os.getenv("LLM_PROVIDER", "local").lower()
        self.timeout = float(os.getenv("LLM_TIMEOUT", "45"))
        self.temperature = float(os.getenv("LLM_TEMPERATURE", "0.1"))
        self.model = os.getenv("LLM_MODEL") or self._default_model()
        self.base_url = os.getenv("LLM_BASE_URL") or self._default_base_url()
        self.api_key = self._resolve_api_key()

    def _default_model(self) -> str:
        if self.provider == "deepseek":
            return os.getenv("DEEPSEEK_MODEL", "deepseek-chat")
        if self.provider == "zhipu":
            return os.getenv("ZHIPU_MODEL", "glm-4-flash")
        if self.provider == "openai":
            return os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        if self.provider == "ollama":
            return os.getenv("OLLAMA_MODEL", "qwen2.5-coder:7b")
        return os.getenv("LOCAL_MODEL", "local-rule-reasoner")

    def _default_base_url(self) -> str:
        if self.provider == "deepseek":
            return os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1")
        if self.provider == "zhipu":
            return os.getenv("ZHIPU_BASE_URL", "https://open.bigmodel.cn/api/paas/v4")
        if self.provider == "openai":
            return os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
        if self.provider == "ollama":
            return os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434/v1")
        return "local"

    def _resolve_api_key(self) -> Optional[str]:
        if self.provider == "deepseek":
            return os.getenv("DEEPSEEK_API_KEY") or os.getenv("LLM_API_KEY")
        if self.provider == "zhipu":
            return os.getenv("ZHIPU_API_KEY") or os.getenv("LLM_API_KEY")
        if self.provider == "openai":
            return os.getenv("OPENAI_API_KEY") or os.getenv("LLM_API_KEY")
        if self.provider in {"openai-compatible", "compatible", "custom"}:
            return os.getenv("LLM_API_KEY")
        if self.provider == "ollama":
            return os.getenv("OLLAMA_API_KEY") or "ollama"
        return None

    @property
    def configured(self) -> bool:
        if self.provider in {"local", "none", "disabled"}:
            return False
        if self.provider == "ollama":
            return True
        return bool(self.api_key and self.base_url)

    def chat_json(self, *, system: str, user: str) -> LLMResponse:
        user = mask_sensitive_text(user)
        if not self.configured or httpx is None:
            reason = "LLM provider not configured" if not self.configured else "httpx not installed"
            return LLMResponse(provider=self.provider, model=self.model, configured=False, content="", error=reason)

        headers = {"Content-Type": "application/json"}
        if self.provider != "ollama" and self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": self.temperature,
            "response_format": {"type": "json_object"},
        }
        url = self.base_url.rstrip("/") + "/chat/completions"
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(url, headers=headers, json=payload)
                resp.raise_for_status()
                data = resp.json()
            content = data["choices"][0]["message"]["content"]
            return LLMResponse(provider=self.provider, model=self.model, configured=True, content=content)
        except Exception as exc:  # pragma: no cover - network dependent
            return LLMResponse(provider=self.provider, model=self.model, configured=True, content="", error=str(exc))

    def parse_json_content(self, content: str) -> Dict[str, Any]:
        if not content:
            return {}
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            start = content.find("{")
            end = content.rfind("}")
            if start >= 0 and end > start:
                try:
                    return json.loads(content[start : end + 1])
                except json.JSONDecodeError:
                    return {"raw_text": content}
            return {"raw_text": content}

    def safe_config(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "model": self.model,
            "base_url": self.base_url,
            "configured": self.configured,
            "api_key_loaded": bool(self.api_key),
        }
