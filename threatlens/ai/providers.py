"""Multi-provider AI interface for threat explanations.

Supports: Ollama (local, free), OpenAI, YandexGPT.
"""

import os
import logging
import httpx
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)


class AIProvider:
    """Base interface for AI providers."""

    def explain(self, prompt: str) -> str:
        raise NotImplementedError


class OllamaProvider(AIProvider):
    """Local Ollama provider (free, offline)."""

    def __init__(self):
        self.url = os.getenv("OLLAMA_URL", "http://localhost:11434")
        self.model = os.getenv("OLLAMA_MODEL", "llama3.1")

    def explain(self, prompt: str) -> str:
        try:
            r = httpx.post(
                f"{self.url}/api/generate",
                json={"model": self.model, "prompt": prompt, "stream": False},
                timeout=120.0,
            )
            r.raise_for_status()
            return r.json()["response"]
        except httpx.ConnectError:
            return "[Ollama not running. Start with: ollama serve]"
        except Exception as e:
            logger.error("Ollama error: %s", e)
            return f"[AI error: {e}]"


class OpenAIProvider(AIProvider):
    """OpenAI GPT provider."""

    def __init__(self):
        self.api_key = os.getenv("OPENAI_API_KEY", "")
        self.model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    def explain(self, prompt: str) -> str:
        if not self.api_key:
            return "[OpenAI API key not set. Add OPENAI_API_KEY to .env]"
        try:
            r = httpx.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={
                    "model": self.model,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 500,
                    "temperature": 0.3,
                },
                timeout=60.0,
            )
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"]
        except Exception as e:
            logger.error("OpenAI error: %s", e)
            return f"[AI error: {e}]"


class YandexGPTProvider(AIProvider):
    """YandexGPT provider."""

    def __init__(self):
        self.oauth_token = os.getenv("YANDEX_OAUTH_TOKEN", "")
        self.folder_id = os.getenv("YANDEX_CLOUD_FOLDER_ID", "")
        self._iam_token = None

    def _get_iam_token(self) -> str:
        if self._iam_token:
            return self._iam_token
        r = httpx.post(
            "https://iam.api.cloud.yandex.net/iam/v1/tokens",
            json={"yandexPassportOauthToken": self.oauth_token},
            timeout=10,
        )
        r.raise_for_status()
        self._iam_token = r.json()["iamToken"]
        return self._iam_token

    def explain(self, prompt: str) -> str:
        if not self.oauth_token or not self.folder_id:
            return "[YandexGPT not configured. Add YANDEX_OAUTH_TOKEN and YANDEX_CLOUD_FOLDER_ID to .env]"
        try:
            token = self._get_iam_token()
            r = httpx.post(
                "https://llm.api.cloud.yandex.net/foundationModels/v1/completion",
                headers={"Authorization": f"Bearer {token}"},
                json={
                    "modelUri": f"gpt://{self.folder_id}/yandexgpt/latest",
                    "completionOptions": {"stream": False, "temperature": 0.3, "maxTokens": 500},
                    "messages": [{"role": "user", "text": prompt}],
                },
                timeout=30.0,
            )
            r.raise_for_status()
            return r.json()["result"]["alternatives"][0]["message"]["text"]
        except Exception as e:
            logger.error("YandexGPT error: %s", e)
            return f"[AI error: {e}]"


def get_provider(name: str = None) -> AIProvider:
    """Get AI provider by name."""
    name = name or os.getenv("AI_PROVIDER", "ollama")
    providers = {
        "ollama": OllamaProvider,
        "openai": OpenAIProvider,
        "yandexgpt": YandexGPTProvider,
    }
    if name not in providers:
        raise ValueError(f"Unknown provider: {name}. Choose from: {list(providers.keys())}")
    return providers[name]()
