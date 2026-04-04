"""YandexGPT AI provider for threat explanations."""

import os
import logging
import httpx
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)


class YandexGPTProvider:
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
            return "[YandexGPT not configured. Add YANDEX_OAUTH_TOKEN and YANDEX_CLOUD_FOLDER_ID to env]"
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


def get_provider(name: str = None) -> YandexGPTProvider:
    """Get AI provider (YandexGPT)."""
    return YandexGPTProvider()
