"""LLM provider interface and local Ollama backend."""

import json
import urllib.request
import urllib.error


class LLMProviderNotConfigured(RuntimeError):
    """Raised when no LLM backend has been configured."""


class LLMProvider:
    def generate_text(self, prompt: str) -> str:
        raise LLMProviderNotConfigured(
            "No LLM backend configured. Use OllamaProvider or another backend."
        )

    def propose_protocol_patch(self, prompt: str) -> str:
        return self.generate_text(prompt)

    def propose_fuzzing_strategy(self, prompt: str) -> str:
        return self.generate_text(prompt)


class OllamaProvider(LLMProvider):
    def __init__(
        self,
        model="qwen2.5-coder:7b",
        host="http://localhost:11434",
        timeout=180,
    ):
        self.model = model
        self.host = host.rstrip("/")
        self.timeout = timeout

    def generate_text(self, prompt: str) -> str:
        payload = json.dumps({
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0},
        }).encode("utf-8")

        request = urllib.request.Request(
            f"{self.host}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(
                request, timeout=self.timeout
            ) as response:
                result = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError) as exc:
            raise RuntimeError(f"Ollama request failed: {exc}") from exc

        text = result.get("response")
        if not isinstance(text, str) or not text.strip():
            raise RuntimeError("Ollama returned an empty response")
        return text.strip()
