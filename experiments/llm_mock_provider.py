"""Deterministic mock provider for testing LLM fuzzing workflows."""

from experiments.llm_provider import LLMProvider


class MockLLMProvider(LLMProvider):
    def __init__(self, responses=None):
        self.responses = list(responses or [])
        self.prompts = []

    def generate_text(self, prompt: str) -> str:
        self.prompts.append(prompt)
        if not self.responses:
            raise RuntimeError("MockLLMProvider has no responses configured")
        return self.responses.pop(0)
