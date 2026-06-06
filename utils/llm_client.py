import os
from dataclasses import dataclass


@dataclass
class LLMConfig:
    api_key: str
    model: str
    base_url: str | None = None
    provider: str = "openai"

    @property
    def supports_json_mode(self) -> bool:
        return self.provider == "openai"


def resolve_llm_config(config_model: str | None = None) -> LLMConfig:
    """Resolve LLM settings from environment. Priority: Groq > Grok > OpenAI."""
    groq_key = os.getenv("GROQ_API_KEY")
    if groq_key:
        return LLMConfig(
            api_key=groq_key,
            model=config_model or os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile"),
            base_url=os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1"),
            provider="groq",
        )

    grok_key = os.getenv("GROK_API_KEY")
    if grok_key:
        return LLMConfig(
            api_key=grok_key,
            model=config_model or os.getenv("GROK_MODEL", "grok-3-mini"),
            base_url=os.getenv("GROK_BASE_URL", "https://api.x.ai/v1"),
            provider="grok",
        )

    openai_key = os.getenv("OPENAI_API_KEY")
    if openai_key:
        return LLMConfig(
            api_key=openai_key,
            model=config_model or os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
            base_url=None,
            provider="openai",
        )

    raise ValueError(
        "No LLM API key found. Set GROQ_API_KEY, GROK_API_KEY, or OPENAI_API_KEY in .env"
    )
