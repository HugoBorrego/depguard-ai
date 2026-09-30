"""Configuração central da aplicação (Pydantic Settings / variáveis de ambiente)."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Lê todas as configurações do ambiente.

    A chave ``ANTHROPIC_API_KEY`` nunca é exposta em respostas HTTP nem logada:
    o modelo repr foi customizado em ``__repr__``.
    """

    model_config = SettingsConfigDict(
        env_file=("../.env", ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ---------------------------------------------------------------- app
    app_name: str = "DepGuard AI"
    app_version: str = "1.0.0"
    app_env: Literal["development", "production", "test"] = "development"
    log_level: str = "INFO"

    # ---------------------------------------------------------------- llm
    anthropic_api_key: str | None = Field(default=None, repr=False)
    anthropic_model: str = "claude-sonnet-4-5"
    anthropic_base_url: str | None = None
    llm_max_tokens: int = 8000
    llm_batch_size: int = 12
    llm_batch_concurrency: int = 2

    # ---------------------------------------------------------------- github
    github_token: str | None = Field(default=None, repr=False)

    # ---------------------------------------------------------------- api
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    rate_limit_per_minute: int = 10
    max_upload_bytes: int = 1_048_576

    # ---------------------------------------------------------------- rede
    http_timeout_seconds: float = 20.0
    http_max_retries: int = 3
    registry_cache_ttl_seconds: int = 3600
    registry_concurrency: int = 8
    osv_concurrency: int = 4
    cache_enabled: bool = True

    @field_validator("anthropic_api_key", "github_token", "anthropic_base_url", mode="before")
    @classmethod
    def _blank_to_none(cls, value: object) -> object:
        """Trata ``VAR=""`` como ``None`` (comum em arquivos .env)."""
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @property
    def cors_origin_list(self) -> list[str]:
        """Lista de origens CORS.Normaliza ``*`` e remove entradas vazias."""
        raw = (self.cors_origins or "").strip()
        if not raw or raw == "*":
            return ["*"]
        return [origin.strip() for origin in raw.split(",") if origin.strip()]

    @property
    def llm_enabled(self) -> bool:
        """A IA só é usada quando existe ``ANTHROPIC_API_KEY``."""
        return bool(self.anthropic_api_key)

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    def __repr__(self) -> str:  # pragma: no cover - cosmético
        safe = super().__repr__()
        return safe.replace(str(self.anthropic_api_key), "***")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Instância única de ``Settings`` (cacheada por processo)."""
    return Settings()
