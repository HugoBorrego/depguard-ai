"""Schemas de entrada das requisições (validação estrita)."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.security import InvalidGitHubUrlError, parse_github_url


class AnalyzeGitHubRequest(BaseModel):
    """Corpo de ``POST /api/analyze/github``."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    url: str = Field(
        min_length=10,
        max_length=300,
        description="URL pública de um repositório GitHub, ex.: https://github.com/user/repo",
    )

    @field_validator("url")
    @classmethod
    def _validate_github_url(cls, value: str) -> str:
        """Valida a URL já no modelo: erro 422 claro se não for github.com."""
        try:
            ref = parse_github_url(value)
        except InvalidGitHubUrlError as exc:
            raise ValueError(str(exc)) from exc
        return ref.url
