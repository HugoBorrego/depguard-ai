"""Dependências compartilhadas da aplicação (injeção de dependências)."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Request

from app.core.config import Settings, get_settings
from app.core.security import RateLimiter, client_identifier
from app.services.analyzer import DependencyAnalyzer
from app.services.github import GitHubClient
from app.services.llm_analyzer import LLMAnalyzer
from app.services.npm_registry import NpmRegistryClient
from app.services.osv import OsvClient


def get_rate_limiter(request: Request) -> RateLimiter:
    """Instância compartilhada do limitador, criada no startup."""
    limiter: RateLimiter | None = getattr(request.app.state, "rate_limiter", None)
    if limiter is None:  # pragma: no cover - defensivo
        limiter = RateLimiter(get_settings().rate_limit_per_minute)
        request.app.state.rate_limiter = limiter
    return limiter


def enforce_rate_limit(request: Request) -> None:
    """Dependência FastAPI que aplica o rate limit por IP.

    Raises:
        HTTPException: 429 quando o IP excedeu o limite na janela de 1 minuto.
    """
    from fastapi import HTTPException, status

    from app.core.logging_config import get_logger

    limiter: RateLimiter = request.app.state.rate_limiter
    key = client_identifier(request)
    allowed, retry_after = limiter.check(key)
    if not allowed:
        get_logger("ratelimit").warning("Rate limit excedido para %s", key)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"Limite de requisições excedido ({limiter.limit}/minuto). "
                f"Tente novamente em {retry_after}s."
            ),
            headers={"Retry-After": str(retry_after)},
        )


SettingsDep = Annotated[Settings, Depends(get_settings)]
RateLimitDep = Depends(enforce_rate_limit)


def get_analyzer(request: Request, settings: SettingsDep) -> DependencyAnalyzer:
    """Cria um ``DependencyAnalyzer`` reutilizando os clients do app state.

    Reusar as instâncias é essencial: é nelas que mora o cache TTL do registry,
    que precisa sobreviver entre requisições.
    """
    return DependencyAnalyzer(
        settings,
        registry=get_registry_client(request, settings),
        osv=get_osv_client(request, settings),
        llm=get_llm_analyzer(request, settings),
    )


def get_github_client(request: Request, settings: SettingsDep) -> GitHubClient:
    """Reusa o client HTTP global (importante para o pool de conexões)."""
    http = getattr(request.app.state, "http_client", None)
    return GitHubClient(http=http, settings=settings)


def get_registry_client(request: Request, settings: SettingsDep) -> NpmRegistryClient:
    """Client do registry npm (com cache próprio, compartilhado entre requisições)."""
    existing: NpmRegistryClient | None = getattr(request.app.state, "registry_client", None)
    if existing is None:
        existing = NpmRegistryClient(
            http=getattr(request.app.state, "http_client", None), settings=settings
        )
        request.app.state.registry_client = existing
    return existing


def get_osv_client(request: Request, settings: SettingsDep) -> OsvClient:
    """Client do OSV."""
    existing: OsvClient | None = getattr(request.app.state, "osv_client", None)
    if existing is None:
        existing = OsvClient(
            http=getattr(request.app.state, "http_client", None), settings=settings
        )
        request.app.state.osv_client = existing
    return existing


def get_llm_analyzer(request: Request, settings: SettingsDep) -> LLMAnalyzer:
    """Analisador de IA (o SDK é criado de forma lazy na primeira chamada)."""
    existing: LLMAnalyzer | None = getattr(request.app.state, "llm_analyzer", None)
    if existing is None:
        existing = LLMAnalyzer(settings)
        request.app.state.llm_analyzer = existing
    return existing


AnalyzerDep = Annotated[DependencyAnalyzer, Depends(get_analyzer)]
GitHubDep = Annotated[GitHubClient, Depends(get_github_client)]
