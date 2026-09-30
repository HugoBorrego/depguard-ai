"""Endpoint de health check."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Request, status

from app.core.config import get_settings
from app.schemas.report import HealthResponse

router = APIRouter(tags=["sistema"])


@router.get(
    "/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Verifica se a API está no ar",
)
async def health(request: Request) -> HealthResponse:
    """Retorna o estado do serviço e dos recursos opcionais configurados.

    Nunca expõe segredos: apenas booleanos (``aiEnabled``,
    ``githubTokenConfigured``).
    """
    settings = get_settings()
    registry = getattr(request.app.state, "registry_client", None)
    cache_entries = registry.cache_size if registry is not None else 0

    return HealthResponse(
        status="ok",
        version=settings.app_version,
        environment=settings.app_env,
        aiEnabled=settings.llm_enabled,
        githubTokenConfigured=bool(settings.github_token),
        cacheEntries=cache_entries,
        serverTime=datetime.now(UTC).isoformat(),
    )
