"""Ponto de entrada da API DepGuard AI (FastAPI)."""

from __future__ import annotations

import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

from app.core.config import get_settings
from app.core.http_client import HttpClient
from app.core.logging_config import get_logger, setup_logging
from app.core.security import RateLimiter as InMemoryRateLimiter
from app.routers import analyze, health

settings = get_settings()
setup_logging(settings.log_level)
logger = get_logger("main")

DESCRIPTION = """
Ferramenta de **Análise Inteligente de Dependências** para projetos Node.js.

O DepGuard lê o `package.json` de um repositório público do GitHub (ou recebe o
arquivo por upload), consulta **dados reais** no registro npm e na base de
vulnerabilidades OSV.dev, aplica regras determinísticas e — quando há
`ANTHROPIC_API_KEY` — pede a um modelo Claude que classifique o risco de cada
dependência, explique o problema em linguagem simples e sugira uma ação concreta.

Cada achado informa sua **origem**: `osv`, `npm_registry`, `regra_local` ou
`analise_ia`.
""".strip()

TAGS_METADATA: list[dict[str, Any]] = [
    {"name": "análise", "description": "Análise de dependências Node.js."},
    {"name": "sistema", "description": "Health check e informações do serviço."},
]


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Inicializa e finaliza os recursos compartilhados (HTTP client e caches)."""
    app.state.http_client = HttpClient(settings)
    # Um limitador já injetado (testes, deployments com Redis, etc.) tem
    # precedência: sobrescrever aqui ignoraria a configuração de quem montou o app.
    if getattr(app.state, "rate_limiter", None) is None:
        app.state.rate_limiter = InMemoryRateLimiter(settings.rate_limit_per_minute)

    logger.info(
        "Iniciando %s v%s | env=%s | IA=%s | GITHUB_TOKEN=%s | rate_limit=%s/min",
        settings.app_name,
        settings.app_version,
        settings.app_env,
        "habilitada" if settings.llm_enabled else "desabilitada (sem ANTHROPIC_API_KEY)",
        "configurado" if settings.github_token else "não configurado",
        settings.rate_limit_per_minute,
    )
    if not settings.llm_enabled:
        logger.warning(
            "ANTHROPIC_API_KEY não definida: a análise usará apenas regras determinísticas."
        )

    try:
        yield
    finally:
        llm = getattr(app.state, "llm_analyzer", None)
        if llm is not None:
            await llm.aclose()
        http: HttpClient | None = getattr(app.state, "http_client", None)
        if http is not None:
            await http.aclose()
        logger.info("DepGuard AI encerrado.")


def create_app() -> FastAPI:
    """Factory da aplicação (facilita testes com configurações diferentes)."""
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description=DESCRIPTION,
        openapi_tags=TAGS_METADATA,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    # ---------------------------------------------------------------- CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials="*" not in settings.cors_origin_list,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
        expose_headers=["Retry-After", "X-Request-Duration"],
        max_age=600,
    )

    # ------------------------------------------------------- rate limiting
    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=[f"{settings.rate_limit_per_minute}/minute"],
        enabled=True,
        headers_enabled=True,
    )
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)

    # -------------------------------------------------------------rotas
    app.include_router(health.router, prefix="/api")
    app.include_router(analyze.router, prefix="/api")

    # ---------------------------------------------------- error handlers
    @app.middleware("http")
    async def add_timing_header(request: Request, call_next: Any) -> Any:
        """Adiciona ``X-Request-Duration`` e registra o acesso."""
        started = time.perf_counter()
        response = await call_next(request)
        duration_ms = (time.perf_counter() - started) * 1000
        response.headers["X-Request-Duration"] = f"{duration_ms:.0f}ms"
        if request.url.path.startswith("/api"):
            logger.info(
                "%s %s -> %s em %.0fms",
                request.method,
                request.url.path,
                response.status_code,
                duration_ms,
            )
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_handler(_request: Request, exc: RequestValidationError) -> JSONResponse:
        """Erros de validação em português e sem stack trace."""
        problems: list[str] = []
        for error in exc.errors():
            location = ".".join(str(part) for part in error["loc"] if part != "body") or "corpo"
            message = error["msg"]
            if message.startswith("Value error, "):
                message = message[len("Value error, ") :]
            problems.append(f"{location}: {message}")
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"detail": "Dados inválidos: " + " | ".join(problems[:5])},
        )

    @app.exception_handler(500)
    async def internal_handler(_request: Request, _exc: Exception) -> JSONResponse:  # pragma: no cover
        """Nunca devolve stack trace ao cliente."""
        logger.exception("Erro interno não tratado.")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "Erro interno. Tente novamente em instantes."},
        )

    @app.get("/", include_in_schema=False)
    async def root() -> dict[str, str]:
        """Redireciona a raiz para a documentação."""
        return {
            "name": settings.app_name,
            "version": settings.app_version,
            "docs": "/docs",
            "health": "/api/health",
        }

    return app


app = create_app()
