"""Configuração do pytest e fixtures compartilhadas."""

from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

# Garante que o pacote 'app' seja importável ao rodar pytest a partir de backend/
BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))


@pytest.fixture(scope="session")
def anyio_backend() -> str:
    """Backend do anyio usado nos testes async."""
    return "asyncio"


@pytest.fixture
def settings() -> Iterator[Any]:
    """``Settings`` de teste: sem chave de IA, sem token, tudo local."""
    from app.core.config import Settings

    cfg = Settings(
        anthropic_api_key=None,
        github_token=None,
        app_env="test",
        rate_limit_per_minute=1000,
        max_upload_bytes=1_048_576,
        registry_cache_ttl_seconds=60,
        cache_enabled=True,
        registry_concurrency=4,
        osv_concurrency=2,
        cors_origins="http://localhost:5173",
    )
    yield cfg


@pytest.fixture
def example_manifest() -> str:
    """Conteúdo do package.json de exemplo (com problemas propositais).

    Lê o arquivo real do repositório de propósito: assim o teste garante que o
    exemplo que a documentação manda usar continua sendo analisável.
    """
    path = BACKEND_ROOT.parent / "examples" / "problematic-project" / "package.json"
    if not path.exists():  # pragma: no cover - só ocorre em checkout incompleto
        pytest.fail(f"exemplo ausente: {path}")
    return path.read_text(encoding="utf-8")
