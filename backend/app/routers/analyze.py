"""Endpoints de análise: upload de package.json e repositório GitHub."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from fastapi.responses import StreamingResponse

from app.core.logging_config import get_logger
from app.core.security import InvalidGitHubUrlError, validate_upload
from app.routers.dependencies import (
    AnalyzerDep,
    GitHubDep,
    RateLimitDep,
    enforce_rate_limit,
)
from app.schemas.enums import SourceFile
from app.schemas.report import AnalysisReport
from app.schemas.requests import AnalyzeGitHubRequest
from app.services.analyzer import STEP_DONE, AnalysisError, DependencyAnalyzer
from app.services.github import GitHubError, GitHubPackageNotFound
from app.services.package_parser import ParsedPackageJson, parse_package_json

logger = get_logger("router.analyze")

router = APIRouter(prefix="/analyze", tags=["análise"])

#: Limite de leitura do upload (o settings valida de novo o tamanho exato).
MAX_READ_BYTES = 2_000_000


@router.post(
    "/upload",
    response_model=AnalysisReport,
    status_code=status.HTTP_200_OK,
    summary="Analisa um package.json enviado por upload",
    responses={
        400: {"description": "package.json inválido, malformado ou sem dependências"},
        413: {"description": "Arquivo maior que o limite configurado"},
        415: {"description": "Arquivo que não é um package.json"},
        422: {"description": "Campos do formulário inválidos"},
        429: {"description": "Rate limit excedido"},
    },
    dependencies=[RateLimitDep],
)
async def analyze_upload(
    file: Annotated[UploadFile, File(description="Arquivo package.json (máx. 1 MB por padrão)")],
    analyzer: AnalyzerDep,
) -> AnalysisReport:
    """Analisa o ``package.json`` enviado na requisição.

    O arquivo é validado em três camadas: tamanho, nome/encoding e formato JSON
    com seções de dependência reconhecidas.
    """
    raw = await file.read(MAX_READ_BYTES)

    try:
        upload = validate_upload(file.filename or "package.json", raw)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc

    if not upload.parsed().get("name"):
        logger.info("Upload sem campo 'name'; usando o nome do arquivo como título.")

    try:
        parsed = parse_package_json(
            upload.content,
            source=SourceFile(
                path=upload.filename,
                url=f"upload://{upload.filename}",
                is_monorepo_root=True,
                size_bytes=upload.size_bytes,
            ),
            fallback_name=_name_from_filename(upload.filename),
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Não foi possível ler o package.json: {exc}",
        ) from exc

    logger.info("Analisando upload '%s' (%s dependências).", upload.filename, len(parsed.dependencies))
    return await _run_analysis(analyzer, [parsed], source="upload", source_url=None)


@router.post(
    "/github",
    response_model=AnalysisReport,
    status_code=status.HTTP_200_OK,
    summary="Analisa as dependências de um repositório público do GitHub",
    responses={
        404: {"description": "Repositório não encontrado ou sem package.json"},
        422: {"description": "Corpo inválido, ou URL fora do github.com"},
        429: {"description": "Rate limit do DepGuard ou do GitHub"},
        503: {"description": "GitHub ou registry indisponíveis"},
    },
    dependencies=[RateLimitDep],
)
async def analyze_github(
    body: AnalyzeGitHubRequest,
    github: GitHubDep,
    analyzer: AnalyzerDep,
) -> AnalysisReport:
    """Busca o(s) ``package.json`` do repositório e analisa tudo.

    A URL já é validada (anti-SSRF) na camada de schema, antes de qualquer
    chamada de rede.
    """
    try:
        ref, branch, manifests = await github.find_manifests(body.url)
    except GitHubPackageNotFound as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc
    except GitHubError as exc:
        status_code = exc.status_code if exc.status_code and exc.status_code >= 400 else 503
        if exc.status_code == 404:
            status_code = 404
        raise HTTPException(status_code=status_code, detail=str(exc)) from exc

    parsed_manifests: list[ParsedPackageJson] = []
    errors: list[str] = []

    for manifest in manifests:
        try:
            text = await github.get_raw_text(ref, manifest.path, branch)
        except GitHubError as exc:  # pragma: no cover - defensivo
            errors.append(f"{manifest.path}: {exc}")
            continue
        if not text:
            errors.append(f"{manifest.path}: arquivo não encontrado na branch '{branch}'.")
            continue
        try:
            parsed_manifests.append(
                parse_package_json(
                    text,
                    source=manifest,
                    fallback_name=ref.repo,
                )
            )
        except ValueError as exc:
            errors.append(f"{manifest.path}: {exc}")

    if not parsed_manifests:
        detail = "Nenhum package.json analisável foi encontrado no repositório."
        if errors:
            detail += " Detalhes: " + " | ".join(errors[:3])
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail)

    if errors:
        logger.info("Alguns manifests do repositório %s foram ignorados: %s", ref.full_name, errors)

    logger.info(
        "Analisando %s (%s): %s manifest(s), %s dependências únicas.",
        ref.full_name,
        branch,
        len(parsed_manifests),
        sum(len(p.dependencies) for p in parsed_manifests),
    )
    return await _run_analysis(
        analyzer, parsed_manifests, source="github", source_url=ref.url
    )


@router.get(
    "/github/stream",
    summary="Analisa um repositório com progresso por etapa (Server-Sent Events)",
    response_class=StreamingResponse,
    dependencies=[RateLimitDep],
)
async def analyze_github_stream(
    url: str,
    github: GitHubDep,
    analyzer: AnalyzerDep,
) -> StreamingResponse:
    """Mesma análise de ``/github``, emitindo o progresso de cada etapa em SSE.

    Eventos emitidos:
      - ``progress``: ``{"step": "...", "progress": 0.35}``
      - ``report``: o ``AnalysisReport`` completo
      - ``error``: ``{"detail": "mensagem amigável"}``
    """
    from app.schemas.requests import AnalyzeGitHubRequest as _Request

    try:
        validated = _Request(url=url)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    async def event_stream() -> AsyncIterator[str]:
        try:
            ref, branch, manifests = await github.find_manifests(validated.url)
            parsed: list[ParsedPackageJson] = []
            for manifest in manifests:
                text = await github.get_raw_text(ref, manifest.path, branch)
                if text:
                    try:
                        parsed.append(parse_package_json(text, source=manifest, fallback_name=ref.repo))
                    except ValueError:
                        continue
            if not parsed:
                yield _sse("error", {"detail": "Nenhum package.json analisável encontrado."})
                return

            report: AnalysisReport | None = None
            async for step, progress, result in analyzer.stream_analysis(
                parsed, source="github", source_url=ref.url
            ):
                if step == STEP_DONE and result is not None:
                    report = result
                else:
                    yield _sse("progress", {"step": step, "progress": progress})

            if report is not None:
                yield _sse("report", json.loads(report.model_dump_json()))
        except (GitHubError, AnalysisError) as exc:
            yield _sse("error", {"detail": str(exc)})
        except Exception as exc:
            logger.exception("Falha no streaming da análise: %s", exc)
            yield _sse("error", {"detail": f"Erro inesperado: {type(exc).__name__}"})

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


# ==========================================================
# Helpers
# ==========================================================


async def _run_analysis(
    analyzer: DependencyAnalyzer,
    manifests: list[ParsedPackageJson],
    *,
    source: str,
    source_url: str | None,
) -> AnalysisReport:
    """Executa a análise traduzindo erros internos para HTTP."""
    try:
        return await analyzer.analyze_manifests(manifests, source=source, source_url=source_url)
    except AnalysisError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Falha inesperada na análise: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro interno ao processar a análise. Tente novamente em instantes.",
        ) from exc


def _sse(event: str, data: Any) -> str:
    """Formata um evento Server-Sent Events."""
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


def _name_from_filename(filename: str) -> str:
    """Nome de projeto razoável a partir do nome do arquivo enviado."""
    base = (filename or "package.json").replace("\\", "/").split("/")[-1]
    stem = base[: -len(".json")] if base.endswith(".json") else base
    return stem if stem and stem != "package" else "projeto-enviado"


__all__ = ["Depends", "InvalidGitHubUrlError", "enforce_rate_limit", "router"]
