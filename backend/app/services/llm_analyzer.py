"""Analisador por LLM (Anthropic Claude): lotes, JSON estrito e retry de correção.

O system prompt vive em ``app/prompts/analyze.md`` e é carregado em runtime
para poder ser editado sem mexer no código.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from collections.abc import Iterable, Sequence
from functools import lru_cache
from pathlib import Path
from typing import Any, Final

from pydantic import ValidationError

from app.core.config import Settings, get_settings
from app.core.logging_config import get_logger
from app.schemas.enums import SEVERITY_RANK
from app.schemas.llm import LLMAnalysisResult, LLMDependencyItem, LLMFinding

logger = get_logger("llm")

PROMPT_DIR: Final[Path] = Path(__file__).resolve().parent.parent / "prompts"
SYSTEM_PROMPT_FILE: Final[Path] = PROMPT_DIR / "analyze.md"

#: Máximo de tentativas por lote (1 original + 2 correções).
MAX_ATTEMPTS: Final[int] = 3

#: Temperatura baixa: classificação de risco deve ser determinística.
TEMPERATURE: Final[float] = 0.0

_JSON_BLOCK_RE: Final[re.Pattern[str]] = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL)


class LLMNotConfiguredError(RuntimeError):
    """``ANTHROPIC_API_KEY`` não configurada."""


class LLMResponseError(RuntimeError):
    """O modelo respondeu algo que não pudemos validar como JSON estrito."""


@lru_cache(maxsize=1)
def load_system_prompt() -> str:
    """Lê ``app/prompts/analyze.md`` (cacheado por processo)."""
    try:
        return SYSTEM_PROMPT_FILE.read_text(encoding="utf-8").strip()
    except OSError as exc:  # pragma: no cover - falha de empacotamento
        raise RuntimeError(f"Não foi possível ler o system prompt em {SYSTEM_PROMPT_FILE}: {exc}") from exc


def _extract_json(raw: str) -> str:
    """Remove cercas de markdown e o texto em volta, sobrando só o JSON."""
    text = (raw or "").strip()
    if not text:
        raise LLMResponseError("O modelo devolveu uma resposta vazia.")

    match = _JSON_BLOCK_RE.search(text)
    if match:
        return match.group(1).strip()

    # Tolerância a uma única chave wrapper, ex.: {"resultado": {...}}
    starts = [index for index in (text.find("{"), text.find("[")) if index != -1]
    if starts:
        start = min(starts)
        end = max(text.rfind("}"), text.rfind("]"))
        if end > start:
            return text[start : end + 1]
    return text


def _build_user_prompt(
    items: Sequence[LLMDependencyItem],
    *,
    project_name: str,
    project_engine_node: str | None,
    attempt: int,
    validation_error: str | None = None,
) -> str:
    """Monta o prompt de usuário: os fatos + (na 2ª tentativa) o erro de validação."""
    payload = [item.model_dump(exclude_none=False) for item in items]

    header = [
        f"Projeto: {project_name}",
        f"engines.node do projeto: {project_engine_node or 'não declarado'}",
        f"Total de dependências neste lote: {len(items)}",
        "",
        "Dados coletados do registro npm e do OSV.dev (fontes: npm_registry, osv).",
        "As regras determinísticas já rodaram: os itens em `local_rule_flags` são fatos confirmados.",
        "",
        "DADOS (JSON):",
        json.dumps(payload, ensure_ascii=False, indent=2),
        "",
        f"Responda com um JSON no formato especificado, com EXATAMENTE {len(items)} entradas em `findings`,",
        "uma para cada pacote acima, na mesma ordem. Não omita nenhum e não invente nenhum.",
    ]

    if attempt > 1 and validation_error:
        header = [
            f"TENTATIVA {attempt}. Sua resposta anterior foi REJEITADA pelo validador.",
            "",
            "ERRO DE VALIDAÇÃO:",
            validation_error,
            "",
            "Corrija e devolva novamente SOMENTE o JSON válido, no mesmo formato,",
            f"com EXATAMENTE {len(items)} entradas em `findings`.",
            "",
            *header,
        ]

    return "\n".join(header)


class LLMAnalyzer:
    """Envia lotes de dependências ao Claude e devolve a classificação validada."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._client: Any | None = None
        self.batches_sent = 0
        self.failures = 0

    # ------------------------------------------------------------ client
    @property
    def enabled(self) -> bool:
        """``True`` se existe ``ANTHROPIC_API_KEY``."""
        return self.settings.llm_enabled

    @property
    def model(self) -> str:
        """Modelo configurado em ``ANTHROPIC_MODEL``."""
        return self.settings.anthropic_model

    def _get_client(self) -> Any:
        """Cria (lazy) o cliente ``anthropic.AsyncAnthropic``.

        A chave nunca é logada nem devolvida: fica apenas no cliente do SDK.
        """
        if self._client is not None:
            return self._client
        if not self.enabled:
            raise LLMNotConfiguredError(
                "ANTHROPIC_API_KEY não configurada. Defina a variável de ambiente para habilitar a análise por IA."
            )
        try:
            from anthropic import AsyncAnthropic
        except ImportError as exc:  # pragma: no cover - dependência obrigatória
            raise LLMNotConfiguredError("Pacote 'anthropic' não está instalado no ambiente.") from exc

        self._client = AsyncAnthropic(
            api_key=self.settings.anthropic_api_key,
            base_url=self.settings.anthropic_base_url,
            max_retries=0,
        )
        return self._client

    async def aclose(self) -> None:
        """Fecha o cliente do SDK, se existir."""
        if self._client is not None and hasattr(self._client, "close"):
            try:
                await self._client.close()
            except Exception as exc:
                logger.debug("Erro ao fechar cliente Anthropic: %s", exc)
            self._client = None

    # ------------------------------------------------------------ chamada
    async def _call_model(self, system_prompt: str, user_prompt: str) -> str:
        """Faz uma chamada ao Claude e devolve o texto bruto da resposta."""
        client = self._get_client()
        response = await client.messages.create(
            model=self.model,
            max_tokens=self.settings.llm_max_tokens,
            temperature=TEMPERATURE,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )

        parts: list[str] = []
        for block in getattr(response, "content", []) or []:
            text = getattr(block, "text", None)
            if isinstance(text, str):
                parts.append(text)
        return "\n".join(parts).strip()

    async def _analyze_batch(
        self,
        items: Sequence[LLMDependencyItem],
        *,
        project_name: str,
        project_engine_node: str | None,
    ) -> tuple[list[LLMFinding], str | None]:
        """Analisa um lote com até ``MAX_ATTEMPTS`` tentativas.

        Returns:
            ``(findings, erro)`` — o erro é ``None`` em caso de sucesso.
            Em falha, devolve ``([], motivo)`` para o chamador manter o resultado
            determinístico daquele pacote.
        """
        system_prompt = load_system_prompt()
        validation_error: str | None = None
        self.batches_sent += 1

        for attempt in range(1, MAX_ATTEMPTS + 1):
            user_prompt = _build_user_prompt(
                items,
                project_name=project_name,
                project_engine_node=project_engine_node,
                attempt=attempt,
                validation_error=validation_error,
            )
            try:
                raw = await self._call_model(system_prompt, user_prompt)
            except Exception as exc:
                self.failures += 1
                logger.warning(
                    "Lote de %s dependências falhou na tentativa %s/%s: %s: %s",
                    len(items), attempt, MAX_ATTEMPTS, type(exc).__name__, exc,
                )
                return [], f"erro de API na tentativa {attempt}: {type(exc).__name__}"

            try:
                payload = json.loads(_extract_json(raw))
            except (json.JSONDecodeError, LLMResponseError) as exc:
                validation_error = f"JSON inválido: {exc}"
                logger.warning("Resposta não-JSON do modelo (tentativa %s): %s", attempt, exc)
                continue

            try:
                result = LLMAnalysisResult.model_validate(payload)
            except ValidationError as exc:
                validation_error = _format_validation_error(exc)
                logger.warning("JSON do modelo não passou no schema (tentativa %s): %s", attempt, validation_error)
                continue

            findings = _align_findings(result.findings, items)
            if findings is None:
                validation_error = (
                    f"findings com {len(result.findings)} entradas para {len(items)} dependências. "
                    "É obrigatório devolver uma entrada por dependência, na mesma ordem."
                )
                continue

            return findings, None

        self.failures += 1
        return [], validation_error or "resposta inválida após todas as tentativas"

    # ------------------------------------------------------------ público
    async def analyze_dependencies(
        self,
        items: Sequence[LLMDependencyItem],
        *,
        project_name: str = "projeto",
        project_engine_node: str | None = None,
    ) -> dict[str, LLMFinding]:
        """Analisa todas as dependências, em lotes paralelos e controlados.

        Returns:
            Mapa ``nome_do_pacote -> LLMFinding``. Pacotes sem resultado (lote
            que falhou) simplesmente não aparecem no mapa, e o chamador mantém a
            classificação determinística deles.
        """
        if not self.enabled:
            # Verificado antes do caso vazio: o erro de configuração é um erro de
            # programmer error e precisa aparecer mesmo em chamadas degeneradas.
            raise LLMNotConfiguredError("ANTHROPIC_API_KEY não configurada.")
        if not items:
            return {}

        batch_size = max(1, self.settings.llm_batch_size)
        batches = [list(items[i : i + batch_size]) for i in range(0, len(items), batch_size)]
        concurrency = max(1, self.settings.llm_batch_concurrency)
        semaphore = asyncio.Semaphore(concurrency)

        async def run(batch: list[LLMDependencyItem]) -> tuple[list[LLMFinding], str | None]:
            async with semaphore:
                return await self._analyze_batch(
                    batch,
                    project_name=project_name,
                    project_engine_node=project_engine_node,
                )

        started = time.monotonic()
        outcomes = await asyncio.gather(*(run(batch) for batch in batches), return_exceptions=True)

        collected: dict[str, LLMFinding] = {}
        for outcome in outcomes:
            if isinstance(outcome, BaseException):
                self.failures += 1
                logger.warning("Lote do Claude lançou exceção: %s", type(outcome).__name__)
                continue
            findings, error = outcome
            if error:
                logger.warning("Lote mantido no modo determinístico: %s", error)
            for finding in findings:
                collected[finding.package] = finding

        logger.info(
            "Análise IA concluída: %s dependências em %s lote(s) em %.1fs (%s falha(s)).",
            len(collected), len(batches), time.monotonic() - started, self.failures,
        )
        return collected


# ==========================================================
# Helpers de validação
# ==========================================================


def _format_validation_error(exc: ValidationError) -> str:
    """Transforma o erro do Pydantic em uma instrução curta e acionável."""
    problems: list[str] = []
    for error in exc.errors()[:8]:
        location = ".".join(str(part) for part in error["loc"]) or "(raiz)"
        problems.append(f"- {location}: {error['msg']}")
    return "\n".join(problems)


def _align_findings(
    findings: Iterable[LLMFinding],
    items: Sequence[LLMDependencyItem],
) -> list[LLMFinding] | None:
    """Garante 1:1 entre entrada e saída, reordenando pelos pacotes recebidos.

    Devolve ``None`` (para forçar retry) se houver pacote faltando ou extra.
    """
    by_package: dict[str, LLMFinding] = {}
    for finding in findings:
        if finding.package in by_package:
            return None  # duplicata
        by_package[finding.package] = finding

    expected = {item.package for item in items}
    if set(by_package) != expected:
        return None

    ordered = [by_package[item.package] for item in items]
    for finding in ordered:
        for issue in finding.issues:
            # Regra do contrato: tudo que vem do modelo é 'analise_ia'.
            issue.source = "analise_ia"
    return ordered


def worst_severity(severities: Iterable[str]) -> str:
    """Devolve a severidade mais alta de uma coleção."""
    worst = "ok"
    for severity in severities:
        if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(worst, 0):
            worst = severity
    return worst
