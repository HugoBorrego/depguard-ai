"""Orquestrador da análise: coleta de dados → regras → LLM → consolidação."""

from __future__ import annotations

import time
from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Final

from app.core.config import Settings, get_settings
from app.core.logging_config import get_logger
from app.core.semver import is_prerelease, major_distance, normalize_version, parse_range
from app.schemas.enums import SEVERITY_RANK, SourceFile
from app.schemas.llm import LLMDependencyItem, LLMVulnerabilityItem
from app.schemas.report import (
    AnalysisMeta,
    AnalysisReport,
    DependencyFinding,
    Issue,
    ProjectInfo,
    Summary,
)
from app.services import rules as rules_module
from app.services.llm_analyzer import LLMAnalyzer, LLMNotConfiguredError
from app.services.npm_registry import NpmRegistryClient, RegistryResults
from app.services.osv import OsvClient, parse_vulnerability
from app.services.package_parser import (
    PackageJsonParseError,
    ParsedDependency,
    ParsedPackageJson,
    parse_package_json,
)

logger = get_logger("analyzer")

#: Etapas reportadas ao frontend durante o processamento.
type ProgressStep = str

STEP_READING: Final[ProgressStep] = "lendo_package_json"
STEP_REGISTRY: Final[ProgressStep] = "consultando_npm"
STEP_OSV: Final[ProgressStep] = "consultando_vulnerabilidades"
STEP_RULES: Final[ProgressStep] = "aplicando_regras"
STEP_AI: Final[ProgressStep] = "analisando_com_ia"
STEP_DONE: Final[ProgressStep] = "finalizando"

PROGRESS_STEPS: Final[list[ProgressStep]] = [
    STEP_READING,
    STEP_REGISTRY,
    STEP_OSV,
    STEP_RULES,
    STEP_AI,
    STEP_DONE,
]


class AnalysisError(RuntimeError):
    """Falha durante a análise, já com mensagem amigável para o usuário."""

    def __init__(self, message: str, *, status_code: int = 400, hint: str | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.hint = hint


@dataclass(slots=True)
class CollectedDependency:
    """Estado intermediário de uma dependência entre coleta e relatório."""

    parsed: ParsedDependency
    context: rules_module.DependencyContext
    rule_result: rules_module.RuleResult
    findings: DependencyFinding
    llm_item: LLMDependencyItem
    ai_applied: bool = False


@dataclass(slots=True)
class _Runtime:
    """Dependências compartilhadas entre os módulos do pipeline."""

    settings: Settings
    registry: NpmRegistryClient
    osv: OsvClient
    llm: LLMAnalyzer
    warnings: list[str] = field(default_factory=list)


class DependencyAnalyzer:
    """Pipeline completo de análise de dependências Node.js."""

    def __init__(
        self,
        settings: Settings | None = None,
        *,
        registry: NpmRegistryClient | None = None,
        osv: OsvClient | None = None,
        llm: LLMAnalyzer | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.registry = registry or NpmRegistryClient(settings=self.settings)
        self.osv = osv or OsvClient(settings=self.settings)
        self.llm = llm or LLMAnalyzer(self.settings)

    # ------------------------------------------------------------ pipeline
    async def analyze_manifests(
        self,
        parsed_manifests: Sequence[ParsedPackageJson],
        *,
        source: str,
        source_url: str | None,
    ) -> AnalysisReport:
        """Executa a análise completa e devolve o relatório."""
        report: AnalysisReport | None = None
        async for _step, _progress, result in self.stream_analysis(
            parsed_manifests, source=source, source_url=source_url
        ):
            if result is not None:
                report = result
        if report is None:  # pragma: no cover - o pipeline sempre emite o relatório
            raise AnalysisError("A análise não produziu relatório.", status_code=500)
        return report

    async def stream_analysis(
        self,
        parsed_manifests: Sequence[ParsedPackageJson],
        *,
        source: str,
        source_url: str | None,
    ) -> AsyncIterator[tuple[str, float, AnalysisReport | None]]:
        """Executa a análise emitindo progresso real por etapa.

        Emite ``(etapa, progresso 0.0..1.0, relatório)``. O relatório só é
        preenchido na última emissão, quando ``etapa == STEP_DONE``.
        """
        started = time.monotonic()
        runtime = _Runtime(
            settings=self.settings,
            registry=self.registry,
            osv=self.osv,
            llm=self.llm,
        )

        if not parsed_manifests:
            raise AnalysisError("Nenhum manifest válido para analisar.", status_code=400)
        primary = parsed_manifests[0]

        # ---------- Etapa 1: consolidando o manifest ----------
        yield STEP_READING, 0.05, None

        merged: dict[tuple[str, str], ParsedDependency] = {}
        for parsed in parsed_manifests:
            for dependency in parsed.dependencies:
                merged.setdefault((dependency.name, dependency.section), dependency)

        if not merged:
            raise AnalysisError(
                "Nenhuma dependência analisável foi encontrada no package.json.", status_code=400
            )

        known_packages = {dependency.name for dependency in merged.values()}

        # ---------- Etapa 2: dados reais do registro npm ----------
        registry_payloads = await self._collect_registry(runtime, list(merged.values()))
        yield STEP_REGISTRY, 0.35, None

        # ---------- Etapa 3: versões resolvidas + OSV ----------
        collected = self._build_contexts(merged, registry_payloads, primary)
        await self._collect_vulnerabilities(runtime, collected)
        yield STEP_OSV, 0.6, None

        # ---------- Etapa 4: regras determinísticas ----------
        for item in collected.values():
            item.rule_result = rules_module.apply_rules(
                item.context, known_packages=known_packages
            )
            item.findings = self._build_finding(item)
            item.llm_item.local_rule_flags = list(item.rule_result.local_flags)
            item.llm_item.similar_popular_packages = list(item.rule_result.suspicious_matches)
        yield STEP_RULES, 0.7, None

        # ---------- Etapa 5: LLM (se habilitado) ----------
        ai_batches = 0
        if self.llm.enabled:
            ai_batches = await self._apply_llm(runtime, collected, primary)
        else:
            runtime.warnings.append(
                "Análise por IA desativada: ANTHROPIC_API_KEY não configurada. "
                "O relatório usa apenas regras determinísticas."
            )
        yield STEP_AI, 0.9, None

        # ---------- Etapa 6: consolidação ----------
        findings = [item.findings for item in collected.values()]
        report = AnalysisReport(
            project=ProjectInfo(
                name=primary.name,
                version=primary.version,
                source=source,
                sourceUrl=source_url,
                manifests=[p.source.path for p in parsed_manifests if p.source is not None],
                totalDependencies=len(collected),
                runtimeDependencies=sum(
                    1 for item in collected.values() if item.parsed.section != "devDependencies"
                ),
                devDependencies=sum(
                    1 for item in collected.values() if item.parsed.section == "devDependencies"
                ),
                engineNode=primary.engine_node,
                license=primary.license,
            ),
            summary=_build_summary(findings),
            findings=findings,
            meta=AnalysisMeta(
                analyzedAt=datetime.now(UTC).isoformat(),
                durationMs=int((time.monotonic() - started) * 1000),
                aiEnabled=self.llm.enabled,
                aiModel=self.llm.model if self.llm.enabled else None,
                aiBatches=ai_batches,
                aiFailures=self.llm.failures,
                npmEtagCache=self.registry.cache_size,
                warnings=runtime.warnings,
            ),
        )
        yield STEP_DONE, 1.0, report

    # ------------------------------------------------------------ etapas
    async def _collect_registry(
        self,
        runtime: _Runtime,
        dependencies: list[ParsedDependency],
    ) -> RegistryResults:
        """Busca metadados do registry para todas as dependências em paralelo."""
        names = [dependency.name for dependency in dependencies]
        try:
            results = await runtime.registry.fetch_many(names)
        except Exception as exc:
            logger.error("Falha geral ao consultar o registry npm: %s", exc)
            runtime.warnings.append(
                "Não foi possível consultar o registro npm. A análise usou apenas regras locais."
            )
            return RegistryResults()

        if results.unavailable:
            # Falha transitória: avisar é obrigatório. Sem isso, tratar esses pacotes
            # como "inexistentes" geraria um falso positivo crítico contra o projeto.
            preview = ", ".join(sorted(results.unavailable)[:5])
            more = len(results.unavailable) - 5
            runtime.warnings.append(
                f"Registro npm indisponível para {len(results.unavailable)} pacote(s) "
                f"({preview}{', …' if more > 0 else ''}). "
                "Esses pacotes foram pulados — repita a análise para um resultado completo."
            )
        return results

    def _build_contexts(
        self,
        dependencies: dict[tuple[str, str], ParsedDependency],
        registry_payloads: RegistryResults,
        primary: ParsedPackageJson,
    ) -> dict[str, CollectedDependency]:
        """Transforma payloads do registry em contextos prontos para as regras."""
        collected: dict[str, CollectedDependency] = {}
        unavailable = registry_payloads.unavailable

        for (name, section), parsed in dependencies.items():
            metadata = registry_payloads.get(name)
            # `None` = não foi possível verificar (indisponibilidade).
            # `False` = o registry respondeu 404, ou seja, o pacote não existe.
            # A diferença importa: a primeira gera aviso, a segunda um achado crítico.
            found: bool | None = None if name in unavailable else (metadata is not None)
            declared = parsed.requested_version
            range_info = parse_range(declared)
            resolved = normalize_version(range_info.base) if range_info.base else declared

            # Tudo que vem do registry só é calculado quando temos o documento.
            # Quando `found` é False/None, os padrões abaixo mantêm a dependência
            # sem dados externos — as regras já sabem não concluir nada nesse caso.
            if metadata is not None:
                latest = self.registry.latest_version(metadata)
                max_sat = self.registry.max_satisfying(metadata, declared)

                # Versão efetivamente resolvida: a mais alta que satisfaz a faixa
                # declarada, senão a base, senão a latest do pacote.
                if max_sat:
                    resolved = max_sat
                elif range_info.base:
                    resolved = normalize_version(range_info.base)
                elif latest:
                    resolved = latest

                # `declared_version_exists` exige uma versão concreta: perguntar ao
                # registry se "^4.17.15" existe sempre responderia "não", porque a
                # chave publicada é "4.17.15". Para faixas basta haver versão que
                # a satisfaça, e URL não tem versão para conferir.
                if range_info.is_url:
                    exists: bool | None = None
                elif range_info.is_special_tag:
                    exists = latest is not None
                elif range_info.is_comparator:
                    # Só é válida se existe versão publicada que a satisfaça.
                    exists = bool(max_sat) or (
                        range_info.base is not None
                        and self.registry.version_exists(metadata, range_info.base) is True
                    )
                else:
                    exists = self.registry.version_exists(metadata, declared)

                deprecated_at_declared = self.registry.deprecated_message(
                    metadata, normalize_version(resolved)
                )
                if deprecated_at_declared is None:
                    deprecated_at_declared = self.registry.deprecated_message(metadata)

                context = rules_module.DependencyContext(
                    name=name,
                    declared_version=declared,
                    section=section,
                    project_engine_node=primary.engine_node,
                    found_in_registry=found,
                    latest_version=latest,
                    declared_version_exists=exists,
                    declared_version_published_at=self.registry.published_at(
                        metadata, normalize_version(resolved)
                    ),
                    latest_published_at=self.registry.latest_published_at(metadata),
                    deprecated_message=deprecated_at_declared,
                    maintainer_count=self.registry.maintainer_count(metadata),
                    maintainers=self.registry.maintainers(metadata),
                    engines=self.registry.engines(metadata),
                    license=self.registry.license_of(metadata),
                    description=self.registry.description(metadata),
                    repository_url=self.registry.repository_url(metadata),
                    resolved_version=resolved,
                    max_satisfying=max_sat,
                    min_version=self.registry.min_version(metadata, declared),
                )
            else:
                context = rules_module.DependencyContext(
                    name=name,
                    declared_version=declared,
                    section=section,
                    project_engine_node=primary.engine_node,
                    found_in_registry=found,
                    resolved_version=resolved,
                )

            llm_item = self._build_llm_item(context, range_info)
            collected[f"{name}::{section}"] = CollectedDependency(
                parsed=parsed,
                context=context,
                rule_result=rules_module.RuleResult(),
                findings=self._empty_finding(parsed, context),
                llm_item=llm_item,
            )
        return collected

    async def _collect_vulnerabilities(
        self,
        runtime: _Runtime,
        collected: dict[str, CollectedDependency],
    ) -> None:
        """Consulta o OSV em um único lote para as versões resolvidas."""
        targets: list[tuple[str, str]] = []
        for item in collected.values():
            context = item.context
            if context.found_in_registry is False:
                continue
            version = normalize_version(context.resolved)
            if not version or not version[0].isdigit():
                continue
            targets.append((context.name, version))

        if not targets:
            return

        try:
            raw_by_target = await runtime.osv.query_many(targets)
        except Exception as exc:
            logger.error("Falha ao consultar o OSV: %s", exc)
            runtime.warnings.append(
                "Não foi possível consultar a base de vulnerabilidades (OSV.dev). "
                "Vulnerabilidades conhecidas não foram consideradas nesta análise."
            )
            return

        # `query_batch` não propaga a falha por pacote (para não perder as
        # consultas que deram certo), então a degradação é comunicada aqui.
        if raw_by_target.degraded:
            runtime.warnings.append(
                f"O OSV.dev não respondeu para parte das {len(targets)} dependências consultadas. "
                "Elas não foram verificadas contra vulnerabilidades conhecidas — repita a análise "
                "para um resultado completo."
            )

        for key, item in collected.items():
            context = item.context
            target_key = f"{context.name}@{normalize_version(context.resolved)}"
            raw_vulns = raw_by_target.get(target_key, [])
            if not raw_vulns:
                continue
            parsed_vulns = [parse_vulnerability(raw) for raw in raw_vulns]
            # `to_rule_dict` é a fronteira explícita entre o modelo do OSV e o
            # contrato de dicionados consumido pelas regras locais.
            context.vulnerabilities = [vuln.to_rule_dict() for vuln in parsed_vulns]
            item.llm_item.vulnerabilities = [
                LLMVulnerabilityItem(
                    id=vuln.id,
                    summary=vuln.summary,
                    aliases=vuln.aliases[:5],
                    severity_score=vuln.severity_score,
                    database_specific_severity=vuln.severity_label,
                    affected_ranges=vuln.affected_ranges,
                    fixed_versions=vuln.fixed_versions,
                    published_at=vuln.published_at,
                    references=vuln.references[:3],
                )
                for vuln in parsed_vulns[:8]
            ]
            logger.debug("%s: %s vulnerabilidade(s) encontradas no OSV.", key, len(parsed_vulns))

    async def _apply_llm(
        self,
        runtime: _Runtime,
        collected: dict[str, CollectedDependency],
        primary: ParsedPackageJson,
    ) -> int:
        """Envia os lotes ao LLM e funde a resposta com as regras determinísticas."""
        items = [item.llm_item for item in collected.values()]
        try:
            llm_findings = await runtime.llm.analyze_dependencies(
                items,
                project_name=primary.name,
                project_engine_node=primary.engine_node,
            )
        except LLMNotConfiguredError:
            runtime.warnings.append("Análise por IA desativada (ANTHROPIC_API_KEY ausente).")
            return 0
        except Exception as exc:
            logger.error("Falha na análise por IA: %s", exc)
            runtime.warnings.append(
                "A análise por IA falhou; o relatório usa apenas as regras determinísticas."
            )
            return 0

        for item in collected.values():
            llm_finding = llm_findings.get(item.context.name)
            if llm_finding is None:
                continue
            self._merge_llm_finding(item, llm_finding)

        if runtime.llm.failures:
            runtime.warnings.append(
                f"{runtime.llm.failures} lote(s) não puderam ser analisados pela IA; "
                "esses pacotes mantiveram a classificação das regras locais."
            )
        return runtime.llm.batches_sent

    # ---------- construção do relatório ----------
    def _build_llm_item(
        self,
        context: rules_module.DependencyContext,
        range_info: Any,
    ) -> LLMDependencyItem:
        """Serializa os fatos de uma dependência para envio ao LLM."""
        resolved = normalize_version(context.resolved) or context.resolved
        latest = context.latest_version
        majors_behind: int | None = None
        if latest and resolved and resolved[0].isdigit() and latest[0].isdigit():
            majors_behind = major_distance(resolved, latest)

        weeks = rules_module.weeks_since(context.latest_published_at)
        uses_range = bool(range_info.is_comparator or range_info.is_special_tag or range_info.is_loose)

        return LLMDependencyItem(
            package=context.name,
            requested_version=context.declared_version,
            section=context.section,
            latest_version=latest,
            requested_version_exists=context.declared_version_exists,
            weeks_since_latest_release=weeks,
            deprecated_message=context.deprecated_message,
            major_versions_behind=majors_behind,
            min_version=context.min_version,
            max_satisfying=context.max_satisfying,
            uses_range=uses_range,
            range_kind=_range_kind(context.declared_version),
            is_url_dependency=bool(range_info.is_url),
            is_prerelease_declaration=bool(range_info.base and is_prerelease(range_info.base)),
            maintainer_count=context.maintainer_count,
            license=context.license,
            weekly_downloads=context.weekly_downloads,
            declared_engines_node=context.engines.get("node"),
            project_engines_node=context.project_engine_node,
            repository_url=context.repository_url,
            description=context.description,
            vulnerabilities=[],
            local_rule_flags=[],
            similar_popular_packages=[],
        )

    def _empty_finding(
        self,
        parsed: ParsedDependency,
        context: rules_module.DependencyContext,
    ) -> DependencyFinding:
        """Finding vazio, preenchido depois pelas regras e pelo LLM."""
        return DependencyFinding(
            package=parsed.name,
            requestedVersion=parsed.requested_version,
            resolvedVersion=normalize_version(context.resolved),
            latestVersion=context.latest_version,
            severity="ok",
            issues=[],
            recommendation="",
            breakingChangeRisk="low",
            section=parsed.section,
            description=context.description,
            latestPublishedAt=context.latest_published_at,
            maintainers=context.maintainers[:20],
            engines=context.engines,
            licenses=[context.license] if context.license else [],
            weeklyDownloads=context.weekly_downloads,
            deprecatedMessage=context.deprecated_message,
            repository=context.repository_url,
            isDevDependency=parsed.section == "devDependencies",
            analyzedByAi=False,
        )

    def _build_finding(self, item: CollectedDependency) -> DependencyFinding:
        """Monta o ``DependencyFinding`` a partir das regras determinísticas."""
        context = item.context
        result = item.rule_result
        return DependencyFinding(
            package=item.parsed.name,
            requestedVersion=item.parsed.requested_version,
            resolvedVersion=normalize_version(context.resolved),
            latestVersion=context.latest_version,
            severity=result.severity,
            issues=list(result.issues),
            recommendation=result.recommendation_hint,
            breakingChangeRisk=result.breaking_change_risk,
            section=item.parsed.section,
            description=context.description,
            latestPublishedAt=context.latest_published_at,
            maintainers=context.maintainers[:20],
            engines=context.engines,
            licenses=[context.license] if context.license else [],
            weeklyDownloads=context.weekly_downloads,
            deprecatedMessage=context.deprecated_message,
            repository=context.repository_url,
            isDevDependency=item.parsed.section == "devDependencies",
            analyzedByAi=False,
        )

    def _merge_llm_finding(self, item: CollectedDependency, llm_finding: Any) -> None:
        """Funde a classificação do LLM com o resultado determinístico.

        A IA pode **subir** a severidade (nunca rebaixar abaixo do que os dados
        objetivos já provaram) e adiciona issues com origem ``analise_ia``.
        """
        finding = item.findings
        existing_types = {issue.type for issue in finding.issues}

        for issue in llm_finding.issues:
            # Não duplica um achado objetivo que já foi registrado.
            if issue.type in existing_types and issue.source == "analise_ia":
                # Mantém, mas descarta se for exatamente o mesmo tipo já presente
                # com a mesma origem; a origem determinística tem prioridade.
                continue
            if issue.type in existing_types:
                continue
            finding.issues.append(
                Issue(
                    type=issue.type,
                    description=issue.description,
                    source="analise_ia",
                    references=issue.references[:5],
                )
            )
            existing_types.add(issue.type)

        deterministic_severity = finding.severity
        if SEVERITY_RANK.get(llm_finding.severity, 0) > SEVERITY_RANK.get(deterministic_severity, 0):
            finding.severity = llm_finding.severity  # type: ignore[assignment]

        if llm_finding.recommendation.strip():
            finding.recommendation = llm_finding.recommendation.strip()

        if SEVERITY_RANK.get(llm_finding.breaking_change_risk, 0) > SEVERITY_RANK.get(
            finding.breakingChangeRisk, 0
        ):
            finding.breakingChangeRisk = llm_finding.breaking_change_risk  # type: ignore[assignment]

        item.ai_applied = True
        finding.analyzedByAi = True


# ==========================================================
# Helpers
# ==========================================================


def _range_kind(declared: str) -> str:
    """Classifica o tipo de declaração de versão (usado no prompt)."""
    parsed = parse_range(declared)
    if parsed.is_url:
        return "url"
    if parsed.is_special_tag:
        return "latest" if declared.strip().lower().startswith("latest") else "wildcard"
    raw = declared.strip()
    if not parsed.is_comparator:
        return "exact"
    if raw.startswith("^"):
        return "caret"
    if raw.startswith("~"):
        return "tilde"
    if "||" in raw:
        return "alternative"
    return "other"


def _build_summary(findings: list[DependencyFinding]) -> Summary:
    """Conta as dependências por severidade."""
    counters = {"critical": 0, "high": 0, "medium": 0, "low": 0, "ok": 0}
    for finding in findings:
        counters[finding.severity] = counters.get(finding.severity, 0) + 1
    return Summary(**counters)


def parse_uploaded_package_json(
    content: str,
    *,
    filename: str = "package.json",
) -> ParsedPackageJson:
    """Atalho usado pelo router de upload, com erro amigável.

    Raises:
        AnalysisError: conteúdo inválido (traduzido para HTTP 400).
    """
    source = SourceFile(
        path=filename,
        url=f"upload://{filename}",
        is_monorepo_root=True,
    )
    try:
        return parse_package_json(content, source=source, fallback_name=_name_from_filename(filename))
    except PackageJsonParseError as exc:
        raise AnalysisError(str(exc), status_code=400) from exc
    except ValueError as exc:
        raise AnalysisError(str(exc), status_code=400) from exc


def _name_from_filename(filename: str) -> str:
    """Deriva um nome de projeto razoável do nome do arquivo enviado."""
    base = (filename or "package.json").replace("\\", "/").split("/")[-1]
    stem = base.rsplit(".json", 1)[0]
    return stem if stem and stem != "package" else "projeto-enviado"
