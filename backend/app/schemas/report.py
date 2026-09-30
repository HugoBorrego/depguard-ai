"""Schema de resposta do relatório (``AnalysisReport``) — contrato público da API."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field, computed_field

from app.schemas.enums import (
    SEVERITY_ORDER,
    BreakingRisk,
    IssueSource,
    IssueType,
    Severity,
)


class Issue(BaseModel):
    """Um problema encontrado em uma dependência."""

    model_config = ConfigDict(extra="forbid")

    type: IssueType = Field(description="Categoria do problema")
    description: str = Field(min_length=1, max_length=2000, description="Explicação em linguagem simples")
    source: IssueSource = Field(description="Origem do achado")
    references: list[str] = Field(
        default_factory=list, max_length=20, description="Links de apoio (advisories, registry, docs)"
    )


class DependencyFinding(BaseModel):
    """Resultado da análise de uma dependência."""

    model_config = ConfigDict(extra="forbid")

    package: str = Field(min_length=1, max_length=214, description="Nome do pacote")
    requestedVersion: str = Field(description="Versão exatamente como declarada no package.json")
    resolvedVersion: str | None = Field(
        default=None, description="Versão que o npm resolveria (base da faixa declarada)"
    )
    latestVersion: str | None = Field(default=None, description="Última versão publicada no registry")
    severity: Severity = Field(description="Severidade consolidada")
    issues: list[Issue] = Field(default_factory=list, description="Problemas encontrados")
    recommendation: str = Field(
        default="",
        max_length=4000,
        description="Ação concreta sugerida (versão alvo, alternativa ou remoção)",
    )
    breakingChangeRisk: BreakingRisk = Field(
        default="low", description="Risco de breaking change ao seguir a recomendação"
    )

    # Campos informativos extras (útil na UI, ignorados por clientes simples)
    section: str | None = Field(default=None, description="Seção do package.json onde foi declarada")
    description: str | None = Field(default=None, description="Descrição do pacote no registry")
    latestPublishedAt: str | None = Field(
        default=None, description="Data de publicação da última versão (ISO-8601)"
    )
    maintainers: list[str] = Field(default_factory=list, max_length=50, description="Mantenedores no registry")
    engines: dict[str, str] = Field(default_factory=dict, description="Campo 'engines' da última versão")
    licenses: list[str] = Field(default_factory=list, max_length=20, description="Licenças declaradas")
    weeklyDownloads: int | None = Field(
        default=None, description="Downloads semanais (via api.npmjs.org), se disponível"
    )
    deprecatedMessage: str | None = Field(default=None, description="Mensagem de depreciação do registry")
    repository: str | None = Field(default=None, description="URL do repositório do pacote")
    isDevDependency: bool = Field(default=False, description="True se veio de devDependencies")
    analyzedByAi: bool = Field(
        default=False, description="True se a classificação de severidade veio do LLM"
    )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def issueCount(self) -> int:
        """Quantidade de problemas encontrados (facilita a UI)."""
        return len(self.issues)

    @property
    def severity_rank(self) -> int:
        """Rank numérico da severidade (0 = critical). Usado na ordenação."""
        return SEVERITY_ORDER.get(self.severity, 99)


class ProjectInfo(BaseModel):
    """Metadados do projeto analisado."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(description="Nome do projeto (do package.json ou do repositório)")
    version: str | None = Field(default=None, description="Versão declarada do projeto")
    source: str = Field(description="'github' | 'upload'")
    sourceUrl: str | None = Field(default=None, description="URL do repositório ou null em uploads")
    manifests: list[str] = Field(
        default_factory=list, description="Caminhos dos package.json encontrados no repositório"
    )
    totalDependencies: int = Field(ge=0, description="Total de dependências únicas analisadas")
    runtimeDependencies: int = Field(default=0, ge=0, description="Qtd. em dependencies/peer/optional")
    devDependencies: int = Field(default=0, ge=0, description="Qtd. em devDependencies")
    engineNode: str | None = Field(default=None, description="Campo engines.node do projeto")
    license: str | None = Field(default=None, description="Licença do projeto")


class Summary(BaseModel):
    """Contagem de dependências por severidade."""

    model_config = ConfigDict(extra="forbid")

    critical: int = Field(default=0, ge=0)
    high: int = Field(default=0, ge=0)
    medium: int = Field(default=0, ge=0)
    low: int = Field(default=0, ge=0)
    ok: int = Field(default=0, ge=0)

    @property
    def total(self) -> int:
        """Soma de todas as severidades."""
        return self.critical + self.high + self.medium + self.low + self.ok


class AnalysisMeta(BaseModel):
    """Informações sobre como a análise foi feita (transparência e diagnóstico)."""

    model_config = ConfigDict(extra="forbid")

    analyzedAt: str = Field(description="Timestamp ISO-8601 da análise")
    durationMs: int = Field(ge=0, description="Tempo total em milissegundos")
    aiEnabled: bool = Field(description="True se a análise por LLM foi executada")
    aiModel: str | None = Field(default=None, description="Modelo usado")
    aiBatches: int = Field(default=0, ge=0, description="Número de lotes enviados ao LLM")
    aiFailures: int = Field(default=0, ge=0, description="Lotes que falharam após retries")
    npmEtagCache: int | None = Field(default=None, description="Entradas no cache do registry")
    warnings: list[str] = Field(default_factory=list, description="Avisos não-fatais da execução")


class AnalysisReport(BaseModel):
    """Resposta completa de ``/api/analyze/*``."""

    model_config = ConfigDict(extra="forbid")

    project: ProjectInfo
    summary: Summary
    findings: list[DependencyFinding] = Field(description="Uma entrada por dependência")
    meta: AnalysisMeta = Field(default_factory=lambda: AnalysisMeta(
        analyzedAt=datetime.now(UTC).isoformat(), durationMs=0, aiEnabled=False
    ))

    def sort_findings(self) -> list[DependencyFinding]:
        """Ordena por severidade (pior primeiro) e depois por nome do pacote."""
        return sorted(self.findings, key=lambda f: (f.severity_rank, f.package.lower()))


class HealthResponse(BaseModel):
    """Resposta de ``GET /api/health``."""

    model_config = ConfigDict(extra="forbid")

    status: str = Field(examples=["ok"])
    version: str
    environment: str
    aiEnabled: bool
    githubTokenConfigured: bool
    cacheEntries: int = 0
    serverTime: str
