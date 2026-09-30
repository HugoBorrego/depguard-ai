"""Schemas de entrada/saída do LLM (JSON estrito exigido ao modelo)."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.enums import BreakingRisk, IssueSource, IssueType, Severity


class LLMDependencyItem(BaseModel):
    """Dependência serializada e enviada ao LLM (somente fatos coletados)."""

    model_config = ConfigDict(extra="forbid")

    package: str
    requested_version: str = Field(description="Exatamente como declarado no package.json")
    section: str = Field(description="dependencies | devDependencies | peerDependencies | optionalDependencies")
    latest_version: str | None = None
    requested_version_exists: bool | None = Field(
        default=None, description="True se a versão declarada existe no registry"
    )
    weeks_since_latest_release: int | None = Field(
        default=None, description="Semanas desde a publicação da última versão"
    )
    deprecated_message: str | None = Field(default=None, description="Mensagem de deprecated do registry")
    major_versions_behind: int | None = None
    min_version: str | None = Field(default=None, description="Menor versão dentro da faixa declarada")
    max_satisfying: str | None = Field(default=None, description="Maior versão que satisfaz a faixa")
    uses_range: bool = Field(default=False, description="True se a declaração não é uma versão exata")
    range_kind: str | None = Field(default=None, description="latest | wildcard | caret | tilde | url | exact | other")
    is_url_dependency: bool = False
    is_prerelease_declaration: bool = False
    maintainer_count: int | None = None
    license: str | None = None
    weekly_downloads: int | None = None
    declared_engines_node: str | None = Field(default=None, description="engines.node da última versão")
    project_engines_node: str | None = None
    repository_url: str | None = None
    description: str | None = None
    vulnerabilities: list[LLMVulnerabilityItem] = Field(default_factory=list)
    local_rule_flags: list[str] = Field(
        default_factory=list, description="Flags curta de regras determinísticas já aplicadas"
    )
    similar_popular_packages: list[str] = Field(
        default_factory=list,
        max_length=5,
        description="Pacotes populares com nome muito parecido (candidato a typosquatting)",
    )


class LLMVulnerabilityItem(BaseModel):
    """Vulnerabilidade do OSV já formatada para o prompt."""

    model_config = ConfigDict(extra="forbid")

    id: str
    summary: str | None = None
    aliases: list[str] = Field(default_factory=list)
    severity_score: float | None = Field(
        default=None, description="CVSS/score do OSV, quando disponível"
    )
    database_specific_severity: str | None = None
    affected_ranges: list[str] = Field(default_factory=list)
    fixed_versions: list[str] = Field(default_factory=list)
    published_at: str | None = None
    references: list[str] = Field(default_factory=list, max_length=10)


class LLMFinding(BaseModel):
    """Uma dependência como classificada pelo LLM."""

    model_config = ConfigDict(extra="forbid")

    package: str
    severity: Severity
    issues: list[LLMIssue] = Field(default_factory=list)
    recommendation: str = Field(default="", max_length=1500)
    breaking_change_risk: BreakingRisk = "low"


class LLMIssue(BaseModel):
    """Um issue levantado pelo LLM (sempre ``source='analise_ia'``)."""

    model_config = ConfigDict(extra="forbid")

    type: IssueType
    description: str = Field(min_length=1, max_length=800)
    source: IssueSource = Field(default="analise_ia")
    references: list[str] = Field(default_factory=list, max_length=5)


class LLMAnalysisResult(BaseModel):
    """Resposta completa esperada do LLM para um lote."""

    model_config = ConfigDict(extra="forbid")

    findings: list[LLMFinding] = Field(
        description="Uma entrada para CADA dependência recebida, sem omissões e sem extras"
    )


LLMDependencyItem.model_rebuild()
LLMFinding.model_rebuild()
