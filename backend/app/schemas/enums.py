"""Enums e tipos base compartilhados pelo contrato da API."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["critical", "high", "medium", "low", "ok"]
IssueType = Literal[
    "vulnerability",
    "deprecated",
    "not_found",
    "outdated",
    "unmaintained",
    "suspicious",
    "loose_range",
    "prerelease",
    "engine_conflict",
]
IssueSource = Literal["osv", "npm_registry", "regra_local", "analise_ia"]
BreakingRisk = Literal["low", "medium", "high"]
DependencyKind = Literal["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]

#: Ordem de severidade, do pior para o melhor (usada em ordenações e no "pior caso").
SEVERITY_ORDER: dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}

#: Ordem numérica para agregação do pior caso de um lote.
SEVERITY_RANK: dict[str, int] = {"ok": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class DependencySection(StrEnum):
    """Seções do ``package.json`` analisadas."""

    dependencies = "dependencies"
    dev_dependencies = "devDependencies"
    peer_dependencies = "peerDependencies"
    optional_dependencies = "optionalDependencies"


class SourceFile(BaseModel):
    """Um ``package.json`` localizado em um repositório GitHub."""

    model_config = ConfigDict(extra="forbid")

    path: str = Field(description="Caminho no repositório, ex.: 'package.json' ou 'packages/api/package.json'")
    url: str = Field(description="URL de download do arquivo")
    is_monorepo_root: bool = Field(
        default=False, description="True quando é o package.json da raiz do repositório"
    )
    size_bytes: int | None = Field(default=None, description="Tamanho do arquivo em bytes")
