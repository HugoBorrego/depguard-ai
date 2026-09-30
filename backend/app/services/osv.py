"""Cliente do OSV.dev: vulnerabilidades conhecidas por pacote + versão."""

from __future__ import annotations

import math
from typing import Any, Final

from app.core.config import Settings, get_settings
from app.core.http_client import ExternalServiceError, HttpClient, Semaphore
from app.core.logging_config import get_logger
from app.core.semver import normalize_version

logger = get_logger("osv")

OSV_QUERY_BATCH: Final[str] = "https://api.osv.dev/v1/querybatch"
OSV_QUERY: Final[str] = "https://api.osv.dev/v1/query"
OSV_VULN_BASE: Final[str] = "https://osv.dev/vulnerability"

#: Severidades do OSV normalizadas para nossa escala.
OSV_SEVERITY_MAP: Final[dict[str, str]] = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MODERATE": "medium",
    "MEDIUM": "medium",
    "LOW": "low",
}

# Pesos oficiais do CVSS v3.1 para as métricas base.
_CVSS_AV: Final[dict[str, float]] = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_CVSS_AC: Final[dict[str, float]] = {"L": 0.77, "H": 0.44}
_CVSS_UI: Final[dict[str, float]] = {"N": 0.85, "R": 0.62}
_CVSS_CIA: Final[dict[str, float]] = {"H": 0.56, "L": 0.22, "N": 0.0}
_CVSS_PR: Final[dict[str, dict[str, float]]] = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.5},
}


class OsvError(RuntimeError):
    """Falha ao consultar o OSV."""


class OsvVulnerability:
    """Vulnerabilidade normalizada vinda do OSV."""

    __slots__ = (
        "affected_ranges",
        "aliases",
        "cvss_vector",
        "details",
        "fixed_versions",
        "id",
        "modified_at",
        "published_at",
        "references",
        "severity_label",
        "severity_score",
        "summary",
    )

    def __init__(
        self,
        *,
        id: str,
        aliases: list[str],
        summary: str | None,
        details: str | None,
        severity_label: str | None,
        severity_score: float | None,
        published_at: str | None,
        modified_at: str | None,
        references: list[str],
        affected_ranges: list[str],
        fixed_versions: list[str],
        cvss_vector: str | None,
    ) -> None:
        self.id = id
        self.aliases = aliases
        self.summary = summary
        self.details = details
        self.severity_label = severity_label
        self.severity_score = severity_score
        self.published_at = published_at
        self.modified_at = modified_at
        self.references = references
        self.affected_ranges = affected_ranges
        self.fixed_versions = fixed_versions
        self.cvss_vector = cvss_vector

    @property
    def best_reference(self) -> str:
        """Melhor link de referência (advisory do OSV ou primeiro link)."""
        if self.references:
            return self.references[0]
        return f"{OSV_VULN_BASE}/{self.id}"

    @property
    def short_id(self) -> str:
        """Identificador curto e legível (CVE quando existir, senão o id do OSV)."""
        for alias in self.aliases:
            if alias.upper().startswith("CVE-"):
                return alias.upper()
        return self.id.upper()

    def to_rule_dict(self) -> dict[str, Any]:
        """Adaptador para o contrato das regras locais (``app.services.rules``).

        As regras são funções puras que recebem mapas simples; este método é a
        **única** fronteira entre o modelo do OSV e esse contrato, o que evita
        que regras e analisador compartilhem nomes de campo divergentes.
        """
        return {
            "id": self.id,
            "short_id": self.short_id,
            "summary": self.summary,
            "severity_label": self.severity_label,
            "severity_score": self.severity_score,
            "fixed_versions": list(self.fixed_versions),
            "affected_ranges": list(self.affected_ranges),
            "best_reference": self.best_reference,
        }

    def to_dict(self) -> dict[str, Any]:
        """Representação serializável (usada no log e nos testes)."""
        return {
            "id": self.id,
            "aliases": self.aliases,
            "summary": self.summary,
            "severity": self.severity_label,
            "score": self.severity_score,
            "fixedVersions": self.fixed_versions,
            "references": self.references,
        }


class QueryBatchResults(list[dict[str, Any] | None]):
    """Resultado de :meth:`OsvClient.query_batch`.

    Uma ``list`` comum (um resultado por consulta, ``None`` quando o bloco
    falhou) com o atributo extra ``failed_blocks``. Sem isso, a degradação
    silenciosa do OSV seria indistinguível de "nenhuma vulnerabilidade
    encontrada" — e o relatório afirmaria que o projeto está limpo quando, na
    verdade, ninguém perguntou.
    """

    def __init__(self) -> None:
        super().__init__()
        self.failed_blocks = 0

    @property
    def degraded(self) -> bool:
        """``True`` se alguma consulta foi perdida por indisponibilidade."""
        return self.failed_blocks > 0


class VulnResults(dict[str, list[dict[str, Any]]]):
    """Mapa ``"pacote@versão" -> vulnerabilidades`` com indicação de degradação."""

    def __init__(self) -> None:
        super().__init__()
        self.degraded = False


class OsvClient:
    """Consulta o OSV em lote (``querybatch``), com semáforo e degradação silenciosa."""

    def __init__(
        self,
        http: HttpClient | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.http = http or HttpClient(settings=self.settings)
        self.semaphore = Semaphore(self.settings.osv_concurrency)

    async def query_batch(self, queries: list[dict[str, Any]]) -> QueryBatchResults:
        """Envia várias consultas em uma requisição.

        O OSV aceita no máximo 1000 consultas por request; dividimos em blocos.

        Returns:
            :class:`QueryBatchResults` com um resultado por consulta (``None``
            em falha) e ``failed_blocks`` indicando quantos blocos se perderam.
        """
        results = QueryBatchResults()
        if not queries:
            return results

        block_size = 500
        blocks = [queries[i : i + block_size] for i in range(0, len(queries), block_size)]

        for block in blocks:
            try:
                async with self.semaphore:
                    payload = await self.http.post_json(
                        OSV_QUERY_BATCH,
                        json_body={"queries": block},
                        headers={"Content-Type": "application/json"},
                        service="osv",
                    )
            except ExternalServiceError as exc:
                logger.warning("OSV indisponível (%s): %s dependências ficarão sem dados de CVE.", exc, len(block))
                results.extend([None] * len(block))
                results.failed_blocks += 1
                continue

            batch_results = (payload or {}).get("results") if isinstance(payload, dict) else None
            if not isinstance(batch_results, list):
                logger.warning("Resposta inesperada do OSV; %s consultas descartadas.", len(block))
                results.extend([None] * len(block))
                results.failed_blocks += 1
                continue

            for index in range(len(block)):
                entry = batch_results[index] if index < len(batch_results) else None
                results.append(entry if isinstance(entry, dict) else None)

        return results

    async def get_vulnerabilities(self, package: str, version: str) -> list[dict[str, Any]]:
        """Vulns do OSV para ``package@version`` (formato cru do OSV)."""
        results = await self.query_batch([{"package": {"name": package, "ecosystem": "npm"}, "version": version}])
        entry = results[0] if results else None
        if not entry:
            return []
        vulns = entry.get("vulns")
        return [v for v in vulns if isinstance(v, dict)] if isinstance(vulns, list) else []

    async def query_many(
        self,
        targets: list[tuple[str, str]],
    ) -> VulnResults:
        """Consulta vários ``(pacote, versão)`` de uma vez.

        Returns:
            :class:`VulnResults` — mapa ``"pacote@versão" -> vulnerabilidades``.
            ``degraded`` sinaliza que alguma dependência ficou sem resposta do
            OSV e, portanto, **não** foi verificada.
        """
        pairs = list(dict.fromkeys(targets))
        if not pairs:
            return VulnResults()

        queries = [
            {"package": {"name": name, "ecosystem": "npm"}, "version": normalize_version(version)}
            for name, version in pairs
        ]
        batch = await self.query_batch(queries)

        out = VulnResults()
        for (name, version), entry in zip(pairs, batch, strict=False):
            vulns: list[dict[str, Any]] = []
            if entry and isinstance(entry.get("vulns"), list):
                vulns = [v for v in entry["vulns"] if isinstance(v, dict)]
            out[f"{name}@{normalize_version(version)}"] = vulns
        out.degraded = batch.degraded
        return out

    async def aclose(self) -> None:
        """Fecha o cliente HTTP subjacente."""
        await self.http.aclose()


# ==========================================================
# Normalização das respostas do OSV
# ==========================================================


def parse_vulnerability(raw: dict[str, Any]) -> OsvVulnerability:
    """Converte o JSON do OSV em ``OsvVulnerability`` normalizada."""
    vuln_id = str(raw.get("id") or "OSV-UNKNOWN")
    aliases = [a for a in (raw.get("aliases") or []) if isinstance(a, str)]

    summary = raw.get("summary") if isinstance(raw.get("summary"), str) else None
    details = raw.get("details") if isinstance(raw.get("details"), str) else None

    database_severity, score, vector = _extract_severity(raw)

    references: list[str] = []
    for ref in raw.get("references") or []:
        if isinstance(ref, dict) and isinstance(ref.get("url"), str):
            references.append(ref["url"])
        elif isinstance(ref, str):
            references.append(ref)
    references = list(dict.fromkeys(references))[:10]

    affected_ranges, fixed_versions = _extract_ranges(raw)

    return OsvVulnerability(
        id=vuln_id,
        aliases=aliases,
        summary=summary.strip()[:500] if summary else None,
        details=details.strip()[:2000] if details else None,
        severity_label=database_severity,
        severity_score=score,
        published_at=raw.get("published") if isinstance(raw.get("published"), str) else None,
        modified_at=raw.get("modified") if isinstance(raw.get("modified"), str) else None,
        references=references,
        affected_ranges=affected_ranges,
        fixed_versions=fixed_versions,
        cvss_vector=vector,
    )


def _extract_severity(raw: dict[str, Any]) -> tuple[str | None, float | None, str | None]:
    """Extrai severidade do OSV: ``database_specific`` > ``severity[]`` (CVSS)."""
    label: str | None = None
    vector: str | None = None
    score: float | None = None

    database_specific = raw.get("database_specific")
    if isinstance(database_specific, dict):
        raw_severity = database_specific.get("severity")
        if isinstance(raw_severity, str):
            label = OSV_SEVERITY_MAP.get(raw_severity.upper(), raw_severity.upper())

    severities = raw.get("severity")
    if isinstance(severities, list):
        for entry in severities:
            if not isinstance(entry, dict):
                continue
            entry_vector = entry.get("score")
            if isinstance(entry_vector, str) and not vector:
                vector = entry_vector
            if isinstance(entry.get("type"), str) and entry["type"].startswith("CVSS"):
                parsed = _cvss_to_score(entry_vector)
                if parsed is not None:
                    score = parsed
                    if label is None:
                        label = _score_to_label(parsed)
                break

    if label is None and score is not None:
        label = _score_to_label(score)

    return label, score, vector


def _score_to_label(score: float) -> str:
    """Mapeia um score CVSS (0-10) para nossos níveis."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _cvss_to_score(vector: str | None) -> float | None:
    """Calcula o score base a partir de um vetor CVSS v3.x.

    O OSV normalmente envia apenas o vetor (``CVSS:3.1/AV:N/AC:L/...``), sem o
    score separado. Implementamos a fórmula oficial do CVSS v3.1 para obter a
    severidade real em vez de inventar uma aproximação:

        ISS  = 1 - (1-C)(1-I)(1-A)
        Impact = 6.42 × ISS                              (escopo inalterado)
        Impact = 7.52 × (ISS - 0.029) - 3.25 × (ISS - 0.02)^15   (escopo alterado)
        Exploitability = 8.22 × AV × AC × PR × UI
        Base = roundup(min((1.08 se escopo alterado) × (Impact + Exploitability), 10))

    Devolve ``None`` se o vetor não for reconhecível.
    """
    if not vector or "/" not in vector:
        return None
    try:
        metrics = dict(
            part.split(":", 1) for part in vector.split("/")[1:] if ":" in part
        )
    except ValueError:
        return None

    av = _CVSS_AV.get(metrics.get("AV", "N"), _CVSS_AV["N"])
    ac = _CVSS_AC.get(metrics.get("AC", "L"), _CVSS_AC["L"])
    ui = _CVSS_UI.get(metrics.get("UI", "N"), _CVSS_UI["N"])
    scope_changed = metrics.get("S", "U") == "C"
    pr = _CVSS_PR["C" if scope_changed else "U"].get(metrics.get("PR", "N"), 0.85)

    # C, I e A são três métricas independentes: ler só "C" zerava o impacto de
    # vulnerabilidades que só afetam integridade ou disponibilidade.
    c = _CVSS_CIA.get(metrics.get("C", "N"), 0.0)
    i = _CVSS_CIA.get(metrics.get("I", "N"), 0.0)
    a = _CVSS_CIA.get(metrics.get("A", "N"), 0.0)

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if iss <= 0:
        return 0.0

    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui
    raw_score = impact + exploitability
    if scope_changed:
        raw_score *= 1.08
    return _cvss_roundup(min(raw_score, 10.0))


def _cvss_roundup(value: float) -> float:
    """``Roundup`` do CVSS v3.1: arredonda para cima com 1 casa decimal.

    É propositalmente diferente de ``round()``: o CVSS usa "arredondar para
    cima" para não subestimar a severidade (ex.: 6.05 vira 6.1, não 6.0).
    """
    return math.ceil(value * 10 - 1e-9) / 10


def _extract_ranges(raw: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Extrai os intervalos afetados e as versões corrigidas, em texto simples."""
    ranges: list[str] = []
    fixed: list[str] = []

    for affected in raw.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        # Consideramos apenas o ecossistema npm
        pkg = affected.get("package")
        if isinstance(pkg, dict) and str(pkg.get("ecosystem", "npm")).lower() != "npm":
            continue
        for rng in affected.get("ranges") or []:
            if not isinstance(rng, dict):
                continue
            # O OSV identifica o "repo" do range de várias formas para o npm:
            # "npm", "https://github.com/npm/npm", "https://github.com/npm/cli".
            # Filtrar por igualdade descartaria os intervalos (e as correções) de
            # boa parte dos advisories reais, então aceitamos qualquer repo
            # cujo identificador contenha "npm".
            repo = rng.get("repo")
            if isinstance(repo, str) and repo.strip() and "npm" not in repo.lower():
                continue
            events: list[str] = []
            for event in rng.get("events") or []:
                if not isinstance(event, dict):
                    continue
                introduced = event.get("introduced")
                fixed_version = event.get("fixed")
                last_affected = event.get("last_affected")
                if isinstance(introduced, str):
                    events.append(f">= {introduced}" if introduced != "0" else "todas")
                if isinstance(fixed_version, str):
                    events.append(f"< {fixed_version}")
                    fixed.append(fixed_version)
                if isinstance(last_affected, str):
                    events.append(f"<= {last_affected}")
            if events:
                ranges.append(" ".join(events))

    fixed_versions = sorted(set(fixed))[:6]
    return list(dict.fromkeys(ranges))[:6], fixed_versions
