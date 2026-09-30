"""Regras determinísticas:transformam dados reais do registry/OSV em achados.

Nenhuma regra aqui usa heurística de IA — todas são reproduzíveis e
identificáveis pela origem ``regra_local`` / ``npm_registry`` / ``osv``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Final

from app.core.logging_config import get_logger
from app.core.semver import (
    compare_versions,
    is_prerelease,
    loose_range_reason,
    major_distance,
    normalize_version,
    parse_range,
    version_tuple,
)
from app.schemas.report import Issue

logger = get_logger("rules")

# ==========================================================
# Limiares configuráveis por constante
# ==========================================================

#: Sem nenhuma release há N semanas -> unmaintained.
UNMAINTAINED_WEEKS: Final[int] = 104  # ~2 anos

#: Versão "desatualizada" a partir de quantos majors atrás.
OUTDATED_MAJORS: Final[int] = 2

#: Pacote com menos de N downloads semanais e sem release há muito tempo.
ABANDONED_WEEKS: Final[int] = 78  # 18 meses

#: Severidade base de cada tipo de vulnerabilidade (ajustada pelo score do OSV).
VULN_SEVERITY_BY_LABEL: Final[dict[str, str]] = {
    "critical": "critical",
    "high": "high",
    "moderate": "medium",
    "medium": "medium",
    "low": "low",
}

#: Severidade base por regra local.
RULE_SEVERITY: Final[dict[str, str]] = {
    "not_found": "critical",
    "deprecated": "high",
    "unmaintained": "medium",
    "outdated": "medium",
    "loose_range": "low",
    "suspicious": "high",
    "vulnerability": "high",
    "engine_conflict": "medium",
}

#: Nomes de pacotes populares usados para detectar typosquatting.
POPULAR_PACKAGES: Final[dict[str, int]] = {
    "react": 1_000_000,
    "react-dom": 900_000,
    "lodash": 900_000,
    "axios": 800_000,
    "express": 700_000,
    "vue": 600_000,
    "next": 500_000,
    "chalk": 600_000,
    "commander": 500_000,
    "debug": 600_000,
    "moment": 500_000,
    "webpack": 500_000,
    "typescript": 500_000,
    "eslint": 400_000,
    "jest": 400_000,
    "dotenv": 300_000,
    "uuid": 400_000,
    "request": 400_000,
    "async": 400_000,
    "bluebird": 200_000,
    "mongoose": 300_000,
    "socket.io": 300_000,
    "nodemon": 200_000,
    "cors": 200_000,
    "body-parser": 200_000,
    "jsonwebtoken": 200_000,
    "bcrypt": 150_000,
    "passport": 150_000,
    "rollup": 150_000,
    "vite": 150_000,
    "nodemailer": 150_000,
    "cheerio": 150_000,
    "rxjs": 150_000,
    "prettier": 150_000,
    "babel": 150_000,
    "cross-env": 120_000,
    "rimraf": 120_000,
    "yargs": 120_000,
    "colors": 100_000,
    "semver": 100_000,
    "minimist": 100_000,
    "qs": 100_000,
    "tar": 100_000,
    "glob": 100_000,
    "ws": 100_000,
    "events": 90_000,
    "util": 80_000,
    "core-js": 80_000,
    "prop-types": 70_000,
    "styled-components": 60_000,
    "formik": 50_000,
    "redux": 50_000,
    "antd": 50_000,
    "@types/node": 60_000,
    "@babel/core": 50_000,
    "classnames": 40_000,
    "immer": 25_000,
    "date-fns": 40_000,
    "dayjs": 30_000,
}

#: Distância de edição mínima para considerar dois nomes "muito parecidos".
#: O limite efetivo é escalado pelo tamanho do nome em ``_typosquat_similarity``.
TYPOSQUAT_MAX_DISTANCE: Final[int] = 2

#: Quantos caracteres extras um nome pode ter sobre um pacote popular para ainda
#: ser tratado como imitação (``lodashash`` → ``lodash``).
TYPOSQUAT_SUFFIX_MAX: Final[int] = 3

#: Palavras suspeitas em pacotes desconhecidos.
SUSPICIOUS_KEYWORDS: Final[tuple[str, ...]] = (
    "keylogger",
    "password-stealer",
    "credential",
    "coinminer",
    "cryptominer",
    "shell-reverse",
    "rat-backdoor",
    "stealer",
    "exfiltrat",
)


# ==========================================================
# Modelo interno
# ==========================================================


@dataclass(slots=True)
class DependencyContext:
    """Todos os fatos coletados sobre uma dependência (entrada das regras)."""

    name: str
    declared_version: str
    section: str = "dependencies"
    project_engine_node: str | None = None

    # registry
    found_in_registry: bool | None = None
    latest_version: str | None = None
    declared_version_exists: bool | None = None
    declared_version_published_at: str | None = None
    latest_published_at: str | None = None
    deprecated_message: str | None = None
    maintainer_count: int | None = None
    maintainers: list[str] = field(default_factory=list)
    engines: dict[str, str] = field(default_factory=dict)
    license: str | None = None
    description: str | None = None
    repository_url: str | None = None
    weekly_downloads: int | None = None
    resolved_version: str | None = None
    max_satisfying: str | None = None
    min_version: str | None = None

    # osv
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)

    @property
    def is_dev(self) -> bool:
        """``True`` se veio de ``devDependencies``."""
        return self.section == "devDependencies"

    @property
    def resolved(self) -> str:
        """Versão efetiva considerada na análise."""
        return self.resolved_version or self.declared_version


@dataclass(slots=True)
class RuleResult:
    """Saída das regras para uma dependência."""

    issues: list[Issue] = field(default_factory=list)
    severity: str = "ok"
    breaking_change_risk: str = "low"
    local_flags: list[str] = field(default_factory=list)
    suspicious_matches: list[str] = field(default_factory=list)
    recommendation_hint: str = ""


# ==========================================================
# Utilidades
# ==========================================================


def weeks_since(iso_timestamp: str | None, *, now: datetime | None = None) -> int | None:
    """Semanas desde um timestamp ISO-8601 (``None`` se ausente/inválido)."""
    if not iso_timestamp:
        return None
    reference = now or datetime.now(UTC)
    try:
        parsed = datetime.fromisoformat(iso_timestamp.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    delta = reference - parsed
    if delta.total_seconds() < 0:
        return 0
    return int(delta.days // 7)


def levenshtein(a: str, b: str) -> int:
    """Distância de edição de Levenshtein (matriz em duas linhas)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            current.append(
                min(
                    previous[j] + 1,        # deleção
                    current[j - 1] + 1,     # inserção
                    previous[j - 1] + (ca != cb),  # substituição
                )
            )
        previous = current
    return previous[-1]


def _typosquat_similarity(base: str, popular: str) -> bool:
    """``True`` se ``base`` parece ser uma imitação de ``popular``.

    Cobre os dois padrões mais comuns na prática:

    1. **Pequena distância de edição** — ``expres`` vs ``express``, ``lodahs``
       vs ``lodash``. O limite escala com o tamanho do nome popular, senão
       nomes curtos (``vue``) geram falso positivo e longos (``@angular/core``)
       ficam sem proteção.
    2. **Extensão de prefixo/sufixo** — ``lodashash``, ``expresss``, ``reactt``.
       Aqui a distância de edição cresce junto com o sufixo e deixa de ser um
       bom sinal, mas a imitação é óbvia: um nome de pacote popular seguido de
       poucos caracteres aleatórios.
    """
    if base == popular:
        return False
    if len(base) < 4 or len(popular) < 4:
        return False

    limit = max(TYPOSQUAT_MAX_DISTANCE, min(3, len(popular) // 4))
    if 0 < levenshtein(base, popular) <= limit:
        return True

    # Extensão curta de um nome popular, nas duas pontas.
    if base.startswith(popular) and len(base) - len(popular) <= TYPOSQUAT_SUFFIX_MAX:
        return True
    return popular.startswith(base) and len(popular) - len(base) <= TYPOSQUAT_SUFFIX_MAX


def _similar_packages(name: str, *, known: set[str] | None = None) -> list[str]:
    """Pacotes populares com nome muito parecido (candidato a typosquatting)."""
    base = name.split("/")[-1].lower() if name.startswith("@") else name.lower()
    if not base or base in POPULAR_PACKAGES:
        return []
    matches: list[str] = []
    for popular in POPULAR_PACKAGES:
        if known is not None and popular not in known:
            continue
        if _typosquat_similarity(base, popular):
            matches.append(popular)
    matches.sort(key=len)
    return matches[:5]


def _issue_url(package: str) -> str:
    """Link do pacote no site do npm."""
    return f"https://www.npmjs.com/package/{package}"


# ==========================================================
# Regras individuais
# ==========================================================


def rule_version_not_found(ctx: DependencyContext) -> list[Issue]:
    """Versão declarada não existe no registry, ou o pacote não existe."""
    issues: list[Issue] = []

    if ctx.found_in_registry is False:
        issues.append(
            Issue(
                type="not_found",
                description=(
                    f"O pacote '{ctx.name}' não existe no registro npm com esse nome. "
                    "Isso pode indicar um erro de digitação, um pacote removido ou um nome de "
                    "pacote interno/escrito errado — e também é um padrão típico de typosquatting."
                ),
                source="npm_registry",
                references=[f"https://www.npmjs.com/package/{ctx.name}"],
            )
        )
        return issues

    if ctx.declared_version_exists is False:
        parsed = parse_range(ctx.declared_version)
        if parsed.is_url:
            return issues  # dependência via URL não é versionada
        base = normalize_version(parsed.base or ctx.declared_version)
        latest = ctx.latest_version or "desconhecida"
        issues.append(
            Issue(
                type="not_found",
                description=(
                    f"A versão '{base}' declarada para '{ctx.name}' não existe no registro npm. "
                    f"A versão mais recente publicada é {latest}. "
                    "O build pode quebrar na hora do npm install."
                ),
                source="npm_registry",
                references=[_issue_url(ctx.name)],
            )
        )
    return issues


def rule_deprecated(ctx: DependencyContext) -> list[Issue]:
    """Pacote/versão marcado como deprecated pelo mantenedor."""
    if not ctx.deprecated_message:
        return []
    message = ctx.deprecated_message.strip()
    return [
        Issue(
            type="deprecated",
            description=(
                f"O mantenedor marcou '{ctx.name}' como depreciado. Motivo informado: "
                f"\"{message}\". Versões depreciadas deixam de receber correções de segurança."
            ),
            source="npm_registry",
            references=[_issue_url(ctx.name)],
        )
    ]


def rule_vulnerabilities(ctx: DependencyContext) -> list[Issue]:
    """Vulnerabilidades conhecidas (OSV) para a versão efetivamente resolvida."""
    issues: list[Issue] = []
    if not ctx.vulnerabilities:
        return issues

    version = ctx.resolved
    for vuln in ctx.vulnerabilities:
        label = vuln.get("severity_label")
        vuln_id = vuln.get("short_id") or vuln.get("id") or "OSV-UNKNOWN"
        fixed = vuln.get("fixed_versions") or []
        summary = vuln.get("summary") or "Sem descrição fornecida pelo banco de dados."
        score = vuln.get("severity_score")

        severity_txt = (label or "não classificada").upper()
        score_txt = f" (CVSS {score})" if isinstance(score, (int, float)) else ""
        fixed_txt = (
            f" Versão corrigida disponível: {', '.join(fixed)}." if fixed else " Nenhuma versão corrigida foi publicada."
        )

        issues.append(
            Issue(
                type="vulnerability",
                description=(
                    f"{vuln_id}: {summary} Severidade {severity_txt}{score_txt}. "
                    f"Afeta a versão {version} de '{ctx.name}'.{fixed_txt}"
                ),
                source="osv",
                references=[vuln.get("best_reference") or f"https://osv.dev/vulnerability/{vuln_id}"],
            )
        )

    return issues


def rule_outdated(ctx: DependencyContext) -> tuple[list[Issue], str]:
    """Versão muito atrás da última publicada.

    Returns:
        Tupla ``(issues, severidade)`` — a severidade só é aplicada se houver issue.
    """
    if not ctx.latest_version:
        return [], "low"
    resolved = ctx.resolved
    if not resolved:
        return [], "low"
    if _is_url_or_tag(ctx.declared_version):
        return [], "low"

    # Versão inexistente já foi reportada por rule_version_not_found
    if ctx.declared_version_exists is False:
        return [], "low"

    if compare_versions(resolved, ctx.latest_version) >= 0:
        return [], "low"

    distance = major_distance(resolved, ctx.latest_version)
    minor_gap = version_tuple(ctx.latest_version)[:2] != version_tuple(resolved)[:2]

    if distance < OUTDATED_MAJORS and not minor_gap:
        return [], "low"  # diferença pequena: não vale um achado

    weeks = weeks_since(ctx.latest_published_at)
    if distance >= OUTDATED_MAJORS:
        text = (
            f"'{ctx.name}' está {distance} versão(ões) principal(is) atrás: usa {resolved} e a mais "
            f"recente é {ctx.latest_version}."
        )
    elif minor_gap:
        text = (
            f"'{ctx.name}' está defasado dentro da mesma major: {resolved} contra {ctx.latest_version}."
        )
    else:
        text = (
            f"'{ctx.name}' usa {resolved} e já existe {ctx.latest_version} publicada"
            + (f" há {weeks} semanas" if weeks else "")
            + "."
        )

    severity = "medium" if distance >= OUTDATED_MAJORS else "low"
    return [
        Issue(
            type="outdated",
            description=text + " Atualizar costuma trazer correções de segurança e de bugs.",
            source="npm_registry",
            references=[_issue_url(ctx.name)],
        )
    ], severity


def rule_unmaintained(ctx: DependencyContext) -> list[Issue]:
    """Sem publicação há mais de 2 anos (ou pacote praticamente abandonado)."""
    issues: list[Issue] = []
    weeks = weeks_since(ctx.latest_published_at)
    if weeks is None or weeks < UNMAINTAINED_WEEKS:
        return issues

    abandoned = (ctx.weekly_downloads is not None and ctx.weekly_downloads < 50 and weeks >= ABANDONED_WEEKS)
    years = round(weeks / 52, 1)

    if abandoned:
        description = (
            f"'{ctx.name}' parece abandonado: última publicação há {years} anos e apenas "
            f"{ctx.weekly_downloads} downloads por semana. Pacotes nesse estado costumam não corrigir "
            "vulnerabilidades nem compatibilidade com versões novas do Node."
        )
    else:
        description = (
            f"'{ctx.name}' não recebe atualizações há {years} anos (última versão: {ctx.latest_version}). "
            "Pacotes sem manutenção provavelmente não recebem correções de segurança."
        )

    if ctx.maintainer_count == 1:
        description += " O pacote tem apenas 1 mantenedor, o que aumenta o risco de abandono."

    return [
        Issue(
            type="unmaintained",
            description=description,
            source="npm_registry",
            references=[_issue_url(ctx.name)],
        )
    ]


def rule_loose_range(ctx: DependencyContext) -> list[Issue]:
    """Uso de ``latest``, ``*`` ou ranges permissivos demais."""
    issues: list[Issue] = []
    reason = loose_range_reason(ctx.declared_version)
    if not reason:
        return issues

    parsed = parse_range(ctx.declared_version)
    declared = ctx.declared_version

    if parsed.is_url:
        description = (
            f"'{ctx.name}' aponta para um repositório/tarball Git em vez de uma versão do registro npm: "
            f"\"{declared}\". Não dá para auditar a versão instalada, e o código pode mudar "
            "sem nenhum aviso."
        )
    elif declared.strip() == "*" or declared.strip().startswith("*") or declared.strip().endswith("*") or "x" in declared.lower():
        # Cobre "*", "1.x", "16.x.x". O texto cita o motivo real (wildcard) em
        # vez de chamar isso de "tag móvel", que seria enganoso.
        description = (
            f"'{ctx.name}' usa o wildcard em \"{declared}\": {reason}. O npm escolhe a versão sozinho, "
            "então uma atualização maior pode entrar na máquina sem você perceber."
        )
    elif parsed.is_special_tag:
        description = (
            f"'{ctx.name}' está declarado como \"{declared}\", uma tag móvel em vez de uma "
            "faixa de versão. Cada instalação pode resolver uma versão diferente, o que torna o build "
            "não reprodutível e permite que uma versão futura com problemas entre na máquina."
        )
    else:
        description = (
            f"'{ctx.name}' usa a faixa permissiva \"{declared}\": {reason}. "
            "Isso pode instalar versões que você nunca testou."
        )

    issues.append(
        Issue(
            type="loose_range",
            description=description,
            source="regra_local",
            references=[_issue_url(ctx.name)],
        )
    )
    return issues


def rule_suspicious(ctx: DependencyContext, *, known_packages: set[str] | None = None) -> list[Issue]:
    """Possível typosquatting ou nome com padrão suspeito.

    ``known_packages`` são os pacotes realmente declarados no projeto: só
    consideramos imitação de um pacote popular que *também* está no projeto
    (é o cenário real de confusão: ``lodahs`` no lugar de ``lodash``).
    """
    issues: list[Issue] = []
    lowered = ctx.name.lower()
    flags: list[str] = []

    similar = _similar_packages(lowered, known=known_packages)
    if similar:
        flags.append("nome_parecido")
        issues.append(
            Issue(
                type="suspicious",
                description=(
                    f"O nome '{ctx.name}' é muito parecido com o pacote popular '{similar[0]}' "
                    "(diferença de poucos caracteres). Esse é o padrão clássico de typosquatting: "
                    "pacotes maliciosos copiam nomes conhecidos para capturar instalações por engano. "
                    "Confirme se você realmente quer esse pacote."
                ),
                source="regra_local",
                references=[f"https://www.npmjs.com/package/{similar[0]}"],
            )
        )

    keyword_hit = next((word for word in SUSPICIOUS_KEYWORDS if word in lowered), None)
    if keyword_hit:
        flags.append("palavra_suspeita")
        issues.append(
            Issue(
                type="suspicious",
                description=(
                    f"O nome do pacote '{ctx.name}' contém o termo \"{keyword_hit}\", associado a "
                    "ferramentas de roubo de credenciais ou mineração de criptomoedas. Revise com muita "
                    "cautela se esse pacote é legítimo."
                ),
                source="regra_local",
                references=[_issue_url(ctx.name)],
            )
        )

    # Pacote recém-publicado, sem downloads, com nome de pacote popular
    if similar and ctx.weekly_downloads is not None and ctx.weekly_downloads == 0:
        flags.append("sem_downloads")
        issues.append(
            Issue(
                type="suspicious",
                description=(
                    f"'{ctx.name}' não registra nenhum download na semana e imita o nome de "
                    f"'{similar[0]}'. Pacotes recém-criados com imitação de nomes conhecidos devem "
                    "ser considerados não confiáveis até passarem por uma revisão de segurança."
                ),
                source="regra_local",
                references=[f"https://www.npmjs.com/package/{similar[0]}"],
            )
        )

    if flags:
        logger.debug("Pacote suspeito detectado: %s (%s)", ctx.name, ", ".join(flags))
    return issues


def rule_engine_conflict(ctx: DependencyContext) -> list[Issue]:
    """Incompatibilidade entre ``engines.node`` do pacote e do projeto."""
    if not ctx.engines or not ctx.project_engine_node:
        return []
    package_range = ctx.engines.get("node")
    project_range = ctx.project_engine_node
    if not package_range or not project_range:
        return []

    package_min = _min_node(package_range)
    project_min = _min_node(project_range)
    if package_min is None or project_min is None:
        return []

    if version_tuple(project_min) < version_tuple(package_min):
        return [
            Issue(
                type="engine_conflict",
                description=(
                    f"'{ctx.name}' exige Node \"{package_range}\", mas o projeto declara "
                    f"engines.node \"{project_range}\". A instalação pode falhar ou o pacote pode não "
                    "funcionar na versão de Node do projeto."
                ),
                source="regra_local",
                references=[_issue_url(ctx.name)],
            )
        ]
    return []


def rule_prerelease_declared(ctx: DependencyContext) -> list[Issue]:
    """Dependência declarada em pré-release (beta/rc/next)."""
    base = parse_range(ctx.declared_version).base
    if not base or not is_prerelease(base):
        return []
    return [
        Issue(
            type="loose_range",
            description=(
                f"'{ctx.name}' está fixado em uma versão de pré-lançamento ({base}). "
                "Pré-releases não têm garantia de estabilidade e podem quebrar sem aviso."
            ),
            source="regra_local",
            references=[_issue_url(ctx.name)],
        )
    ]


def _is_url_or_tag(declared: str) -> bool:
    """``True`` se a declaração é URL ou tag móvel (não comparável por semver)."""
    parsed = parse_range(declared)
    return parsed.is_url or parsed.is_special_tag or parsed.base is None


def _min_node(node_range: str) -> str | None:
    """Extrai a menor versão de Node aceitável de uma string ``engines.node``."""
    import re

    match = re.search(r">=?\s*v?(\d+(?:\.\d+){0,2})", node_range)
    if match:
        return match.group(1)
    match = re.match(r"\^?\s*v?(\d+(?:\.\d+){0,2})", node_range.strip())
    if match:
        return match.group(1)
    return None


# ==========================================================
# Orquestrador das regras
# ==========================================================


def apply_rules(ctx: DependencyContext, *, known_packages: set[str] | None = None) -> RuleResult:
    """Aplica todas as regras determinísticas a uma dependência.

    A severidade resultante é a **pior** entre todos os achados, e o risco de
    breaking change é derivado da distância de major e da existência de
    vulnerabilidades sem correção disponível.
    """
    result = RuleResult()
    collected: list[tuple[str, Issue]] = []
    worst_severity = "ok"

    def collect(rule_name: str, issues: list[Issue], severity: str) -> None:
        """Acumula issues e registra o pior cenário de severidade."""
        nonlocal worst_severity
        for issue in issues:
            collected.append((rule_name, issue))
        if issues and _rank(severity) > _rank(worst_severity):
            worst_severity = severity

    # 1) Pacote inexistente no registry: nenhuma outra regra de registry faz sentido.
    not_found = rule_version_not_found(ctx)
    if ctx.found_in_registry is False:
        return RuleResult(
            issues=not_found,
            severity="critical",
            breaking_change_risk="high",
            local_flags=["pacote_inexistente"],
            recommendation_hint=(
                f"Remova '{ctx.name}' ou corrija o nome do pacote. Se você esperava esse pacote, "
                "verifique se o nome está escrito corretamente."
            ),
        )

    collect("not_found", not_found, RULE_SEVERITY["not_found"])
    collect("vulnerability", rule_vulnerabilities(ctx), _max_vuln_severity(ctx))
    collect("deprecated", rule_deprecated(ctx), RULE_SEVERITY["deprecated"])

    outdated_issues, outdated_severity = rule_outdated(ctx)
    collect("outdated", outdated_issues, outdated_severity)

    collect("unmaintained", rule_unmaintained(ctx), RULE_SEVERITY["unmaintained"])
    collect("loose_range", rule_loose_range(ctx), RULE_SEVERITY["loose_range"])
    collect("prerelease", rule_prerelease_declared(ctx), "low")
    collect("engine_conflict", rule_engine_conflict(ctx), RULE_SEVERITY["engine_conflict"])
    collect("suspicious", rule_suspicious(ctx, known_packages=known_packages), RULE_SEVERITY["suspicious"])

    result.issues = [issue for _, issue in collected]
    result.local_flags = [rule_name for rule_name, _ in collected]
    result.suspicious_matches = _similar_packages(ctx.name.lower(), known=known_packages)
    result.severity = _final_severity(ctx, worst_severity)
    result.breaking_change_risk = _breaking_risk(ctx, result)
    result.recommendation_hint = _build_hint(ctx, result)
    return result


def _max_vuln_severity(ctx: DependencyContext) -> str:
    """Pior severidade entre as vulnerabilidades OSV da dependência.

    Começamos em ``ok`` (acumulador neutro) para que uma vulnerabilidade de
    severidade ``medium`` não fique presa no piso ``high``. Se nenhuma
    vulnerabilidade trouxer severidade interpretável, caímos no piso
    conservador da regra: classificar um advisory sem severidade como "low"
    subestimaria o risco.
    """
    worst = "ok"
    resolved_any = False
    for vuln in ctx.vulnerabilities:
        label = vuln.get("severity_label")
        score = vuln.get("severity_score")
        mapped = VULN_SEVERITY_BY_LABEL.get(str(label).lower()) if label else None
        if mapped is None and isinstance(score, (int, float)) and not isinstance(score, bool):
            value = float(score)
            mapped = (
                "critical"
                if value >= 9.0
                else "high"
                if value >= 7.0
                else "medium"
                if value >= 4.0
                else "low"
            )
        if mapped is None:
            continue
        resolved_any = True
        if _rank(mapped) > _rank(worst):
            worst = mapped
    return worst if resolved_any else RULE_SEVERITY["vulnerability"]


def _final_severity(ctx: DependencyContext, worst_rule: str) -> str:
    """Ajusta a severidade final considerando o contexto (dev vs runtime)."""
    if ctx.is_dev and worst_rule in {"critical", "high"}:
        # Vulnerabilidades de devDependencies não afetam produção: rebaixamos 1 nível.
        return "high" if worst_rule == "critical" else "medium"
    return worst_rule


def _breaking_risk(ctx: DependencyContext, result: RuleResult) -> str:
    """Estima o risco de breaking change da atualização recomendada."""
    has_vuln = any(issue.type == "vulnerability" for issue in result.issues)
    unfixed = has_vuln and all(
        not vuln.get("fixed_versions") for vuln in ctx.vulnerabilities
    )

    if ctx.found_in_registry is False:
        return "high"
    if not ctx.latest_version or _is_url_or_tag(ctx.declared_version):
        return "high" if unfixed else "medium"

    distance = major_distance(ctx.resolved, ctx.latest_version)
    if distance >= 2:
        return "high"
    if distance == 1:
        return "high" if has_vuln else "medium"
    if version_tuple(ctx.resolved)[:2] != version_tuple(ctx.latest_version)[:2]:
        return "medium" if has_vuln else "low"
    if has_vuln and unfixed:
        return "medium"
    if any(issue.type == "loose_range" for issue in result.issues):
        return "low"
    return "low"


def _build_hint(ctx: DependencyContext, result: RuleResult) -> str:
    """Sugestão curta de ação, completada depois pelo LLM quando disponível."""
    if result.severity == "ok":
        return "Nenhuma ação necessária."
    if ctx.found_in_registry is False:
        return "Remover ou corrigir o nome do pacote."
    if any(issue.type == "vulnerability" for issue in result.issues):
        fixed = sorted({v for vuln in ctx.vulnerabilities for v in (vuln.get("fixed_versions") or [])})
        if fixed and ctx.latest_version:
            return f"Atualizar para {ctx.latest_version} (corrige as vulnerabilidades conhecidas)."
        return "Procurar uma alternativa mantida ou um fork seguro."
    if ctx.deprecated_message:
        if ctx.latest_version:
            return f"Migrar para {ctx.latest_version} ou para o sucessor indicado pelo mantenedor."
        return "Substituir pelo pacote sucessor indicado na mensagem de depreciação."
    if any(issue.type == "unmaintained" for issue in result.issues):
        return "Avaliar a troca por uma alternativa com manutenção ativa."
    if ctx.latest_version and compare_versions(ctx.resolved, ctx.latest_version) < 0:
        return f"Atualizar para {ctx.latest_version}."
    return "Revisar a configuração da dependência."


def _rank(severity: str) -> int:
    """Rank numérico da severidade (maior = pior)."""
    return {"ok": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(severity, 0)
