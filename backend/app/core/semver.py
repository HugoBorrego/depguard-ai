"""Utilidades de versionamento semântico (faixas e comparação de versões)."""

from __future__ import annotations

import re
from functools import lru_cache
from typing import NamedTuple

# Prefixos de range que removemos para obter a "versão declarada".
_RANGE_PREFIX_RE = re.compile(
    r"^[\s]*(?:[~^]|>=|<=|>|<|=)?\s*|\s*\|\|\s*$",
)

# Prefixos de protocolo / VCS que indicam dependência via URL.
_URL_PREFIXES: tuple[str, ...] = (
    "git+",
    "git:",
    "http://",
    "https://",
    "ssh://",
    "file:",
    "github:",
    "bitbucket:",
    "gitlab:",
    "npm:",
    "workspace:",
    "link:",
    "portal:",
)

_SPECIAL_TAGS: frozenset[str] = frozenset({"latest", "*", "x", "X", "next", "beta", "canary"})

_VERSION_RE = re.compile(r"^\d+(?:\.\d+){0,3}(?:[-+][0-9A-Za-z.\-+]+)?$")

#: Faixa parcialmente curinga com major e minor definidos: ``1.x``, ``16.x.x``.
_WILDCARD_BASE_RE = re.compile(r"^(\d+)\.([xX*]+)(?:\.[xX*]+)?$")

#: Primeiro token de versão concreto dentro de um range composto.
_FIRST_VERSION_RE = re.compile(r"v?\d+(?:\.\d+){0,2}")


class ParsedRange(NamedTuple):
    """Resultado da análise de uma faixa de versão declarada."""

    raw: str
    base: str | None
    is_special_tag: bool
    is_loose: bool
    is_url: bool
    is_comparator: bool

    @property
    def is_usable(self) -> bool:
        """``True`` se a string é uma versão/faixa aproveitável para consultar a API."""
        return self.base is not None and not self.is_url


def is_url_dependency(raw: str) -> bool:
    """``True`` se a dependência aponta para git, tarball ou URL."""
    value = (raw or "").strip().lower()
    if not value:
        return False
    if value.startswith(_URL_PREFIXES):
        return True
    if value.startswith("www.") and ".com/" in value:
        return True
    return "://" in value


def is_special_tag(raw: str) -> bool:
    """``True`` para ``latest``, ``*`` e tags móveis parecidas."""
    value = (raw or "").strip()
    if not value:
        return False
    return value in _SPECIAL_TAGS or value.startswith(("latest", "*", "beta", "next", "canary", "x"))


def parse_range(raw: str) -> ParsedRange:
    """Separa uma faixa declarada em tag especial, URL, comparador ou versão base."""
    value = (raw or "").strip()
    empty = ParsedRange(raw="", base=None, is_special_tag=False, is_loose=False, is_url=False, is_comparator=False)
    if not value:
        return empty

    if is_url_dependency(value):
        return ParsedRange(
            raw=value, base=None, is_special_tag=False, is_loose=False, is_url=True, is_comparator=False
        )

    if is_special_tag(value):
        return ParsedRange(
            raw=value, base=None, is_special_tag=True, is_loose=True, is_url=False, is_comparator=False
        )

    is_comparator = bool(re.search(r"[<>=~^]|\s-\s|\|\|", value))
    is_loose = value == "*" or bool(re.search(r"^\s*[\^~*]|[<>]\s*0|\|\||\s-\s|>", value))

    # Extrai a "versão base": a parte que o npm usaria para escolher a versão.
    base = value
    if "||" in base:
        base = base.split("||", 1)[0].strip()  # npm prefere a primeira alternativa
    if " - " in base:
        base = base.split(" - ", 1)[1].strip()  # limite superior de range inclusivo
    if is_comparator:
        base = re.sub(r"^[\s^~=><]+", "", base).strip()
    base = base.lstrip("v").strip()

    # Wildcards parciais têm uma base bem definida: "1.x" é a linha 1.0.0,
    # "16.x.x" é a 16.0.0. Sem isso, o analisador não teria versão alguma para
    # comparar e a dependência ficaria sem resolved_version.
    if base and not _VERSION_RE.match(base):
        wildcard_base = _WILDCARD_BASE_RE.match(base)
        if wildcard_base:
            base = f"{wildcard_base[1]}.0.0"
        else:
            # Range composto (">=1.0.0 <3.0.0", ">=1.2 || 2.x"): a base é o
            # primeiro token de versão concreto, que é o piso que o npm usaria.
            first_version = _FIRST_VERSION_RE.search(base)
            base = first_version[0] if first_version else None
    elif base:
        # Completa segmentos ausentes: "4" -> "4.0.0", "1.2" -> "1.2.0".
        parts = base.split(".")
        if len(parts) < 3 and all(part.isdigit() for part in parts):
            base = ".".join([*parts, *(["0"] * (3 - len(parts)))])

    return ParsedRange(
        raw=value,
        base=base,
        is_special_tag=False,
        is_loose=is_loose,
        is_url=False,
        is_comparator=is_comparator,
    )


@lru_cache(maxsize=4096)
def version_tuple(version: str) -> tuple[int, int, int, int]:
    """Converte ``"1.2.3"`` em ``(1, 2, 3, 0)``; tolerante a sufixos de prerelease."""
    match = re.match(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?", (version or "").strip())
    if not match:
        return (0, 0, 0, 0)
    return tuple(int(part or 0) for part in match.groups())  # type: ignore[return-value]


def compare_versions(a: str, b: str) -> int:
    """Compara duas versões: ``-1`` se ``a < b``, ``0`` se iguais, ``1`` se ``a > b``."""
    ta, tb = version_tuple(a), version_tuple(b)
    if ta < tb:
        return -1
    if ta > tb:
        return 1
    return 0


def major_distance(a: str, b: str) -> int:
    """Distância absoluta de *major* entre duas versões."""
    return abs(version_tuple(a)[0] - version_tuple(b)[0])


def is_prerelease(version: str) -> bool:
    """``True`` para versões com sufixo de pré-lançamento (``-beta``, ``-rc``, ``-next``)."""
    cleaned = (version or "").strip().lstrip("v")
    if "-" in cleaned.split("+", 1)[0]:
        return True
    return bool(re.search(r"(alpha|beta|rc|pre|dev|canary|nightly)", cleaned, re.IGNORECASE))


def normalize_version(version: str) -> str:
    """Remove prefixo ``v`` e espaços; devolve a versão como publicada."""
    return (version or "").strip().lstrip("vV")


def satisfies_minor_only(raw: str) -> bool:
    """``True`` para ``^1.2.3`` (permite apenas *minor*/*patch*)."""
    return (raw or "").strip().startswith("^")


def satisfies_major_only(raw: str) -> bool:
    """``True`` para ``>=1.2.3 <2.0.0``-style ranges que aceitam qualquer coisa acima."""
    value = (raw or "").strip()
    if not value.startswith(">="):
        return False
    return ">=" in value and not any(ch in value for ch in ("<",))


def loose_range_reason(raw: str) -> str | None:
    """Devolve o motivo pelo qual a faixa é permissiva demais, ou ``None`` se ok."""
    value = (raw or "").strip()
    if not value:
        return "versão vazia"

    # URL / git / tarball: não há versão para auditar.
    if is_url_dependency(value):
        return "aponta para um repositório/tarball em vez de uma versão do registro"

    # Wildcard: verificado antes das tags móveis, porque "*" e "x" também são
    # tags para o npm, mas a causa real é o wildcard (aceita qualquer versão).
    if value == "*":
        return "usa wildcard total (*), que aceita qualquer versão"
    if value.startswith("*") or value.endswith("*") or "x" in value.lower():
        return "contém wildcard (x/*), que deixa a resolução por conta do npm"

    # Tag móvel ("latest", "next", "beta-3"...): a resolução muda com o tempo.
    if is_special_tag(value):
        return f'usa a tag móvel "{value}" em vez de uma faixa de versão'

    if value.startswith("^0"):
        return "caret em 0.x (^0.x.y) restringe a linha 0.x, o que é fácil de deixar para trás"
    if value == ">=0.0.0" or value.startswith(">=0"):
        return "range >=0.x não impõe limite superior"
    if satisfies_major_only(value):
        return "range >=X sem teto superior, pode instalar versões maiores que o esperado"
    if "||" in value:
        return "range com múltiplas alternativas (||), aumenta a chance de resolver uma versão inesperada"
    if " - " in value:
        return "range com limites explícitos, menos previsível para builds reprodutíveis"
    return None
