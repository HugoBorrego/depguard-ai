"""Parser do ``package.json``: extrai dependências das quatro seções relevantes."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Final

from app.core.logging_config import get_logger
from app.schemas.enums import SourceFile

logger = get_logger("pkg_parser")

#: Seções lidas, na ordem de precedência para desempate de nomes duplicados.
DEPENDENCY_SECTIONS: Final[tuple[str, ...]] = (
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
)

#: Limite de dependências aceitas (protege contra manifestos absurdos).
MAX_DEPENDENCIES: Final[int] = 800


class PackageJsonParseError(ValueError):
    """O conteúdo não é um package.json utilizável."""


class ParsedDependency:
    """Uma dependência extraída, com metadados da seção de origem."""

    __slots__ = ("is_optional", "is_peer", "name", "requested_version", "section")

    def __init__(
        self,
        name: str,
        requested_version: str,
        section: str,
        is_optional: bool = False,
        is_peer: bool = False,
    ) -> None:
        self.name = name
        self.requested_version = requested_version
        self.section = section
        self.is_optional = is_optional
        self.is_peer = is_peer

    def to_dict(self) -> dict[str, Any]:
        """Representação serializável (útil em logs e testes)."""
        return {
            "name": self.name,
            "requestedVersion": self.requested_version,
            "section": self.section,
            "isOptional": self.is_optional,
            "isPeer": self.is_peer,
        }

    def __repr__(self) -> str:  # pragma: no cover - debug
        return f"ParsedDependency({self.name!r}@{self.requested_version!r} in {self.section})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ParsedDependency):
            return NotImplemented
        return (
            self.name == other.name
            and self.requested_version == other.requested_version
            and self.section == other.section
        )


class ParsedPackageJson:
    """Resultado do parse: dependências + metadados do projeto."""

    def __init__(
        self,
        name: str,
        dependencies: list[ParsedDependency],
        raw: dict[str, Any],
        source: SourceFile | None = None,
    ) -> None:
        self.name = name
        self.dependencies = dependencies
        self.raw = raw
        self.source = source

    @property
    def version(self) -> str | None:
        """Versão declarada do projeto."""
        value = self.raw.get("version")
        return str(value) if isinstance(value, (str, int, float)) else None

    @property
    def license(self) -> str | None:
        """Licença do projeto (string ou primeira chave de objeto)."""
        value = self.raw.get("license")
        if isinstance(value, str):
            return value
        if isinstance(value, dict) and isinstance(value.get("type"), str):
            return value["type"]
        return None

    @property
    def engine_node(self) -> str | None:
        """Campo ``engines.node`` declarado pelo projeto."""
        engines = self.raw.get("engines")
        if isinstance(engines, dict) and isinstance(engines.get("node"), str):
            return engines["node"]
        return None

    @property
    def unique_names(self) -> list[str]:
        """Nomes únicos na ordem de aparição."""
        seen: dict[str, None] = {}
        for dep in self.dependencies:
            seen.setdefault(dep.name, None)
        return list(seen)

    @property
    def runtime_count(self) -> int:
        """Qtd. de dependências de runtime (não-dev)."""
        return sum(1 for d in self.dependencies if d.section != "devDependencies")

    @property
    def dev_count(self) -> int:
        """Qtd. de dependências de desenvolvimento."""
        return sum(1 for d in self.dependencies if d.section == "devDependencies")

    def to_dict(self) -> dict[str, Any]:
        """Dicionário serializável do resultado do parse."""
        return {
            "name": self.name,
            "version": self.version,
            "license": self.license,
            "engineNode": self.engine_node,
            "totalDependencies": len(self.dependencies),
            "uniqueNames": self.unique_names,
            "dependencies": [d.to_dict() for d in self.dependencies],
        }


def _coerce_version(value: Any) -> str | None:
    """Normaliza o valor de uma dependência para string, ou ``None`` se inválido."""
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    # Alguns manifests legados usam número (ex.: "1.0" -> 1.0) — tratamos como string.
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return None


def parse_package_json(
    content: str | bytes | dict[str, Any],
    *,
    source: SourceFile | None = None,
    fallback_name: str = "projeto-desconhecido",
) -> ParsedPackageJson:
    """Faz o parse do ``package.json`` e extrai as dependências.

    Aceita string, bytes ou dict já decodificado. Nomes duplicados entre seções
    são mantidos, mas sinalizados pela seção de origem (``devDependencies``
    herda o lugar quando o mesmo pacote também é de runtime, para evitar
    alarmes falsos).

    Raises:
        PackageJsonParseError: JSON inválido, não-objeto ou sem nenhuma seção de dependências.
    """
    if isinstance(content, bytes):
        try:
            content = content.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise PackageJsonParseError("package.json não está em UTF-8 válido.") from exc

    if isinstance(content, str):
        import json

        text = content.lstrip("\ufeff").strip()
        if not text:
            raise PackageJsonParseError("package.json está vazio.")
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise PackageJsonParseError(
                f"package.json com JSON inválido (linha {exc.lineno}, coluna {exc.colno}): {exc.msg}"
            ) from exc
    elif isinstance(content, dict):
        data = content
    else:
        raise PackageJsonParseError("package.json inválido: tipo de conteúdo não suportado.")

    if not isinstance(data, dict):
        raise PackageJsonParseError("package.json precisa ser um objeto JSON.")

    name_value = data.get("name")
    project_name = (
        str(name_value).strip() if isinstance(name_value, str) and name_value.strip() else fallback_name
    )

    dependencies: list[ParsedDependency] = []
    seen_names: set[str] = set()

    for section in DEPENDENCY_SECTIONS:
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for raw_name, raw_version in block.items():
            if not isinstance(raw_name, str):
                continue
            name = raw_name.strip()
            if not name:
                continue
            version = _coerce_version(raw_version)
            if version is None:
                logger.warning("Ignorando dependência %r sem versão válida em %s", name, section)
                continue
            dependencies.append(
                ParsedDependency(
                    name=name,
                    requested_version=version,
                    section=section,
                    is_optional=(section == "optionalDependencies"),
                    is_peer=(section == "peerDependencies"),
                )
            )
            seen_names.add(name)

    if not dependencies:
        found = ", ".join(s for s in DEPENDENCY_SECTIONS if isinstance(data.get(s), dict)) or "nenhuma"
        raise PackageJsonParseError(
            f"O package.json não possui dependências analisáveis (seções encontradas: {found})."
        )

    if len(dependencies) > MAX_DEPENDENCIES:
        raise PackageJsonParseError(
            f"package.json com {len(dependencies)} dependências excede o limite de {MAX_DEPENDENCIES}."
        )

    # Promove para 'dependencies' pacotes que também vivem em devDependencies
    # (mesma versão em ambas as seções = dependência de runtime na prática).
    runtime_names = {d.name for d in dependencies if d.section != "devDependencies"}
    for dep in dependencies:
        if dep.section == "devDependencies" and dep.name in runtime_names:
            dep.section = "dependencies"

    return ParsedPackageJson(
        name=project_name,
        dependencies=dependencies,
        raw=data,
        source=source,
    )


def weeks_since(iso_timestamp: str | None, *, now: datetime | None = None) -> int | None:
    """Semanas (arredondadas para baixo) desde um timestamp ISO-8601."""
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
