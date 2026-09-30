"""Cliente do registry npm: metadados reais de cada versão publicada."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any, Final

from app.core.config import Settings, get_settings
from app.core.http_client import ExternalServiceError, HttpClient, Semaphore, TTLCache
from app.core.logging_config import get_logger
from app.core.semver import normalize_version, version_tuple

logger = get_logger("npm")

REGISTRY_BASE: Final[str] = "https://registry.npmjs.org"
DOWNLOADS_API: Final[str] = "https://api.npmjs.org"
ACCEPT_FIELDS: Final[str] = ",".join(
    (
        "name",
        "dist-tags",
        "time",
        "versions",
        "maintainers",
        "description",
        "repository",
        "license",
        "homepage",
        "keywords",
        "deprecated",
        "engines",
        "versions.name",
        "versions.version",
        "versions.deprecated",
        "versions.engines",
        "versions.license",
        "versions.repository",
        "versions.dist.tarball",
    )
)


class NpmRegistryError(RuntimeError):
    """Falha ao consultar o registry npm."""


class PackageNotFound(NpmRegistryError):
    """O pacote não existe no registry.npmjs.org."""


class RegistryUnavailable(NpmRegistryError):
    """O registry respondeu, mas de forma inutilizável (rede, 5xx, rate limit)."""


#: Marcador guardado no cache para pacotes comprovadamente inexistentes (404).
#: O cache é compartilhado entre requisições, então o 404 precisa ser
#: reapresentado como PackageNotFound em vez de devolveido como se fosse
#: metadado válido.
_NOT_FOUND: Final[dict[str, Any]] = {"__not_found__": True}


class RegistryResults(dict[str, dict[str, Any] | None]):
    """Resultado de :meth:`NpmRegistryClient.fetch_many`.

    Um ``dict`` normal (nome -> metadados, ``None`` quando o pacote não existe)
    com o atributo extra ``unavailable``: nomes que **não** puderam ser
    verificados por falha do registry. Sem essa distinção, uma indisponibilidade
    da rede seria reportada como "pacote inexistente", o que é uma charge
    injusta contra o projeto analisado.
    """

    def __init__(self) -> None:
        super().__init__()
        self.unavailable: set[str] = set()

    def found(self, name: str) -> bool:
        """``True`` se o pacote foi encontrado no registry."""
        return self.get(name) is not None

    def exists(self, name: str) -> bool | None:
        """``True``/``False`` se o pacote existe; ``None`` se não foi possível verificar."""
        if name in self.unavailable:
            return None
        return self.get(name) is not None


def _parse_date(value: Any) -> datetime | None:
    """Converte um timestamp ISO do registry em ``datetime`` com timezone."""
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def _normalize_engines(raw: Any) -> dict[str, str]:
    """Normaliza o campo ``engines`` (às vezes dict, às vezes string)."""
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items() if isinstance(v, (str, int, float))}
    if isinstance(raw, str) and raw.strip():
        return {"node": raw.strip()}
    return {}


class NpmRegistryClient:
    """Consulta o registry npm com cache TTL, semáforo e tolerância a falhas.

    Nenhum erro de rede aqui derruba a análise: o campo correspondente
    simplesmente volta ``None`` e as regras locais seguem funcionando com os
    dados disponíveis.
    """

    def __init__(
        self,
        http: HttpClient | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.http = http or HttpClient(settings=self.settings)
        self.cache = TTLCache(
            ttl_seconds=self.settings.registry_cache_ttl_seconds,
            max_entries=2048,
            enabled=self.settings.cache_enabled,
        )
        self.semaphore = Semaphore(self.settings.registry_concurrency)

    # ------------------------------------------------------------ pacote
    async def get_package(self, name: str) -> dict[str, Any] | None:
        """Metadados completos (com ``versions``) de um pacote.

        Levanta :class:`PackageNotFound` em 404 e :class:`RegistryUnavailable`
        quando o registry falhou de outra forma — as duas situações não podem
        ser confundidas, pois a primeira é um problema do projeto analisado.
        """
        encoded = _encode_package_name(name)
        cache_key = f"pkg:{encoded}"
        cached = await self.cache.get(cache_key)
        if isinstance(cached, dict):
            if cached.get("__not_found__") is True:
                raise PackageNotFound(f"Pacote '{name}' não existe no registry npm.")
            return cached

        url = f"{REGISTRY_BASE}/{encoded}"
        try:
            async with self.semaphore:
                data = await self.http.request_json(
                    "GET",
                    url,
                    headers={"Accept": "application/json"},
                    service="npm",
                )
        except ExternalServiceError as exc:
            if exc.status_code == 404:
                logger.info("Pacote %s não encontrado no registry.", name)
                # 404 é definitivo: vale a pena cachear (inclusive o negativo).
                await self.cache.set(cache_key, dict(_NOT_FOUND))
                raise PackageNotFound(f"Pacote '{name}' não existe no registry npm.") from exc
            # Falha transitória: NÃO é cacheada, para que a próxima requisição tente de novo.
            logger.warning("Registry indisponível para %s: %s", name, exc)
            raise RegistryUnavailable(f"Registry npm indisponível ao buscar '{name}'.") from exc

        if not isinstance(data, dict):
            raise RegistryUnavailable(f"Resposta inesperada do registry para '{name}'.")

        await self.cache.set(cache_key, data)
        return data

    async def get_package_safe(self, name: str) -> dict[str, Any] | None:
        """Como :meth:`get_package`, mas devolve ``None`` em vez de levantar :class:`PackageNotFound`.

        :class:`RegistryUnavailable` continua propagando: quem chama precisa saber
        que o pacote não foi verificado (e não que ele não existe).
        """
        try:
            return await self.get_package(name)
        except PackageNotFound:
            return None

    # ------------------------------------------------------------ versões
    def version_exists(self, metadata: dict[str, Any], version: str) -> bool | None:
        """``True``/``False`` se a versão existe; ``None`` se não foi possível verificar."""
        if not metadata:
            return None
        versions = metadata.get("versions")
        if not isinstance(versions, dict):
            return None
        return normalize_version(version) in versions

    def get_version_data(self, metadata: dict[str, Any], version: str) -> dict[str, Any] | None:
        """Dados de uma versão específica (``engines``, ``deprecated``, ``license``...)."""
        versions = metadata.get("versions")
        if not isinstance(versions, dict):
            return None
        entry = versions.get(normalize_version(version))
        return entry if isinstance(entry, dict) else None

    def latest_version(self, metadata: dict[str, Any]) -> str | None:
        """Última versão publicada, usando ``dist-tags.latest``."""
        if not metadata:
            return None
        tags = metadata.get("dist-tags")
        if isinstance(tags, dict):
            latest = tags.get("latest")
            if isinstance(latest, str) and latest:
                return latest
        versions = metadata.get("versions")
        if isinstance(versions, dict) and versions:
            return max(versions.keys(), key=version_tuple)
        return None

    def all_versions(self, metadata: dict[str, Any]) -> list[str]:
        """Todas as versões publicadas, ordenadas crescentemente por semver."""
        versions = metadata.get("versions")
        if not isinstance(versions, dict):
            return []
        return sorted((v for v in versions if isinstance(v, str)), key=version_tuple)

    def latest_published_at(self, metadata: dict[str, Any], version: str | None = None) -> str | None:
        """Data de publicação (ISO) de uma versão, ou da última."""
        if not metadata:
            return None
        time_map = metadata.get("time")
        if not isinstance(time_map, dict):
            return None
        target = version or self.latest_version(metadata)
        if not target:
            return None
        raw = time_map.get(normalize_version(target))
        if not isinstance(raw, str):
            # fallback: a entrada "modified" é a última atualização do pacote
            raw = time_map.get("modified")
        return raw if isinstance(raw, str) else None

    def published_at(self, metadata: dict[str, Any], version: str) -> str | None:
        """Data de publicação de uma versão específica."""
        time_map = (metadata or {}).get("time")
        if not isinstance(time_map, dict):
            return None
        raw = time_map.get(normalize_version(version))
        return raw if isinstance(raw, str) else None

    def deprecated_message(self, metadata: dict[str, Any], version: str | None = None) -> str | None:
        """Mensagem de depreciação da versão, ou do pacote inteiro.

        O npm marca depreciação por versão (``versions[x].deprecated``) e, mais
        raro, no nível do pacote (``deprecated``).
        """
        if not metadata:
            return None
        target = version or self.latest_version(metadata)
        if target:
            entry = self.get_version_data(metadata, target)
            if entry and isinstance(entry.get("deprecated"), str):
                return entry["deprecated"]
        if isinstance(metadata.get("deprecated"), str):
            return metadata["deprecated"]
        return None

    def is_deprecated(self, metadata: dict[str, Any], version: str | None = None) -> bool:
        """``True`` se a versão (ou o pacote) está marcado como deprecated."""
        return self.deprecated_message(metadata, version) is not None

    def maintainers(self, metadata: dict[str, Any]) -> list[str]:
        """Nomes dos mantenedores registrados."""
        maintainers = (metadata or {}).get("maintainers")
        if not isinstance(maintainers, list):
            return []
        names: list[str] = []
        for entry in maintainers:
            if isinstance(entry, str):
                names.append(entry)
            elif isinstance(entry, dict) and isinstance(entry.get("name"), str):
                names.append(entry["name"])
        return names

    def maintainer_count(self, metadata: dict[str, Any]) -> int | None:
        """Quantidade de mantenedores (``None`` se o dado não existir)."""
        maintainers = (metadata or {}).get("maintainers")
        return len(maintainers) if isinstance(maintainers, list) else None

    def engines(self, metadata: dict[str, Any], version: str | None = None) -> dict[str, str]:
        """Campo ``engines`` da versão indicada (ou da última)."""
        target = version or self.latest_version(metadata)
        if not target:
            return {}
        entry = self.get_version_data(metadata, target)
        return _normalize_engines((entry or {}).get("engines"))

    def description(self, metadata: dict[str, Any], version: str | None = None) -> str | None:
        """Descrição do pacote (usa a descrição da versão quando existir)."""
        target = version or self.latest_version(metadata)
        if target:
            entry = self.get_version_data(metadata, target)
            if entry and isinstance(entry.get("description"), str) and entry["description"].strip():
                return entry["description"].strip()[:400]
        value = (metadata or {}).get("description")
        return value.strip()[:400] if isinstance(value, str) and value.strip() else None

    def license_of(self, metadata: dict[str, Any], version: str | None = None) -> str | None:
        """Licença da versão (string ou ``{type: ...}``)."""
        target = version or self.latest_version(metadata)
        candidates: list[Any] = []
        if target:
            entry = self.get_version_data(metadata, target)
            if entry:
                candidates.append(entry.get("license"))
        candidates.append((metadata or {}).get("license"))
        for candidate in candidates:
            if isinstance(candidate, str) and candidate.strip():
                return candidate.strip()[:60]
            if isinstance(candidate, dict) and isinstance(candidate.get("type"), str):
                return candidate["type"]
        return None

    def licenses_of(self, metadata: dict[str, Any], version: str | None = None) -> list[str]:
        """Lista de licenças (para a UI)."""
        single = self.license_of(metadata, version)
        return [single] if single else []

    def repository_url(self, metadata: dict[str, Any], version: str | None = None) -> str | None:
        """URL do repositório, normalizando o formato objeto do npm."""
        target = version or self.latest_version(metadata)
        sources: list[Any] = []
        if target:
            entry = self.get_version_data(metadata, target)
            if entry:
                sources.append(entry.get("repository"))
        sources.append((metadata or {}).get("repository"))
        for source in sources:
            if isinstance(source, str) and source.strip():
                return source.strip()[:300]
            if isinstance(source, dict):
                url = source.get("url")
                if isinstance(url, str) and url.strip():
                    return _clean_repo_url(url.strip())
        return None

    def max_satisfying(self, metadata: dict[str, Any], declared: str) -> str | None:
        """Maior versão publicada que satisfaz a faixa declarada.

        Faz o match de forma simplificada: aceita versões cuja tupla semver
        respeita major/minor conforme o tipo de range. Devolve ``None`` quando
        não é possível determinar (ex.: ``latest`` ou URL).
        """
        from app.core.semver import parse_range

        parsed_range = parse_range(declared)
        if not parsed_range.base:
            return None
        available = self.all_versions(metadata)
        if not available:
            return None

        raw = declared.strip()
        base = parsed_range.base or ""
        base_tuple = version_tuple(base)
        matches: list[str] = []

        if not any(ch in raw for ch in "^~>=<"):
            # versão exata (ou prefixo exato como "1.2.3")
            for candidate in available:
                if normalize_version(candidate) == normalize_version(base):
                    return candidate
                if raw.startswith(candidate) and raw[len(candidate) :].startswith("."):
                    matches.append(candidate)
            return max(matches, key=version_tuple) if matches else None

        if raw.startswith("^"):
            for candidate in available:
                c_tuple = version_tuple(candidate)
                if c_tuple < base_tuple:
                    continue
                if base_tuple[0] > 0:
                    if c_tuple[0] == base_tuple[0]:
                        matches.append(candidate)
                elif base_tuple[1] > 0:
                    if c_tuple[0] == 0 and c_tuple[1] == base_tuple[1]:
                        matches.append(candidate)
                else:
                    if c_tuple[0] == 0 and c_tuple[1] == 0 and c_tuple[2] == base_tuple[2]:
                        matches.append(candidate)
        elif raw.startswith("~"):
            for candidate in available:
                c_tuple = version_tuple(candidate)
                if c_tuple >= base_tuple and c_tuple[0] == base_tuple[0] and c_tuple[1] == base_tuple[1]:
                    matches.append(candidate)
        else:
            # >=, >, <, ranges compostos: usamos o teto definido no range
            ceiling = _ceiling_of(raw)
            for candidate in available:
                c_tuple = version_tuple(candidate)
                if c_tuple < base_tuple:
                    continue
                if ceiling is not None and c_tuple >= ceiling:
                    continue
                matches.append(candidate)

        if not matches:
            return None
        return max(matches, key=version_tuple)

    def min_version(self, metadata: dict[str, Any], declared: str) -> str | None:
        """Menor versão publicada que satisfaz a faixa declarada."""
        from app.core.semver import parse_range

        parsed_range = parse_range(declared)
        if not parsed_range.base:
            return None
        available = self.all_versions(metadata)
        if not available:
            return None
        base_tuple = version_tuple(parsed_range.base)
        candidates = [v for v in available if version_tuple(v) >= base_tuple]
        if not candidates:
            return None
        return min(candidates, key=version_tuple)

    # ------------------------------------------------------------ extras
    async def get_weekly_downloads(self, name: str) -> int | None:
        """Downloads na última semana (endpoint oficial, best-effort)."""
        if not name.strip():
            return None
        cache_key = f"dl:{name}"
        cached = await self.cache.get(cache_key)
        if isinstance(cached, int):
            return cached
        period = "last-week"
        try:
            async with self.semaphore:
                data = await self.http.request_json(
                    "GET",
                    f"{DOWNLOADS_API}/downloads/point/{period}/{_encode_package_name(name)}",
                    service="npm-downloads",
                )
        except ExternalServiceError:
            return None
        value = (data or {}).get("downloads") if isinstance(data, dict) else None
        result = value if isinstance(value, int) else None
        await self.cache.set(cache_key, result)
        return result

    async def fetch_many(
        self,
        names: list[str],
        *,
        with_downloads: bool = False,
    ) -> RegistryResults:
        """Busca metadados de vários pacotes em paralelo (limitado pelo semáforo).

        Devolve um :class:`RegistryResults`, que além do mapa nome -> metadados
        (``None`` = 404) informa em ``unavailable`` quais pacotes falharam por
        indisponibilidade do registry.
        """
        unique = list(dict.fromkeys(names))
        results = RegistryResults()
        gathered = await asyncio.gather(
            *(self.get_package_safe(name) for name in unique), return_exceptions=True
        )
        for name, value in zip(unique, gathered, strict=False):
            if isinstance(value, NpmRegistryError):
                # Falha transitória do registry: registrado, mas sem crashar a análise.
                results.unavailable.add(name)
                results[name] = None
            else:
                results[name] = value if isinstance(value, dict) else None

        if with_downloads:
            download_counts = await asyncio.gather(
                *(self.get_weekly_downloads(name) for name in results), return_exceptions=True
            )
            for name, count in zip(results, download_counts, strict=False):
                payload = results.get(name)
                if isinstance(payload, dict) and isinstance(count, int):
                    results[name] = {**payload, "__weekly_downloads__": count}
        return results

    async def aclose(self) -> None:
        """Fecha o cliente HTTP subjacente."""
        await self.http.aclose()

    @property
    def cache_size(self) -> int:
        """Entradas atuais no cache do registry."""
        return self.cache.size


# ==========================================================
# Helpers
# ==========================================================


def _encode_package_name(name: str) -> str:
    """Escapa ``@scope/name`` para uso em path de URL (form ``@scope%2Fname``)."""
    cleaned = (name or "").strip()
    if not cleaned:
        raise PackageNotFound("Nome de pacote vazio.")
    if cleaned.startswith("@") and "/" in cleaned:
        scope, _, bare = cleaned.partition("/")
        return f"{scope}%2F{bare}"
    return cleaned.replace(" ", "%20")


def _ceiling_of(raw_range: str) -> tuple[int, int, int, int] | None:
    """Extrai o teto (``<X``) de um range composto como ``>=1.2.0 <2.0.0``."""
    import re

    match = re.search(r"<\s*(\d+(?:\.\d+){0,2})", raw_range)
    if not match:
        return None
    return version_tuple(match.group(1))


def _clean_repo_url(url: str) -> str:
    """Normaliza ``git+https://github.com/o/r.git`` para ``https://github.com/o/r``."""
    cleaned = url
    for prefix in ("git+", "git://", "git:"):
        if cleaned.startswith(prefix):
            cleaned = cleaned[len(prefix) :]
    if cleaned.startswith("git@github.com:"):
        cleaned = "https://github.com/" + cleaned.split(":", 1)[1]
    if cleaned.endswith(".git"):
        cleaned = cleaned[: -len(".git")]
    return cleaned
