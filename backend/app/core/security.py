"""Validações de segurança: anti-SSRF, validação de upload e rate limiting."""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any, Final
from urllib.parse import unquote, urlparse

from pydantic import BaseModel, Field, ValidationError, field_validator

from app.core.config import Settings, get_settings
from app.core.logging_config import get_logger

logger = get_logger("security")

# ==========================================================
# Anti-SSRF: só github.com é aceito
# ==========================================================

ALLOWED_GITHUB_HOSTS: Final[frozenset[str]] = frozenset({"github.com", "www.github.com"})

# Nomes de usuário e repositórios no GitHub:
#   usuário: alfanuméricos, hífen, underscore (máx. 39)
#   repo:    qualquer caractere permitido em nomes de repo exceto espaço e ponto
_GITHUB_OWNER_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-_]{0,38})$")
_GITHUB_REPO_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9._-]{1,100}$")

# Hosts de metadados / rede interna que jamais podem ser alcançados.
_BLOCKED_HOSTNAMES: Final[frozenset[str]] = frozenset(
    {
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "::1",
        "169.254.169.254",  # AWS/GCP/Azure instance metadata
        "metadata.google.internal",
        "metadata.goog",
        "instance-data",
    }
)


class GitHubRepoRef(BaseModel):
    """Referência normalizada e validada a um repositório público do GitHub."""

    owner: str
    repo: str
    url: str

    @property
    def full_name(self) -> str:
        """``owner/repo``."""
        return f"{self.owner}/{self.repo}"

    @property
    def api_base(self) -> str:
        """Base da API do GitHub para este repositório."""
        return f"https://api.github.com/repos/{self.owner}/{self.repo}"

    @property
    def raw_base(self) -> str:
        """Base do ``raw.githubusercontent.com`` para este repositório."""
        return f"https://raw.githubusercontent.com/{self.owner}/{self.repo}"


class InvalidGitHubUrlError(ValueError):
    """URL de GitHub inválida, apontando para host não permitido ou malformada."""


def _reject_embedded_credentials(url: str) -> None:
    """Recusa ``user:pass@`` e esquemas perigosos embutidos na URL."""
    if "@" in url.split("://", 1)[-1].split("/", 1)[0]:
        raise InvalidGitHubUrlError("URL não pode conter credenciais embutidas.")


def _assert_public_host(hostname: str) -> None:
    """Garante que o hostname é público (bloqueia loopback, link-local e privados)."""
    if not hostname:
        raise InvalidGitHubUrlError("URL sem hostname.")

    lowered = hostname.lower().strip(".")
    if lowered in _BLOCKED_HOSTNAMES:
        raise InvalidGitHubUrlError(f"Host não permitido: {hostname}")

    # Se parecer com um IP, validamos o endereço diretamente.
    candidate = hostname.strip("[]")
    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError:
        ip = None
    if ip is not None and (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    ):
        raise InvalidGitHubUrlError(f"Endereço IP não público: {hostname}")


def parse_github_url(raw_url: str) -> GitHubRepoRef:
    """Valida e extrai ``owner``/``repo`` de uma URL do GitHub.

    Aceita apenas ``https://github.com/owner/repo`` (com ``/`` opcional e
    variantes de query/fragmento/``.git``). Qualquer outro host é rejeitado,
    o que fecha o vetor de SSRF.
    """
    if not raw_url or not isinstance(raw_url, str):
        raise InvalidGitHubUrlError("URL vazia.")

    url = raw_url.strip()
    if len(url) > 300:
        raise InvalidGitHubUrlError("URL muito longa (máx. 300 caracteres).")

    _reject_embedded_credentials(url)

    parsed = urlparse(url)
    scheme = parsed.scheme.lower()

    # Aceitamos https (e http, convertido), mas nunca outros esquemas
    # (file://, gopher://, dict://, data:...). Sem esquema assumimos https.
    if scheme == "":
        url = f"https://{url}"
        parsed = urlparse(url)
        scheme = "https"
    if scheme not in {"https", "http"}:
        raise InvalidGitHubUrlError(f"Esquema não permitido: {scheme}")
    if scheme == "http":
        raise InvalidGitHubUrlError("Use https:// nas URLs do GitHub.")

    hostname = parsed.hostname or ""
    if hostname.lower() not in ALLOWED_GITHUB_HOSTS:
        raise InvalidGitHubUrlError(
            "Apenas repositórios em github.com são aceitos "
            f"(recebido: {hostname or 'host vazio'})."
        )
    _assert_public_host(hostname)

    # segmenta o path: /owner/repo(/...)?
    segments = [unquote(seg) for seg in parsed.path.split("/") if seg]
    if len(segments) < 2:
        raise InvalidGitHubUrlError(
            "URL incompleta. Use o formato https://github.com/usuario/repositorio"
        )

    owner, repo = segments[0], segments[1]
    if repo.endswith(".git"):
        repo = repo[: -len(".git")]

    if not _GITHUB_OWNER_RE.match(owner):
        raise InvalidGitHubUrlError(f"Nome de usuário inválido: {owner!r}")
    if not _GITHUB_REPO_RE.match(repo):
        raise InvalidGitHubUrlError(f"Nome de repositório inválido: {repo!r}")

    canonical = f"https://github.com/{owner}/{repo}"
    return GitHubRepoRef(owner=owner, repo=repo, url=canonical)


# ==========================================================
# Validação do upload
# ==========================================================

MAX_MANIFEST_DEPTH: Final[int] = 12


class InvalidPackageJsonError(ValueError):
    """O conteúdo enviado não é um ``package.json`` utilizável."""


#: Seções de dependência reconhecidas em um ``package.json``.
DEPENDENCY_SECTIONS: Final[tuple[str, ...]] = (
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
)


def _validate_dependency_sections(manifest: dict[str, Any]) -> None:
    """Garante que cada seção de dependências é um mapa ``nome -> versão``.

    Feito na fronteira (antes de gastar chamadas de API) para devolver um erro
    claro ao usuário em vez de uma exceção no meio da análise.
    """
    for section in DEPENDENCY_SECTIONS:
        if section not in manifest:
            continue
        value = manifest[section]
        if value is None:
            continue
        if not isinstance(value, dict):
            raise ValueError(
                f"\"{section}\" precisa ser um objeto JSON com pacote:versão "
                f"(recebido: {type(value).__name__})."
            )
        for package, spec in value.items():
            if not isinstance(package, str) or not package.strip():
                raise ValueError(f"\"{section}\" contém um nome de pacote vazio ou inválido.")
            if not isinstance(spec, str):
                raise ValueError(
                    f"A versão de \"{package}\" em \"{section}\" deve ser uma string "
                    f"(recebido: {type(spec).__name__})."
                )


class PackageJsonUpload(BaseModel):
    """Envelope do ``package.json`` recebido via upload."""

    filename: str = Field(default="package.json", max_length=120)
    size_bytes: int = Field(ge=0)
    content: str

    @field_validator("content")
    @classmethod
    def _must_be_json_object(cls, value: str) -> str:
        stripped = value.lstrip("\ufeff").strip()
        if not stripped:
            raise ValueError("Arquivo vazio.")
        if len(stripped) > 2_000_000:
            raise ValueError("Conteúdo grande demais para processar.")
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"JSON inválido (linha {exc.lineno}, coluna {exc.colno}): {exc.msg}"
            ) from exc
        if not isinstance(parsed, dict):
            raise ValueError("O package.json precisa ser um objeto JSON.")
        _validate_dependency_sections(parsed)
        return stripped

    def parsed(self) -> dict:
        """Devolve o dicionário já validado."""
        return json.loads(self.content)  # type: ignore[no-any-return]


def validate_upload(filename: str, raw: bytes, settings: Settings | None = None) -> PackageJsonUpload:
    """Valida tamanho, encoding e formato de um ``package.json`` enviado.

    Raises:
        InvalidPackageJsonError: arquivo inválido, grande demais ou não-JSON.
    """
    cfg = settings or get_settings()

    if not raw:
        raise InvalidPackageJsonError("Arquivo vazio.")

    if len(raw) > cfg.max_upload_bytes:
        max_mb = cfg.max_upload_bytes / 1_048_576
        raise InvalidPackageJsonError(
            f"Arquivo muito grande: {len(raw) / 1_048_576:.2f} MB (máximo {max_mb:.0f} MB)."
        )

    # Detecta o nome do arquivo e exige cara de package.json
    safe_name = (filename or "package.json").replace("\\", "/").split("/")[-1]
    if safe_name.lower() not in {"package.json", "package-lock.json.bak"}:
        raise InvalidPackageJsonError(
            f"Arquivo inválido: envie um 'package.json' (recebido: {safe_name})."
        )

    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise InvalidPackageJsonError("Arquivo não está em UTF-8 válido.") from exc

    try:
        return PackageJsonUpload(filename=safe_name, size_bytes=len(raw), content=text)
    except ValidationError as exc:
        messages = "; ".join(
            f"{'.'.join(str(p) for p in err['loc'])}: {err['msg']}" for err in exc.errors()
        )
        raise InvalidPackageJsonError(messages) from exc


# ==========================================================
# Rate limiting
# ==========================================================

# Limite textual, usado como fallback quando o IP não pôde ser resolvido.
UNKNOWN_CLIENT_KEY: Final[str] = "unknown"

# Cabeçalhos que proxies usam para repassar o IP real do cliente.
_TRUSTED_CLIENT_HEADERS: Final[tuple[str, ...]] = (
    "x-forwarded-for",
    "x-real-ip",
    "cf-connecting-ip",
    "true-client-ip",
)


def client_identifier(request) -> str:
    """Extrai o identificador do cliente respeitando headers de proxy.

    Só usamos o primeiro IP da cadeia ``X-Forwarded-For`` (o cliente original).
    """
    for header in _TRUSTED_CLIENT_HEADERS:
        raw = request.headers.get(header)
        if raw:
            first = raw.split(",")[0].strip()
            if first:
                return first
    return getattr(request.client, "host", None) or UNKNOWN_CLIENT_KEY


class RateLimiter:
    """Rate limiting por IP, in-memory, com janela deslizante simples.

    O ``slowapi`` (usado nos routers via ``Limiter``) cobre o caso geral; esta
    classe é usada como segunda camada, mais previsível, nos endpoints de análise.
    """

    def __init__(self, limit_per_minute: int) -> None:
        self.limit = max(1, limit_per_minute)
        self._hits: dict[str, list[float]] = {}

    def check(self, key: str) -> tuple[bool, int]:
        """Registra um acesso e retorna ``(permitido, segundos_para_liberar)``."""
        import time

        now = time.monotonic()
        window = 60.0
        hits = [t for t in self._hits.get(key, []) if now - t < window]
        self._hits[key] = hits

        if len(hits) >= self.limit:
            oldest = hits[0]
            retry_after = max(1, int(window - (now - oldest)))
            return False, retry_after

        hits.append(now)
        return True, 0

    def reset(self) -> None:
        """Limpa o estado (usado nos testes)."""
        self._hits.clear()
