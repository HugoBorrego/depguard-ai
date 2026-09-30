"""Cliente do GitHub (async): valida URL, descobre a branch padrão e busca os ``package.json``."""

from __future__ import annotations

import asyncio
import posixpath
from typing import Any, Final

from app.core.config import Settings, get_settings
from app.core.http_client import ExternalServiceError, HttpClient
from app.core.logging_config import get_logger
from app.core.security import GitHubRepoRef, parse_github_url
from app.schemas.enums import SourceFile

logger = get_logger("github")

#: Subpastas comuns de monorepos, priorizadas na descoberta.
MONOREPO_PREFIXES: Final[frozenset[str]] = frozenset(
    {
        "packages",
        "apps",
        "libs",
        "services",
        "modules",
        "backend",
        "frontend",
        "api",
        "web",
        "client",
        "server",
    }
)

#: Diretórios ignorados ao varrer a árvore.
IGNORED_DIRS: Final[frozenset[str]] = frozenset(
    {"node_modules", "dist", "build", "out", "coverage", "vendor", ".cache", "fixtures", "examples"}
)

#: Profundidade máxima aceita para um manifesto (``a/b/package.json``).
MAX_MANIFEST_DEPTH: Final[int] = 3

#: Manifestos analisados no máximo em um monorepo (protege tempo/custo de LLM).
MAX_MANIFESTS: Final[int] = 5

#: Manifestos baixados em paralelo.
DOWNLOAD_CONCURRENCY: Final[int] = 4

#: Teto de candidatos vindos da Git Trees API, antes do filtro por
#: subpasta Interesting. Repositórios muito grandes (monorepos) podem ter
#: milhares de ``package.json``; sem esse limite a resposta inteira seria
#: baixada da API para, no fim, usarmos no máximo ``MAX_MANIFESTS``.
MAX_TREE_CANDIDATES: Final[int] = 40

#: Manifestos baixados em paralelo na varredura ampla.
SCAN_CONCURRENCY: Final[int] = 6


class GitHubError(RuntimeError):
    """Falha ao interagir com o GitHub."""

    def __init__(self, message: str, *, status_code: int | None = None, hint: str | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.hint = hint


class GitHubPackageNotFound(GitHubError):
    """O repositório existe mas não contém nenhum package.json analisável."""


class GitHubClient:
    """Encapsula as chamadas à API do GitHub usadas pelo DepGuard.

    Quando ``GITHUB_TOKEN`` está configurado, o rate limit sobe de 60 para
    5000 requisições/hora e repositórios privados passam a funcionar.
    """

    def __init__(
        self,
        http: HttpClient | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.http = http or HttpClient()
        self.settings = settings or get_settings()

    # ------------------------------------------------------------ headers
    def _headers(self, *, raw: bool = False) -> dict[str, str]:
        """Headers padrão, com ``Authorization`` opcional e modo texto puro."""
        headers: dict[str, str] = {
            "Accept": "application/vnd.github.raw+json" if raw else "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.settings.github_token:
            headers["Authorization"] = f"Bearer {self.settings.github_token}"
        return headers

    @property
    def authenticated(self) -> bool:
        """Indica se há token configurado (rate limit 5000/h em vez de 60/h)."""
        return bool(self.settings.github_token)

    # ------------------------------------------------------------ repo
    async def get_repo_info(self, ref: GitHubRepoRef) -> dict[str, Any]:
        """Metadados do repositório, incluindo a branch padrão."""
        try:
            data = await self.http.request_json("GET", ref.api_base, headers=self._headers(), service="github")
        except ExternalServiceError as exc:
            if exc.status_code == 404:
                raise GitHubError(
                    f"Repositório '{ref.full_name}' não encontrado, é privado ou foi removido.",
                    status_code=404,
                    hint="Confira a URL ou defina GITHUB_TOKEN para acessar repositórios privados.",
                ) from exc
            raise GitHubError(f"Não foi possível consultar o repositório: {exc}") from exc

        if not isinstance(data, dict):
            raise GitHubError("Resposta inesperada da API do GitHub.")
        return data

    async def get_default_branch(self, ref: GitHubRepoRef) -> str:
        """Branch padrão do repositório (``main``, ``master``, etc.)."""
        info = await self.get_repo_info(ref)
        branch = info.get("default_branch")
        if not isinstance(branch, str) or not branch:
            raise GitHubError("A API do GitHub não informou a branch padrão do repositório.")
        return branch

    # ------------------------------------------------------------ arquivos
    async def get_raw_text(self, ref: GitHubRepoRef, path: str, branch: str) -> str | None:
        """Baixa um arquivo como texto puro, ou ``None`` se não existir (404)."""
        clean = posixpath.normpath(path).lstrip("/")
        url = f"{ref.api_base}/contents/{clean}?ref={branch}"
        try:
            return await self.http.request_text("GET", url, headers=self._headers(raw=True), service="github")
        except ExternalServiceError as exc:
            if exc.status_code == 404:
                return None
            raise GitHubError(f"Erro ao baixar '{clean}': {exc}") from exc

    # ------------------------------------------------------------ descoberta
    async def list_manifest_candidates(self, ref: GitHubRepoRef, branch: str) -> list[str]:
        """Lista caminhos candidatos de ``package.json`` via Git Trees API (1 requisição)."""
        url = f"{ref.api_base}/git/trees/{branch}?recursive=1"
        try:
            data = await self.http.request_json("GET", url, headers=self._headers(), service="github")
        except ExternalServiceError as exc:
            logger.debug("Git Trees API indisponível (%s); mantendo apenas a raiz.", exc)
            return []

        if not isinstance(data, dict) or not isinstance(data.get("tree"), list):
            return []

        candidates: list[str] = []
        for entry in data["tree"]:
            if not isinstance(entry, dict):
                continue
            if entry.get("type") != "blob":
                continue
            path = entry.get("path")
            if not isinstance(path, str) or posixpath.basename(path) != "package.json":
                continue
            if _is_interesting_path(path):
                candidates.append(path)
            if len(candidates) >= MAX_TREE_CANDIDATES:  # trava de segurança
                break
        return candidates

    async def find_manifests(
        self,
        url_or_ref: str | GitHubRepoRef,
        *,
        max_manifests: int = MAX_MANIFESTS,
    ) -> tuple[GitHubRepoRef, str, list[SourceFile]]:
        """Localiza os ``package.json`` de um repositório.

        Estratégia: raiz primeiro; se a raiz não tiver dependências, varre a
        árvore e baixa até ``max_manifests`` subpastas em paralelo.

        Returns:
            ``(ref, branch_padrao, manifests)``

        Raises:
            GitHubError: repositório inexistente ou inacessível.
            GitHubPackageNotFound: nenhum package.json utilizável encontrado.
        """
        ref = url_or_ref if isinstance(url_or_ref, GitHubRepoRef) else parse_github_url(url_or_ref)
        branch = await self.get_default_branch(ref)

        root_text = await self.get_raw_text(ref, "package.json", branch)
        if root_text and _has_dependencies(root_text):
            root = _build_source_file(ref, branch, "package.json", is_monorepo_root=True, size=len(root_text))
            return ref, branch, [root]

        # A raiz existe mas não declara dependências: pode ser um monorepo.
        if root_text and root_text.strip():
            subpackages = await self._scan_subpackages(ref, branch, max_manifests=max_manifests)
            if subpackages:
                root = _build_source_file(ref, branch, "package.json", is_monorepo_root=True, size=len(root_text))
                return ref, branch, [root, *subpackages][:max_manifests]

        subpackages = await self._scan_subpackages(ref, branch, max_manifests=max_manifests)
        if not subpackages:
            raise GitHubPackageNotFound(
                f"Nenhum package.json com dependências encontrado em '{ref.full_name}' (branch '{branch}').",
                hint="O repositório pode não ser um projeto Node.js, ou as dependências podem estar em subpastas fora do padrão.",
            )
        return ref, branch, subpackages

    async def _scan_subpackages(
        self,
        ref: GitHubRepoRef,
        branch: str,
        *,
        max_manifests: int,
    ) -> list[SourceFile]:
        """Baixa em paralelo os candidatos e devolve apenas os que têm dependências."""
        candidates = await self.list_manifest_candidates(ref, branch)
        candidates = [c for c in candidates if posixpath.normpath(c).lstrip("/") != "package.json"]
        if not candidates:
            return []

        semaphore = asyncio.Semaphore(DOWNLOAD_CONCURRENCY)

        async def fetch(path: str) -> SourceFile | None:
            async with semaphore:
                try:
                    text = await self.get_raw_text(ref, path, branch)
                except GitHubError as exc:  # pragma: no cover - defensivo
                    logger.warning("Falha ao baixar %s de %s: %s", path, ref.full_name, exc)
                    return None
            if not text or not _has_dependencies(text):
                return None
            return _build_source_file(ref, branch, path, is_monorepo_root=False, size=len(text))

        results = await asyncio.gather(*(fetch(path) for path in candidates), return_exceptions=True)
        valid = [item for item in results if isinstance(item, SourceFile)]
        # Subpastas de nível superior têm prioridade sobre as aninhadas.
        valid.sort(key=lambda s: (s.path.count("/"), s.path))
        return valid[:max_manifests]

    async def aclose(self) -> None:
        """Fecha o cliente HTTP subjacente."""
        await self.http.aclose()


# ==========================================================
# Helpers
# ==========================================================


def _build_source_file(
    ref: GitHubRepoRef,
    branch: str,
    path: str,
    *,
    is_monorepo_root: bool,
    size: int | None = None,
) -> SourceFile:
    """Monta o descriptor ``SourceFile`` com URL pública de download."""
    clean = posixpath.normpath(path).lstrip("/")
    return SourceFile(
        path=clean,
        url=f"{ref.raw_base}/{branch}/{clean}",
        is_monorepo_root=is_monorepo_root,
        size_bytes=size,
    )


def _has_dependencies(text: str) -> bool:
    """``True`` se o texto parece um manifest com alguma seção de dependências."""
    stripped = text.lstrip("﻿ \n\r\t")
    if not stripped.startswith("{"):
        return False
    return any(
        f'"{key}"' in text
        for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies")
    )


def _is_interesting_path(path: str) -> bool:
    """Filtra ``package.json`` relevantes (ignora node_modules, build, fixtures)."""
    normalized = path.lower()
    if any(f"/{d}/" in normalized or normalized.startswith(f"{d}/") for d in IGNORED_DIRS):
        return False
    parts = path.split("/")
    if len(parts) > MAX_MANIFEST_DEPTH:
        return False
    if len(parts) == 1:
        return True
    if parts[0] in MONOREPO_PREFIXES:
        return True
    # Outros diretórios só entram com um nível de profundidade.
    return len(parts) == 2
