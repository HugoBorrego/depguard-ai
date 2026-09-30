"""Cliente HTTP compartilhado: timeouts, retry com backoff, cache TTL e semáforo."""

from __future__ import annotations

import asyncio
import random
import time
from types import TracebackType
from typing import Any, Final, Self

import httpx

from app.core.config import Settings, get_settings
from app.core.logging_config import get_logger

logger = get_logger("http")

# Códigos que valem a pena repetir (rate limit e erros transitórios de infra).
RETRYABLE_STATUS: Final[frozenset[int]] = frozenset({408, 425, 429, 500, 502, 503, 504})

# Erros de conexão que valem a pena repetir.
RETRYABLE_EXC: Final[tuple[type[Exception], ...]] = (
    httpx.ConnectError,
    httpx.ConnectTimeout,
    httpx.ReadTimeout,
    httpx.WriteTimeout,
    httpx.PoolTimeout,
    httpx.RemoteProtocolError,
)


class TTLCache:
    """Cache em memória com TTL, seguro para uso concorrente (asyncio)."""

    def __init__(self, ttl_seconds: int, max_entries: int = 2048, enabled: bool = True) -> None:
        self.ttl = max(0, ttl_seconds)
        self.max_entries = max_entries
        self.enabled = enabled
        self._store: dict[str, tuple[float, Any]] = {}
        self._lock = asyncio.Lock()
        self.hits = 0
        self.misses = 0

    async def get(self, key: str) -> Any | None:
        """Retorna o valor cacheado ou ``None`` (miss/expirado)."""
        if not self.enabled or self.ttl == 0:
            return None
        async with self._lock:
            entry = self._store.get(key)
            if entry is None:
                self.misses += 1
                return None
            stored_at, value = entry
            if time.monotonic() - stored_at > self.ttl:
                del self._store[key]
                self.misses += 1
                return None
            self.hits += 1
            return value

    async def set(self, key: str, value: Any) -> None:
        """Grava um valor respetando o limite de entradas (evita crescimento sem fim)."""
        if not self.enabled or self.ttl == 0:
            return
        async with self._lock:
            if len(self._store) >= self.max_entries:
                # Evicção do mais antigo (FIFO) — suficiente para uso de leitura.
                oldest_key = next(iter(self._store))
                self._store.pop(oldest_key, None)
            self._store[key] = (time.monotonic(), value)

    def clear(self) -> None:
        """Esvazia o cache (usado nos testes)."""
        self._store.clear()
        self.hits = 0
        self.misses = 0

    @property
    def size(self) -> int:
        """Número de entradas atualmente armazenadas."""
        return len(self._store)


class Semaphore:
    """Semáforo simples e nomeado, para limitar concorrência por serviço."""

    def __init__(self, limit: int) -> None:
        self.limit = max(1, limit)
        self._sem = asyncio.Semaphore(self.limit)
        self.in_flight = 0
        self.max_observed = 0

    async def __aenter__(self) -> Semaphore:
        await self._sem.acquire()
        self.in_flight += 1
        self.max_observed = max(self.max_observed, self.in_flight)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.in_flight = max(0, self.in_flight - 1)
        self._sem.release()

    @property
    def available(self) -> int:
        """Permissões disponíveis no momento."""
        return self._sem._value


class ExternalServiceError(RuntimeError):
    """Falha ao consultar um serviço externo após todos os retries."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class HttpClient:
    """Wrapper em torno do ``httpx.AsyncClient`` com retry e backoff exponencial."""

    def __init__(self, settings: Settings | None = None, *, client: httpx.AsyncClient | None = None) -> None:
        self.settings = settings or get_settings()
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(self.settings.http_timeout_seconds, connect=8.0),
            follow_redirects=True,
            headers={"Accept": "application/json", "User-Agent": "DepGuard-AI/1.0"},
            limits=httpx.Limits(max_connections=40, max_keepalive_connections=20),
        )

    async def aclose(self) -> None:
        """Fecha o client se ele foi criado por esta instância."""
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    async def _send(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None,
        json_body: Any,
        service: str,
        allow_status: frozenset[int] = frozenset(),
    ) -> httpx.Response:
        """Executa a requisição com retry/backoff e devolve a resposta bem-sucedida.

        ``allow_status`` devolve a resposta mesmo com status fora da faixa 2xx
        (usado pelo GitHub para detectar 404 sem retry).

        Raises:
            ExternalServiceError: em erro permanente ou após esgotar os retries.
        """
        attempt = 0
        last_error: str = "desconhecido"
        last_status: int | None = None

        while attempt <= self.settings.http_max_retries:
            attempt += 1
            try:
                response = await self._client.request(method, url, headers=headers, json=json_body)
                last_status = response.status_code

                if response.status_code in allow_status:
                    return response

                if response.status_code in RETRYABLE_STATUS:
                    last_error = f"HTTP {response.status_code}"
                    if attempt > self.settings.http_max_retries:
                        break
                    await self._sleep_backoff(attempt, retry_after=_parse_retry_after(response))
                    continue

                if response.status_code == 404:
                    raise ExternalServiceError("Recurso não encontrado (404).", status_code=404)

                if response.is_error:
                    raise ExternalServiceError(
                        f"Erro {response.status_code} em {service}: {response.text[:200]}",
                        status_code=response.status_code,
                    )
                return response

            except ExternalServiceError:
                raise
            except RETRYABLE_EXC as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                if attempt > self.settings.http_max_retries:
                    break
                await self._sleep_backoff(attempt)
            except Exception as exc:
                raise ExternalServiceError(
                    f"Falha inesperada em {service}: {type(exc).__name__}: {exc}"
                ) from exc

        logger.warning("%s falhou após %s tentativa(s): %s", service, attempt, last_error)
        raise ExternalServiceError(
            f"{service} indisponível após {attempt} tentativa(s): {last_error}",
            status_code=last_status,
        )

    async def request_json(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        json_body: Any = None,
        service: str = "http",
    ) -> Any:
        """Executa uma requisição e devolve o JSON decodificado (``None`` se corpo vazio)."""
        response = await self._send(
            method, url, headers=headers, json_body=json_body, service=service
        )
        if not response.content:
            return None
        try:
            return response.json()
        except ValueError as exc:
            raise ExternalServiceError(f"Resposta não-JSON inválida de {service}.") from exc

    async def request_text(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        service: str = "http",
    ) -> str | None:
        """Executa uma requisição e devolve o corpo como texto (``None`` se vazio)."""
        response = await self._send(method, url, headers=headers, json_body=None, service=service)
        if not response.content:
            return None
        return response.text

    async def post_json(
        self,
        url: str,
        *,
        json_body: Any,
        headers: dict[str, str] | None = None,
        service: str = "http",
    ) -> Any:
        """Atalho para ``POST`` com corpo JSON."""
        return await self.request_json(
            "POST", url, headers=headers, json_body=json_body, service=service
        )

    async def _sleep_backoff(self, attempt: int, retry_after: float | None = None) -> None:
        """Dorme com backoff exponencial + jitter, ou respeita ``Retry-After``."""
        if retry_after is not None:
            delay = min(retry_after, 10.0)
        else:
            delay = min(0.4 * (2 ** (attempt - 1)), 8.0)
            delay += random.uniform(0, 0.2)  # jitter
        await asyncio.sleep(delay)


def _parse_retry_after(response: httpx.Response) -> float | None:
    """Lê o header ``Retry-After`` (segundos) quando presente e válido."""
    raw = response.headers.get("Retry-After")
    if not raw:
        return None
    try:
        value = float(raw)
    except ValueError:
        return None
    if value < 0:
        return None
    return value
