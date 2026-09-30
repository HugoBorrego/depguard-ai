"""Configuração de logging.

Regra de ouro: nenhum log pode conter a ``ANTHROPIC_API_KEY`` ou o ``GITHUB_TOKEN``.
"""

from __future__ import annotations

import logging
import sys

_CONFIGURED = False

_SENSITIVE_HINTS = (
    "anthropic_api_key",
    "github_token",
    "x-api-key",
    "authorization",
)


class _RedactingFilter(logging.Filter):
    """Redige segredos que porventura apareçam em mensagens de log."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # pragma: no cover - defensivo
            return True
        lowered = message.lower()
        if any(hint in lowered for hint in _SENSITIVE_HINTS):
            record.msg = "[log redigido: possível credencial na mensagem]"
            record.args = ()
        return True


def setup_logging(level: str = "INFO") -> None:
    """Configura o logging raiz uma única vez."""
    global _CONFIGURED
    if _CONFIGURED:
        return

    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    handler.addFilter(_RedactingFilter())

    root = logging.getLogger()
    root.setLevel(level.upper())
    root.handlers = [handler]

    # Bibliotecas ruidosas
    for noisy in ("httpx", "httpcore", "urllib3", "anthropic", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """Retorna um logger nomeado sob o namespace ``depguard``."""
    return logging.getLogger(f"depguard.{name}")
