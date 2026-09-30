"""Serviços do DepGuard AI (I/O externo, regras e análise)."""

from app.services.analyzer import (
    PROGRESS_STEPS,
    STEP_AI,
    STEP_DONE,
    STEP_OSV,
    STEP_READING,
    STEP_REGISTRY,
    STEP_RULES,
    AnalysisError,
    DependencyAnalyzer,
)
from app.services.github import GitHubClient, GitHubError, GitHubPackageNotFound
from app.services.llm_analyzer import LLMAnalyzer, LLMNotConfiguredError
from app.services.npm_registry import NpmRegistryClient
from app.services.osv import OsvClient
from app.services.package_parser import (
    PackageJsonParseError,
    ParsedDependency,
    ParsedPackageJson,
    parse_package_json,
)
from app.services.rules import DependencyContext, apply_rules

__all__ = [
    "PROGRESS_STEPS",
    "STEP_AI",
    "STEP_DONE",
    "STEP_OSV",
    "STEP_READING",
    "STEP_REGISTRY",
    "STEP_RULES",
    "AnalysisError",
    "DependencyAnalyzer",
    "DependencyContext",
    "GitHubClient",
    "GitHubError",
    "GitHubPackageNotFound",
    "LLMAnalyzer",
    "LLMNotConfiguredError",
    "NpmRegistryClient",
    "OsvClient",
    "PackageJsonParseError",
    "ParsedDependency",
    "ParsedPackageJson",
    "apply_rules",
    "parse_package_json",
]
