"""Schemas Pydantic v2 do DepGuard AI."""

from app.schemas.enums import (
    SEVERITY_ORDER,
    SEVERITY_RANK,
    BreakingRisk,
    DependencyKind,
    IssueSource,
    IssueType,
    Severity,
    SourceFile,
)
from app.schemas.llm import (
    LLMAnalysisResult,
    LLMDependencyItem,
    LLMFinding,
    LLMIssue,
    LLMVulnerabilityItem,
)
from app.schemas.report import (
    AnalysisMeta,
    AnalysisReport,
    DependencyFinding,
    HealthResponse,
    Issue,
    ProjectInfo,
    Summary,
)
from app.schemas.requests import AnalyzeGitHubRequest

__all__ = [
    "SEVERITY_ORDER",
    "SEVERITY_RANK",
    "AnalysisMeta",
    "AnalysisReport",
    "AnalyzeGitHubRequest",
    "BreakingRisk",
    "DependencyFinding",
    "DependencyKind",
    "HealthResponse",
    "Issue",
    "IssueSource",
    "IssueType",
    "LLMAnalysisResult",
    "LLMDependencyItem",
    "LLMFinding",
    "LLMIssue",
    "LLMVulnerabilityItem",
    "ProjectInfo",
    "Severity",
    "SourceFile",
    "Summary",
]
