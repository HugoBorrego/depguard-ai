/** Funções puras de apresentação: severidade, datas, filtros e ordenação. */

import type {
  AnalysisReport,
  DependencyFinding,
  IssueSource,
  IssueType,
  Severity,
  BreakingRisk,
} from "@/types/api";
import { SEVERITY_ORDER, SOURCE_LABELS } from "@/types/api";

// ==========================================================
// Severidade
// ==========================================================

export interface SeverityStyle {
  label: string;
  /** Classes do badge (fundo/texto/borda) para o tema claro e escuro. */
  badge: string;
  /** Classes da barra/barra de progresso. */
  bar: string;
  /** Cor de texto para listas e números. */
  text: string;
}

export const SEVERITY_STYLES: Record<Severity, SeverityStyle> = {
  critical: {
    label: "Crítico",
    badge:
      "bg-critical-100 text-critical-700 ring-critical-300 dark:bg-critical-900/40 dark:text-critical-300 dark:ring-critical-700",
    bar: "bg-critical-500",
    text: "text-critical-600 dark:text-critical-400",
  },
  high: {
    label: "Alto",
    badge:
      "bg-high-100 text-high-700 ring-high-300 dark:bg-high-900/40 dark:text-high-300 dark:ring-high-700",
    bar: "bg-high-500",
    text: "text-high-600 dark:text-high-400",
  },
  medium: {
    label: "Médio",
    badge:
      "bg-medium-100 text-medium-700 ring-medium-300 dark:bg-medium-900/40 dark:text-medium-300 dark:ring-medium-700",
    bar: "bg-medium-500",
    text: "text-medium-600 dark:text-medium-400",
  },
  low: {
    label: "Baixo",
    badge:
      "bg-low-100 text-low-700 ring-low-300 dark:bg-low-900/40 dark:text-low-300 dark:ring-low-700",
    bar: "bg-low-500",
    text: "text-low-600 dark:text-low-400",
  },
  ok: {
    label: "Ok",
    badge:
      "bg-ok-100 text-ok-700 ring-ok-300 dark:bg-ok-900/40 dark:text-ok-300 dark:ring-ok-700",
    bar: "bg-ok-500",
    text: "text-ok-600 dark:text-ok-400",
  },
};

export const BREAKING_RISK_STYLES: Record<BreakingRisk, string> = {
  low: "text-ok-600 dark:text-ok-400",
  medium: "text-medium-600 dark:text-medium-400",
  high: "text-critical-600 dark:text-critical-400",
};

export const BREAKING_RISK_LABELS: Record<BreakingRisk, string> = {
  low: "Baixo",
  medium: "Médio",
  high: "Alto",
};

/** Compara duas severidades (pior primeiro). */
export function compareSeverity(a: Severity, b: Severity): number {
  return SEVERITY_ORDER[a] - SEVERITY_ORDER[b];
}

// ==========================================================
// Rótulos
// ==========================================================

export const ISSUE_SOURCE_LABELS: Record<IssueSource, string> = SOURCE_LABELS;

export const ISSUE_TYPE_ICONS: Record<IssueType, string> = {
  vulnerability: "⚠",
  deprecated: "⛔",
  not_found: "✕",
  outdated: "↓",
  unmaintained: "⏳",
  suspicious: "🔍",
  loose_range: "≈",
  prerelease: "🧪",
  engine_conflict: "🔌",
};

export const SECTION_LABELS: Record<string, string> = {
  dependencies: "runtime",
  devDependencies: "dev",
  peerDependencies: "peer",
  optionalDependencies: "opcional",
};

/** Estilo do badge que identifica a origem de um achado. */
export const SOURCE_BADGE_STYLES: Record<IssueSource, string> = {
  osv: "bg-purple-100 text-purple-700 dark:bg-purple-900/40 dark:text-purple-300",
  npm_registry: "bg-sky-100 text-sky-700 dark:bg-sky-900/40 dark:text-sky-300",
  regra_local:
    "bg-slate-100 text-slate-700 dark:bg-slate-700/50 dark:text-slate-300",
  analise_ia:
    "bg-indigo-100 text-indigo-700 dark:bg-indigo-900/40 dark:text-indigo-300",
};

// ==========================================================
// Datas e números
// ==========================================================

/** Formata uma data ISO como "há 3 meses" (ou "-" quando ausente/inválida). */
export function formatRelativeDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "—";

  const seconds = Math.floor((Date.now() - date.getTime()) / 1000);
  if (seconds < 0) return "no futuro";
  if (seconds < 60) return "agora há pouco";

  const units: ReadonlyArray<[number, string]> = [
    [60, "minuto"],
    [60, "hora"],
    [24, "dia"],
    [7, "semana"],
    [4.348, "mês"],
    [12, "ano"],
  ];

  let value = seconds;
  let unit = "segundo";
  for (const [step, name] of units) {
    if (Math.abs(value) < step) {
      unit = name;
      break;
    }
    value = Math.floor(value / step);
    unit = name;
  }
  const label = value === 1 ? unit : `${unit}s`;
  return `há ${value} ${label}`;
}

/** Formata uma data ISO curta (dd/mm/aaaa). */
export function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleDateString("pt-BR", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
  });
}

/** Formata millissegundos de forma legível. */
export function formatDuration(ms: number): string {
  if (ms < 1000) return `${Math.round(ms)} ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1).replace(".", ",")} s`;
  const minutes = Math.floor(ms / 60_000);
  const seconds = Math.round((ms % 60_000) / 1000);
  return `${minutes} min ${seconds} s`;
}

/** Formata número grande de downloads (1.2M, 850k). */
export function formatDownloads(value: number | null | undefined): string {
  if (value === null || value === undefined) return "—";
  if (value >= 1_000_000)
    return `${(value / 1_000_000).toFixed(1).replace(".", ",")}M/semana`;
  if (value >= 1_000)
    return `${(value / 1_000).toFixed(1).replace(".", ",")}k/semana`;
  return `${value}/semana`;
}

/** Texto curto de "quantos problemas" (plural correto em pt-BR). */
export function issueCountLabel(count: number): string {
  return count === 0
    ? "sem problemas"
    : count === 1
      ? "1 problema"
      : `${count} problemas`;
}

// ==========================================================
// Filtros e ordenação
// ==========================================================

export type SortKey = "severity" | "package" | "version" | "issues";
export type SortDirection = "asc" | "desc";

export interface FilterState {
  search: string;
  severities: Severity[];
  issueTypes: IssueType[];
  sources: IssueSource[];
  onlyDev: boolean;
  onlyRuntime: boolean;
  onlyWithIssues: boolean;
}

export const EMPTY_FILTERS: FilterState = {
  search: "",
  severities: [],
  issueTypes: [],
  sources: [],
  onlyDev: false,
  onlyRuntime: false,
  onlyWithIssues: false,
};

/** Verifica se há algum filtro ativo além da busca. */
export function hasActiveFilters(filters: FilterState): boolean {
  return (
    filters.severities.length > 0 ||
    filters.issueTypes.length > 0 ||
    filters.sources.length > 0 ||
    filters.onlyDev ||
    filters.onlyRuntime ||
    filters.onlyWithIssues
  );
}

/** Aplica busca + filtros a uma lista de dependências. */
export function filterFindings(
  findings: readonly DependencyFinding[],
  filters: FilterState,
): DependencyFinding[] {
  const term = filters.search.trim().toLowerCase();

  return findings.filter((finding) => {
    if (
      filters.severities.length > 0 &&
      !filters.severities.includes(finding.severity)
    ) {
      return false;
    }
    if (filters.onlyDev && !finding.isDevDependency) return false;
    if (filters.onlyRuntime && finding.isDevDependency) return false;
    if (filters.onlyWithIssues && finding.issues.length === 0) return false;

    if (filters.issueTypes.length > 0) {
      const types = new Set(finding.issues.map((issue) => issue.type));
      if (!filters.issueTypes.some((type) => types.has(type))) return false;
    }

    if (filters.sources.length > 0) {
      const sources = new Set(finding.issues.map((issue) => issue.source));
      if (!filters.sources.some((source) => sources.has(source))) return false;
    }

    if (term) {
      const haystack = [
        finding.package,
        finding.requestedVersion,
        finding.latestVersion ?? "",
        finding.recommendation,
        finding.description ?? "",
        ...finding.issues.map((issue) => issue.description),
      ]
        .join(" ")
        .toLowerCase();
      if (!haystack.includes(term)) return false;
    }

    return true;
  });
}

/** Ordena por uma coluna e direção. */
export function sortFindings(
  findings: readonly DependencyFinding[],
  key: SortKey,
  direction: SortDirection,
): DependencyFinding[] {
  const factor = direction === "asc" ? 1 : -1;
  const sorted = [...findings];

  sorted.sort((a, b) => {
    switch (key) {
      case "severity":
        // 'asc' = pior primeiro (ordem natural de severidade)
        return factor === 1
          ? compareSeverity(a.severity, b.severity)
          : -compareSeverity(a.severity, b.severity);
      case "package":
        return (
          factor *
          a.package.localeCompare(b.package, "pt-BR", { sensitivity: "base" })
        );
      case "version":
        return (
          factor *
          a.requestedVersion.localeCompare(b.requestedVersion, "pt-BR", {
            numeric: true,
          })
        );
      case "issues":
        return (
          factor * (a.issues.length - b.issues.length) ||
          compareSeverity(a.severity, b.severity)
        );
      default:
        return 0;
    }
  });

  return sorted;
}

/** Recalcula o sumário a partir de uma lista (para mostrar o resultado filtrado). */
export function summarize(
  findings: readonly DependencyFinding[],
): AnalysisReport["summary"] {
  const summary: AnalysisReport["summary"] = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    ok: 0,
  };
  for (const finding of findings) {
    summary[finding.severity] += 1;
  }
  return summary;
}

// ==========================================================
// Exportação
// ==========================================================

/** Gera o arquivo JSON do relatório (o que é baixado pelo botão de exportar). */
export function buildExportPayload(
  report: AnalysisReport,
  findings: readonly DependencyFinding[],
): string {
  return JSON.stringify(
    {
      ...report,
      findings,
      exportedAt: new Date().toISOString(),
      tool: { name: "DepGuard AI", kind: "analise-de-dependencias-nodejs" },
    },
    null,
    2,
  );
}

/** Nome do arquivo de exportação, com data. */
export function exportFilename(projectName: string): string {
  const safe =
    projectName.replace(/[^a-zA-Z0-9._-]/g, "-").toLowerCase() || "projeto";
  const stamp = new Date().toISOString().slice(0, 10);
  return `depguard-${safe}-${stamp}.json`;
}

/** Dispara o download de um texto como arquivo. */
export function downloadText(
  filename: string,
  content: string,
  mime = "application/json",
): void {
  const blob = new Blob([content], { type: `${mime};charset=utf-8` });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  URL.revokeObjectURL(url);
}
