/**
 * Tipos do contrato da API do DepGuard AI.
 *
 * Espelham 1:1 o `AnalysisReport` do backend (`app/schemas/report.py`).
 * Se mudar o Pydantic, mude aqui também.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "ok";

export type IssueType =
  | "vulnerability"
  | "deprecated"
  | "not_found"
  | "outdated"
  | "unmaintained"
  | "suspicious"
  | "loose_range"
  | "prerelease"
  | "engine_conflict";

export type IssueSource = "osv" | "npm_registry" | "regra_local" | "analise_ia";

export type BreakingRisk = "low" | "medium" | "high";

export type DependencySection =
  | "dependencies"
  | "devDependencies"
  | "peerDependencies"
  | "optionalDependencies";

export interface Issue {
  type: IssueType;
  description: string;
  source: IssueSource;
  references: string[];
}

export interface DependencyFinding {
  package: string;
  requestedVersion: string;
  resolvedVersion: string | null;
  latestVersion: string | null;
  severity: Severity;
  issues: Issue[];
  recommendation: string;
  breakingChangeRisk: BreakingRisk;
  section: string | null;
  description: string | null;
  latestPublishedAt: string | null;
  maintainers: string[];
  engines: Record<string, string>;
  licenses: string[];
  weeklyDownloads: number | null;
  deprecatedMessage: string | null;
  repository: string | null;
  isDevDependency: boolean;
  analyzedByAi: boolean;
  issueCount: number;
}

export interface ProjectInfo {
  name: string;
  version: string | null;
  source: "github" | "upload";
  sourceUrl: string | null;
  manifests: string[];
  totalDependencies: number;
  runtimeDependencies: number;
  devDependencies: number;
  engineNode: string | null;
  license: string | null;
}

export interface Summary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  ok: number;
}

export interface AnalysisMeta {
  analyzedAt: string;
  durationMs: number;
  aiEnabled: boolean;
  aiModel: string | null;
  aiBatches: number;
  aiFailures: number;
  npmEtagCache: number | null;
  warnings: string[];
}

export interface AnalysisReport {
  project: ProjectInfo;
  summary: Summary;
  findings: DependencyFinding[];
  meta: AnalysisMeta;
}

export interface HealthResponse {
  status: string;
  version: string;
  environment: string;
  aiEnabled: boolean;
  githubTokenConfigured: boolean;
  cacheEntries: number;
  serverTime: string;
}

export interface AnalyzeGitHubRequest {
  url: string;
}

/** Etapas do pipeline, na mesma ordem de `PROGRESS_STEPS` no backend. */
export type ProgressStep =
  | "lendo_package_json"
  | "consultando_npm"
  | "consultando_vulnerabilidades"
  | "aplicando_regras"
  | "analisando_com_ia"
  | "finalizando";

/** Ordem de severidade, do pior para o melhor (usada na ordenação). */
export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  ok: 4,
};

export const SEVERITIES: readonly Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "ok",
] as const;

export const ISSUE_TYPE_LABELS: Record<IssueType, string> = {
  vulnerability: "Vulnerabilidade",
  deprecated: "Depreciado",
  not_found: "Não encontrado",
  outdated: "Desatualizado",
  unmaintained: "Sem manutenção",
  suspicious: "Suspeito",
  loose_range: "Faixa permissiva",
  prerelease: "Pré-lançamento",
  engine_conflict: "Conflito de engines",
};

export const SOURCE_LABELS: Record<IssueSource, string> = {
  osv: "OSV.dev",
  npm_registry: "Registro npm",
  regra_local: "Regra local",
  analise_ia: "Análise IA",
};

export const STEP_LABELS: Record<ProgressStep, string> = {
  lendo_package_json: "Lendo package.json",
  consultando_npm: "Consultando registro npm",
  consultando_vulnerabilidades: "Consultando vulnerabilidades",
  aplicando_regras: "Aplicando regras",
  analisando_com_ia: "Analisando com IA",
  finalizando: "Finalizando",
};
