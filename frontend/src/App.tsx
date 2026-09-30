import { useCallback, useMemo, useState } from "react";

import { ExportButton } from "@/components/ExportButton";
import { FiltersBar } from "@/components/FiltersBar";
import { FindingsTable } from "@/components/FindingsTable";
import { GitHubForm } from "@/components/GitHubForm";
import { Header } from "@/components/Header";
import { ProgressBar } from "@/components/ProgressBar";
import { ProjectCard, SummaryCards } from "@/components/SummaryCards";
import { UploadForm } from "@/components/UploadForm";
import { Alert, EmptyState } from "@/components/ui";
import { useAnalysis } from "@/hooks/useAnalysis";
import { useTheme } from "@/hooks/useTheme";
import {
  EMPTY_FILTERS,
  filterFindings,
  sortFindings,
  summarize,
  type FilterState,
  type SortDirection,
  type SortKey,
} from "@/lib/format";

type Tab = "github" | "upload";

const TABS: ReadonlyArray<{ id: Tab; label: string; icon: string }> = [
  { id: "github", label: "Repositório GitHub", icon: "⌨" },
  { id: "upload", label: "Upload de arquivo", icon: "📦" },
];

const HOW_IT_WORKS: ReadonlyArray<{
  title: string;
  text: string;
  icon: string;
}> = [
  {
    icon: "📥",
    title: "1. Coleta",
    text: "Lemos o package.json e resolvemos a versão declarada de cada dependência pelas quatro seções do manifesto.",
  },
  {
    icon: "☁️",
    title: "2. Dados reais",
    text: "Consultamos o registro npm (versão mais recente, data de publicação, mantenedores, engines e downloads) e o OSV.dev (CVE e advisories).",
  },
  {
    icon: "🧮",
    title: "3. Regras",
    text: "Aplicamos 10 verificações determinísticas: pacote inexistente, deprecated, vulnerabilidade, desatualizada, sem manutenção, faixa permissiva, URL suspeita, typosquatting e conflito de engines.",
  },
  {
    icon: "✦",
    title: "4. IA (opcional)",
    text: "Com ANTHROPIC_API_KEY configurada, o Claude recebe apenas os fatos coletados e prioriza o que realmente exige ação.",
  },
];

export default function App() {
  const { theme, toggleTheme } = useTheme();
  const {
    status,
    report,
    error,
    errorHint,
    stepIndex,
    progress,
    analyzeUrl,
    analyzeFile,
    reset,
    cancel,
  } = useAnalysis();

  const [tab, setTab] = useState<Tab>("github");
  const [filters, setFilters] = useState<FilterState>(EMPTY_FILTERS);
  const [sortKey, setSortKey] = useState<SortKey>("severity");
  const [sortDirection, setSortDirection] = useState<SortDirection>("asc");
  const [showExportToast, setShowExportToast] = useState(false);

  const loading = status === "loading";

  const handleSort = useCallback((key: SortKey) => {
    setSortKey((currentKey) => {
      if (currentKey === key) {
        setSortDirection((current) => (current === "asc" ? "desc" : "asc"));
        return currentKey;
      }
      setSortDirection("asc");
      return key;
    });
  }, []);

  const visible = useMemo(() => {
    if (!report) return [];
    return sortFindings(
      filterFindings(report.findings, filters),
      sortKey,
      sortDirection,
    );
  }, [report, filters, sortKey, sortDirection]);

  const visibleSummary = useMemo(() => summarize(visible), [visible]);

  function startNewAnalysis(): void {
    reset();
    setFilters(EMPTY_FILTERS);
    setShowExportToast(false);
  }

  return (
    <div className="flex min-h-full flex-col">
      <Header theme={theme} onToggleTheme={toggleTheme} />

      <main className="mx-auto w-full max-w-7xl flex-1 space-y-6 px-4 py-6 sm:px-6 sm:py-8">
        {/* ---------- Entrada ---------- */}
        {status !== "success" ? (
          <section className="card p-5 sm:p-6">
            <h1 className="text-xl font-bold text-slate-900 dark:text-white sm:text-2xl">
              Analise as dependências do seu projeto
            </h1>
            <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
              Aponte para um repositório público do GitHub ou envie o seu{" "}
              <span className="font-mono">package.json</span>. A verificação usa
              apenas dados reais — nada é inventado.
            </p>

            <div
              role="tablist"
              aria-label="Modo de entrada"
              className="mt-5 flex gap-1 border-b border-slate-200 dark:border-slate-800"
            >
              {TABS.map((item) => (
                <button
                  key={item.id}
                  role="tab"
                  id={`tab-${item.id}`}
                  aria-selected={tab === item.id}
                  aria-controls={`panel-${item.id}`}
                  type="button"
                  disabled={loading}
                  onClick={() => setTab(item.id)}
                  className={`-mb-px flex items-center gap-2 border-b-2 px-4 py-2.5 text-sm font-semibold transition-colors ${
                    tab === item.id
                      ? "border-blue-600 text-blue-700 dark:border-blue-400 dark:text-blue-300"
                      : "border-transparent text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200"
                  }`}
                >
                  <span aria-hidden="true">{item.icon}</span>
                  {item.label}
                </button>
              ))}
            </div>

            <div className="mt-5">
              {tab === "github" ? (
                <div
                  role="tabpanel"
                  id="panel-github"
                  aria-labelledby="tab-github"
                >
                  <GitHubForm onSubmit={analyzeUrl} loading={loading} />
                </div>
              ) : (
                <div
                  role="tabpanel"
                  id="panel-upload"
                  aria-labelledby="tab-upload"
                >
                  <UploadForm onSubmit={analyzeFile} loading={loading} />
                </div>
              )}
            </div>
          </section>
        ) : null}

        {/* ---------- Erro ---------- */}
        {status === "error" && error ? (
          <Alert
            variant="error"
            title="Não foi possível concluir a análise"
            onDismiss={reset}
          >
            <p>{error}</p>
            {errorHint ? (
              <p className="mt-1 text-xs opacity-80">{errorHint}</p>
            ) : null}
          </Alert>
        ) : null}

        {/* ---------- Progresso ---------- */}
        {loading ? (
          <ProgressBar
            stepIndex={stepIndex}
            progress={progress}
            onCancel={cancel}
          />
        ) : null}

        {/* ---------- Resultado ---------- */}
        {status === "success" && report ? (
          <div className="space-y-5">
            {report.meta.warnings.length > 0 ? (
              <Alert
                variant="warning"
                title={`A análise terminou com ${report.meta.warnings.length} aviso(s)`}
              >
                <ul className="list-inside list-disc space-y-0.5">
                  {report.meta.warnings.map((warning) => (
                    <li key={warning}>{warning}</li>
                  ))}
                </ul>
              </Alert>
            ) : null}

            <ProjectCard report={report} />
            <SummaryCards
              summary={report.summary}
              total={report.findings.length}
            />

            <div className="flex flex-wrap items-center gap-2">
              <ExportButton
                report={report}
                findings={visible}
                onExport={() => {
                  setShowExportToast(true);
                  window.setTimeout(() => setShowExportToast(false), 4000);
                }}
              />
              <button
                type="button"
                className="btn-secondary"
                onClick={startNewAnalysis}
              >
                <span aria-hidden="true">↻</span>
                Nova análise
              </button>
              {report.findings.length > 0 ? (
                <span className="text-sm text-slate-500 dark:text-slate-400">
                  {visible.length} de {report.findings.length} dependências
                  visíveis
                </span>
              ) : null}
            </div>

            {showExportToast ? (
              <p className="text-sm text-ok-600 dark:text-ok-400" role="status">
                Relatório JSON baixado.
              </p>
            ) : null}

            {report.findings.length === 0 ? (
              <EmptyState
                icon="✅"
                title="Nenhuma dependência encontrada"
                description="O package.json foi lido, mas não há dependências declaradas para analisar."
              />
            ) : (
              <>
                <FiltersBar
                  filters={filters}
                  onChange={setFilters}
                  shown={visible.length}
                  total={report.findings.length}
                />
                {visible.length > 0 &&
                visibleSummary.critical +
                  visibleSummary.high +
                  visibleSummary.medium +
                  visibleSummary.low ===
                  0 ? (
                  <Alert
                    variant="info"
                    title="Nenhum problema visível no resultado atual"
                  >
                    As {visible.length} dependências exibidas estão sem
                    pendências. Limpe os filtros para ver todas.
                  </Alert>
                ) : null}
                <FindingsTable
                  findings={visible}
                  sortKey={sortKey}
                  direction={sortDirection}
                  onSort={handleSort}
                />
              </>
            )}
          </div>
        ) : null}

        {/* ---------- Landing ---------- */}
        {status === "idle" ? (
          <>
            <section className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              {HOW_IT_WORKS.map((step) => (
                <article key={step.title} className="card p-4">
                  <div className="mb-2 flex items-center gap-2">
                    <span aria-hidden="true" className="text-xl">
                      {step.icon}
                    </span>
                    <h2 className="text-sm font-semibold text-slate-800 dark:text-slate-100">
                      {step.title}
                    </h2>
                  </div>
                  <p className="text-sm leading-relaxed text-slate-600 dark:text-slate-400">
                    {step.text}
                  </p>
                </article>
              ))}
            </section>

            <section className="card p-5">
              <h2 className="text-base font-semibold text-slate-800 dark:text-slate-100">
                O que é verificado em cada dependência
              </h2>
              <div className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                {[
                  [
                    "not_found",
                    "A versão declarada nem existe no registro npm",
                  ],
                  ["vulnerability", "CVE e advisories confirmados no OSV.dev"],
                  [
                    "deprecated",
                    "O pacote está marcado como depreciado pelo autor",
                  ],
                  ["outdated", "Existe versão estável mais recente disponível"],
                  ["unmaintained", "Nenhuma publicação nos últimos 12 meses"],
                  [
                    "loose_range",
                    "Faixa aberta (^, ~, *, latest) que pode absorver breaking changes futures",
                  ],
                  [
                    "suspicious",
                    "URL de origem, nome e versão fora do padrão do pacote",
                  ],
                  [
                    "engines",
                    "Conflito entre o Node do projeto e o engines do pacote",
                  ],
                  [
                    "maintainers",
                    "Pacote com poucos mantenedores e pouca adoção",
                  ],
                ].map(([type, text]) => (
                  <div key={type} className="flex items-start gap-2 text-sm">
                    <span
                      aria-hidden="true"
                      className="mt-0.5 text-blue-600 dark:text-blue-400"
                    >
                      ▸
                    </span>
                    <span className="text-slate-600 dark:text-slate-400">
                      <span className="font-mono text-xs text-slate-500 dark:text-slate-400">
                        {type}
                      </span>{" "}
                      — {text}
                    </span>
                  </div>
                ))}
              </div>
            </section>
          </>
        ) : null}
      </main>

      <footer className="border-t border-slate-200 py-6 text-center text-xs text-slate-500 dark:border-slate-800 dark:text-slate-400">
        <p>
          DepGuard AI · dados públicos de npm e OSV.dev · a chave da Anthropic
          nunca sai do backend
        </p>
      </footer>
    </div>
  );
}
