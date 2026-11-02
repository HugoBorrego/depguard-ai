import { useCallback, useMemo, useState } from "react";

import { ExportButton } from "@/components/ExportButton";
import { FiltersBar } from "@/components/FiltersBar";
import { FindingsTable } from "@/components/FindingsTable";
import { GitHubForm } from "@/components/GitHubForm";
import { Header } from "@/components/Header";
import { Icon } from "@/components/Icon";
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

type Source = "github" | "upload";

export default function App() {
  const { theme, toggleTheme } = useTheme();
  const {
    status,
    report,
    error,
    stepIndex,
    progress,
    analyzeUrl,
    analyzeFile,
    reset,
    cancel,
  } = useAnalysis();
  const [source, setSource] = useState<Source>("github");
  const [filters, setFilters] = useState<FilterState>(EMPTY_FILTERS);
  const [sortKey, setSortKey] = useState<SortKey>("severity");
  const [sortDirection, setSortDirection] = useState<SortDirection>("asc");
  const [showExportToast, setShowExportToast] = useState(false);
  const loading = status === "loading";

  const handleSort = useCallback((key: SortKey) => {
    setSortKey((current) => {
      if (current === key) {
        setSortDirection((direction) => (direction === "asc" ? "desc" : "asc"));
        return current;
      }
      setSortDirection("asc");
      return key;
    });
  }, []);

  const visible = useMemo(() => {
    if (!report) return [];
    return sortFindings(filterFindings(report.findings, filters), sortKey, sortDirection);
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
      <main className="mx-auto w-full max-w-6xl flex-1 space-y-6 px-4 py-7 sm:px-6 sm:py-10">
        {status !== "success" ? (
          <section className="relative isolate overflow-hidden rounded-3xl border border-slate-200 bg-white shadow-[0_24px_80px_-36px_rgba(15,23,42,0.24)] dark:border-slate-800 dark:bg-slate-900">
            <div className="pointer-events-none absolute inset-0 z-0 overflow-hidden">
              <div className="absolute -right-24 -top-40 h-96 w-96 rounded-full bg-blue-500/10 blur-3xl dark:bg-blue-500/15" />
              <div className="absolute -left-28 bottom-0 h-64 w-64 rounded-full bg-cyan-400/10 blur-3xl" />
            </div>
            <div className="relative z-10 mx-auto max-w-3xl px-5 py-10 sm:px-10 sm:py-14">
              <div className="mb-5 inline-flex items-center gap-2 rounded-full border border-blue-200 bg-blue-50 px-3 py-1.5 text-xs font-semibold text-blue-700 dark:border-blue-900 dark:bg-blue-950/60 dark:text-blue-300">
                <Icon name="shield" className="h-3.5 w-3.5" />
                Segurança de dependências
              </div>
              <h1 className="max-w-2xl text-3xl font-bold tracking-tight text-slate-950 dark:text-white sm:text-5xl sm:leading-[1.12]">
                Cuide da segurança do seu projeto.
              </h1>
              <p className="mt-4 max-w-xl text-base leading-7 text-slate-600 dark:text-slate-400">
                Encontre riscos e atualizações importantes em poucos instantes.
              </p>

              <div className="mt-9 grid gap-3 sm:grid-cols-2">
                {([
                  { id: "github", label: "Repositório GitHub", detail: "Cole o link do projeto", icon: "github" },
                  { id: "upload", label: "Arquivo package.json", detail: "Selecione do seu dispositivo", icon: "upload" },
                ] as const).map((item) => (
                  <button
                    key={item.id}
                    type="button"
                    disabled={loading}
                    onClick={() => setSource(item.id)}
                    aria-pressed={source === item.id}
                    className={`group flex items-center gap-4 rounded-2xl border p-4 text-left transition-all ${source === item.id ? "border-blue-500 bg-blue-50/80 shadow-sm ring-1 ring-blue-500/20 dark:bg-blue-500/10" : "border-slate-200 bg-white/70 hover:border-slate-300 hover:bg-white dark:border-slate-700 dark:bg-slate-900/60 dark:hover:border-slate-600"}`}
                  >
                    <span className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-xl ${source === item.id ? "bg-blue-600 text-white" : "bg-slate-100 text-slate-600 group-hover:bg-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:group-hover:bg-slate-700"}`}>
                      <Icon name={item.icon} className="h-5 w-5" />
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="block text-sm font-semibold text-slate-900 dark:text-white">{item.label}</span>
                      <span className="mt-0.5 block text-xs text-slate-500 dark:text-slate-400">{item.detail}</span>
                    </span>
                    <span className={`h-4 w-4 rounded-full border ${source === item.id ? "border-[5px] border-blue-600 dark:border-blue-400" : "border-slate-300 dark:border-slate-600"}`} aria-hidden="true" />
                  </button>
                ))}
              </div>

              <div className="mt-6 rounded-2xl border border-slate-200/80 bg-white/80 p-4 dark:border-slate-800 dark:bg-slate-950/40 sm:p-5">
                {source === "github" ? (
                  <GitHubForm onSubmit={analyzeUrl} loading={loading} />
                ) : (
                  <UploadForm onSubmit={analyzeFile} loading={loading} />
                )}
              </div>
              <div className="mt-5 flex flex-wrap items-center justify-center gap-x-5 gap-y-2 text-xs text-slate-500 dark:text-slate-400">
                <span className="inline-flex items-center gap-1.5"><Icon name="check" className="h-3.5 w-3.5 text-emerald-600" /> Vulnerabilidades</span>
                <span className="inline-flex items-center gap-1.5"><Icon name="check" className="h-3.5 w-3.5 text-emerald-600" /> Dependências desatualizadas</span>
                <span className="inline-flex items-center gap-1.5"><Icon name="check" className="h-3.5 w-3.5 text-emerald-600" /> Recomendações práticas</span>
              </div>
            </div>
          </section>
        ) : null}

        {status === "error" && error ? (
          <Alert variant="error" title="Não foi possível concluir a análise" onDismiss={reset}>
            <p>{error}</p>
          </Alert>
        ) : null}

        {loading ? <ProgressBar stepIndex={stepIndex} progress={progress} onCancel={cancel} /> : null}

        {status === "success" && report ? (
          <div className="space-y-5">
            {report.meta.warnings.length > 0 ? (
              <Alert variant="warning" title={`A análise terminou com ${report.meta.warnings.length} aviso(s)`}>
                <ul className="list-inside list-disc space-y-0.5">
                  {report.meta.warnings.map((warning) => <li key={warning}>{warning}</li>)}
                </ul>
              </Alert>
            ) : null}
            <ProjectCard report={report} />
            <SummaryCards summary={report.summary} total={report.findings.length} />
            <div className="flex flex-wrap items-center gap-2">
              <ExportButton report={report} findings={visible} onExport={() => {
                setShowExportToast(true);
                window.setTimeout(() => setShowExportToast(false), 4000);
              }} />
              <button type="button" className="btn-secondary" onClick={startNewAnalysis}>
                <Icon name="refresh" /> Nova análise
              </button>
              {report.findings.length > 0 ? <span className="text-sm text-slate-500 dark:text-slate-400">{visible.length} de {report.findings.length} dependências</span> : null}
            </div>
            {showExportToast ? <p className="text-sm text-ok-600 dark:text-ok-400" role="status">Relatório JSON baixado.</p> : null}
            {report.findings.length === 0 ? (
              <EmptyState title="Nenhuma dependência encontrada" description="Não há dependências para analisar neste projeto." />
            ) : (
              <>
                <FiltersBar filters={filters} onChange={setFilters} shown={visible.length} total={report.findings.length} />
                {visible.length > 0 && visibleSummary.critical + visibleSummary.high + visibleSummary.medium + visibleSummary.low === 0 ? (
                  <Alert variant="info" title="Nenhum problema visível no resultado atual">As dependências exibidas estão sem pendências. Limpe os filtros para ver todas.</Alert>
                ) : null}
                <FindingsTable findings={visible} sortKey={sortKey} direction={sortDirection} onSort={handleSort} />
              </>
            )}
          </div>
        ) : null}
      </main>
      <footer className="border-t border-slate-200 py-5 text-center text-xs text-slate-500 dark:border-slate-800 dark:text-slate-400">
        DepGuard <span className="mx-1">·</span> Segurança de dependências
      </footer>
    </div>
  );
}
