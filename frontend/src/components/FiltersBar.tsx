/** Barra de busca + filtros da tabela de dependências. */

import {
  ISSUE_TYPE_LABELS,
  SEVERITIES,
  SOURCE_LABELS,
  type IssueSource,
  type IssueType,
  type Severity,
} from "@/types/api";
import {
  EMPTY_FILTERS,
  hasActiveFilters,
  ISSUE_TYPE_ICONS,
  SEVERITY_STYLES,
  type FilterState,
} from "@/lib/format";

const ISSUE_TYPES = Object.keys(ISSUE_TYPE_LABELS) as IssueType[];
const SOURCES = Object.keys(SOURCE_LABELS) as IssueSource[];

function toggle<T>(list: T[], value: T): T[] {
  return list.includes(value)
    ? list.filter((item) => item !== value)
    : [...list, value];
}

export function FiltersBar({
  filters,
  onChange,
  shown,
  total,
}: {
  filters: FilterState;
  onChange: (next: FilterState) => void;
  shown: number;
  total: number;
}) {
  const dirty = hasActiveFilters(filters) || filters.search.trim().length > 0;

  return (
    <div className="card space-y-3 p-4">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
        <div className="relative flex-1">
          <span
            className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"
            aria-hidden="true"
          >
            🔎
          </span>
          <input
            type="search"
            value={filters.search}
            onChange={(event) =>
              onChange({ ...filters, search: event.target.value })
            }
            placeholder="Buscar por pacote, versão, recomendação…"
            className="field pl-9"
            aria-label="Buscar dependências"
          />
        </div>

        <div className="flex items-center gap-2 text-sm">
          <span className="whitespace-nowrap text-slate-500 dark:text-slate-400">
            <span className="font-semibold text-slate-800 dark:text-slate-100">
              {shown}
            </span>
            <span className="hidden sm:inline"> de {total}</span>
          </span>
          {dirty ? (
            <button
              type="button"
              className="btn-ghost h-8 !px-2.5 !py-1 text-xs"
              onClick={() => onChange(EMPTY_FILTERS)}
            >
              Limpar filtros
            </button>
          ) : null}
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-1.5">
        <span className="mr-1 text-xs font-medium uppercase tracking-wide text-slate-400">
          Severidade
        </span>
        {SEVERITIES.map((severity) => (
          <button
            key={severity}
            type="button"
            onClick={() =>
              onChange({
                ...filters,
                severities: toggle(filters.severities, severity) as Severity[],
              })
            }
            className={`chip ${filters.severities.includes(severity) ? "chip-active" : ""}`}
            aria-pressed={filters.severities.includes(severity)}
          >
            {SEVERITY_STYLES[severity].label}
          </button>
        ))}
      </div>

      <div className="flex flex-wrap items-center gap-1.5">
        <span className="mr-1 text-xs font-medium uppercase tracking-wide text-slate-400">
          Problema
        </span>
        {ISSUE_TYPES.map((type) => (
          <button
            key={type}
            type="button"
            onClick={() =>
              onChange({
                ...filters,
                issueTypes: toggle(filters.issueTypes, type),
              })
            }
            className={`chip ${filters.issueTypes.includes(type) ? "chip-active" : ""}`}
            aria-pressed={filters.issueTypes.includes(type)}
          >
            <span aria-hidden="true">{ISSUE_TYPE_ICONS[type]}</span>
            {ISSUE_TYPE_LABELS[type]}
          </button>
        ))}
      </div>

      <div className="flex flex-wrap items-center gap-1.5">
        <span className="mr-1 text-xs font-medium uppercase tracking-wide text-slate-400">
          Origem
        </span>
        {SOURCES.map((source) => (
          <button
            key={source}
            type="button"
            onClick={() =>
              onChange({ ...filters, sources: toggle(filters.sources, source) })
            }
            className={`chip ${filters.sources.includes(source) ? "chip-active" : ""}`}
            aria-pressed={filters.sources.includes(source)}
          >
            {SOURCE_LABELS[source]}
          </button>
        ))}

        <span
          className="mx-1 hidden h-4 w-px bg-slate-300 sm:block dark:bg-slate-700"
          aria-hidden="true"
        />

        <button
          type="button"
          onClick={() =>
            onChange({ ...filters, onlyWithIssues: !filters.onlyWithIssues })
          }
          className={`chip ${filters.onlyWithIssues ? "chip-active" : ""}`}
          aria-pressed={filters.onlyWithIssues}
        >
          Só com problemas
        </button>
        <button
          type="button"
          onClick={() =>
            onChange({
              ...filters,
              onlyDev: !filters.onlyDev,
              onlyRuntime: false,
            })
          }
          className={`chip ${filters.onlyDev ? "chip-active" : ""}`}
          aria-pressed={filters.onlyDev}
        >
          Só dev
        </button>
        <button
          type="button"
          onClick={() =>
            onChange({
              ...filters,
              onlyRuntime: !filters.onlyRuntime,
              onlyDev: false,
            })
          }
          className={`chip ${filters.onlyRuntime ? "chip-active" : ""}`}
          aria-pressed={filters.onlyRuntime}
        >
          Só runtime
        </button>
      </div>
    </div>
  );
}
