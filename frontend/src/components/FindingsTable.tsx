/** Tabela de dependências com ordenação e linha expansível. */

import { Fragment, useState } from "react";

import {
  BREAKING_RISK_LABELS,
  BREAKING_RISK_STYLES,
  formatDate,
  formatDownloads,
  formatRelativeDate,
  ISSUE_SOURCE_LABELS,
  ISSUE_TYPE_ICONS,
  SECTION_LABELS,
  SOURCE_BADGE_STYLES,
  type SortDirection,
  type SortKey,
} from "@/lib/format";
import type { DependencyFinding } from "@/types/api";
import { CopyButton, SeverityBadge } from "./ui";

interface ColumnDef {
  label: string;
  sortKey: SortKey;
  className: string;
}

const COLUMNS: readonly ColumnDef[] = [
  { label: "Pacote", sortKey: "package", className: "text-left" },
  { label: "Severidade", sortKey: "severity", className: "text-left w-28" },
  { label: "Versão atual", sortKey: "version", className: "text-left w-40" },
  { label: "Última", sortKey: "version", className: "text-left w-32" },
  { label: "Problemas", sortKey: "issues", className: "text-left w-32" },
  { label: "Ação sugerida", sortKey: "issues", className: "text-left" },
];

function SortableHeader({
  label,
  sortKey,
  current,
  direction,
  onSort,
  className,
}: {
  label: string;
  sortKey: SortKey;
  current: SortKey;
  direction: SortDirection;
  onSort: (key: SortKey) => void;
  className: string;
}) {
  const active = current === sortKey;
  return (
    <th
      scope="col"
      className={`px-3 py-2.5 text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 ${className}`}
      aria-sort={
        active ? (direction === "asc" ? "ascending" : "descending") : "none"
      }
    >
      <button
        type="button"
        onClick={() => onSort(sortKey)}
        className={`inline-flex items-center gap-1 rounded transition-colors hover:text-blue-600 dark:hover:text-blue-400 ${
          active ? "text-blue-600 dark:text-blue-400" : ""
        }`}
      >
        {label}
        <span aria-hidden="true" className="text-[10px]">
          {active ? (direction === "asc" ? "▲" : "▼") : "↕"}
        </span>
      </button>
    </th>
  );
}

function Row({
  label,
  value,
  mono,
  copyable,
  className,
}: {
  label: string;
  value: string;
  mono?: boolean;
  copyable?: boolean;
  className?: string;
}) {
  return (
    <div className="flex items-start justify-between gap-3">
      <dt className="shrink-0 text-slate-500 dark:text-slate-400">{label}</dt>
      <dd
        className={`min-w-0 text-right font-medium text-slate-800 dark:text-slate-200 ${mono ? "font-mono text-xs" : ""} ${className ?? ""}`}
      >
        {value}
        {copyable ? <CopyButton value={value} /> : null}
      </dd>
    </div>
  );
}

function DetailRow({ finding }: { finding: DependencyFinding }) {
  return (
    <tr className="border-t border-slate-200 bg-slate-50/70 dark:border-slate-800 dark:bg-slate-800/30">
      <td colSpan={COLUMNS.length + 1} className="px-4 py-4">
        <div className="grid gap-5 lg:grid-cols-3">
          <div className="space-y-3 lg:col-span-2">
            {finding.description ? (
              <div>
                <h4 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
                  Descrição
                </h4>
                <p className="text-sm leading-relaxed text-slate-700 dark:text-slate-300">
                  {finding.description}
                </p>
              </div>
            ) : null}

            <div>
              <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
                Problemas encontrados ({finding.issues.length})
              </h4>
              {finding.issues.length === 0 ? (
                <p className="text-sm text-slate-500 dark:text-slate-400">
                  Nenhum problema detectado por esta análise.
                </p>
              ) : (
                <ul className="space-y-2">
                  {finding.issues.map((issue, index) => (
                    <li
                      key={`${issue.type}-${issue.source}-${index}`}
                      className="rounded-lg border border-slate-200 bg-white p-3 dark:border-slate-700 dark:bg-slate-900"
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        <span aria-hidden="true">
                          {ISSUE_TYPE_ICONS[issue.type]}
                        </span>
                        <span className="text-sm font-semibold text-slate-800 dark:text-slate-200">
                          {issue.type}
                        </span>
                        <span
                          className={`badge ${SOURCE_BADGE_STYLES[issue.source]}`}
                        >
                          {ISSUE_SOURCE_LABELS[issue.source]}
                        </span>
                      </div>
                      <p className="mt-1.5 text-sm leading-relaxed text-slate-600 dark:text-slate-400">
                        {issue.description}
                      </p>
                      {issue.references.length > 0 ? (
                        <ul className="mt-1.5 flex flex-wrap gap-x-3 gap-y-1">
                          {issue.references.map((reference) => (
                            <li key={reference}>
                              <a
                                href={reference}
                                target="_blank"
                                rel="noreferrer noopener"
                                className="break-all font-mono text-xs text-blue-600 hover:underline dark:text-blue-400"
                              >
                                {reference}
                              </a>
                            </li>
                          ))}
                        </ul>
                      ) : null}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>

          <div className="space-y-3">
            <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
              Metadados do pacote
            </h4>
            <dl className="space-y-1.5 text-sm">
              <Row
                label="Seção"
                value={
                  finding.section
                    ? (SECTION_LABELS[finding.section] ?? finding.section)
                    : "—"
                }
              />
              <Row
                label="Resolvida"
                value={finding.resolvedVersion ?? "—"}
                mono
                copyable
              />
              <Row
                label="Última publicada"
                value={formatRelativeDate(finding.latestPublishedAt)}
              />
              <Row
                label="Downloads"
                value={formatDownloads(finding.weeklyDownloads)}
              />
              <Row
                label="Node (engines)"
                value={
                  Object.entries(finding.engines)
                    .map(([key, value]) => `${key} ${value}`)
                    .join(", ") || "—"
                }
                mono
              />
              <Row
                label="Licenças"
                value={finding.licenses.join(", ") || "—"}
              />
              <Row
                label="Mantenedores"
                value={String(finding.maintainers.length)}
              />
              <Row
                label="Risco de breaking"
                value={BREAKING_RISK_LABELS[finding.breakingChangeRisk]}
                className={BREAKING_RISK_STYLES[finding.breakingChangeRisk]}
              />
              <Row
                label="Analisado por"
                value={finding.analyzedByAi ? "Regras + IA" : "Regras locais"}
                className={
                  finding.analyzedByAi
                    ? "text-indigo-600 dark:text-indigo-400"
                    : undefined
                }
              />
            </dl>

            {finding.repository ? (
              <a
                href={finding.repository}
                target="_blank"
                rel="noreferrer noopener"
                className="inline-block break-all font-mono text-xs text-blue-600 hover:underline dark:text-blue-400"
              >
                {finding.repository}
              </a>
            ) : null}
          </div>
        </div>
      </td>
    </tr>
  );
}

export function FindingsTable({
  findings,
  sortKey,
  direction,
  onSort,
}: {
  findings: readonly DependencyFinding[];
  sortKey: SortKey;
  direction: SortDirection;
  onSort: (key: SortKey) => void;
}) {
  const [expanded, setExpanded] = useState<string | null>(null);

  if (findings.length === 0) {
    return (
      <div className="card px-6 py-12 text-center text-sm text-slate-500 dark:text-slate-400">
        Nenhuma dependência corresponde aos filtros aplicados.
      </div>
    );
  }

  return (
    <div className="card overflow-hidden">
      <div className="overflow-x-auto scrollbar-thin">
        <table className="w-full min-w-[900px] border-collapse text-sm">
          <thead className="border-b border-slate-200 bg-slate-50 dark:border-slate-800 dark:bg-slate-800/40">
            <tr>
              <th scope="col" className="w-8 px-3 py-2.5">
                <span className="sr-only">Expandir</span>
              </th>
              {COLUMNS.map((column) => (
                <SortableHeader
                  key={column.label}
                  label={column.label}
                  sortKey={column.sortKey}
                  current={sortKey}
                  direction={direction}
                  onSort={onSort}
                  className={column.className}
                />
              ))}
            </tr>
          </thead>
          <tbody>
            {findings.map((finding) => {
              const rowKey = `${finding.package}::${finding.section ?? ""}`;
              const isOpen = expanded === rowKey;
              return (
                <Fragment key={rowKey}>
                  <tr
                    className={`border-b border-slate-100 transition-colors last:border-0 dark:border-slate-800/60 ${
                      isOpen
                        ? "bg-blue-50/60 dark:bg-blue-500/5"
                        : "hover:bg-slate-50 dark:hover:bg-slate-800/40"
                    }`}
                  >
                    <td className="px-3 py-2.5">
                      <button
                        type="button"
                        onClick={() => setExpanded(isOpen ? null : rowKey)}
                        aria-expanded={isOpen}
                        aria-label={
                          isOpen
                            ? `Ocultar detalhes de ${finding.package}`
                            : `Ver detalhes de ${finding.package}`
                        }
                        className="flex h-6 w-6 items-center justify-center rounded text-slate-400 transition-colors hover:bg-slate-200 hover:text-slate-700 dark:hover:bg-slate-700 dark:hover:text-slate-200"
                      >
                        <span
                          aria-hidden="true"
                          className="text-[10px] transition-transform"
                          style={{
                            transform: isOpen ? "rotate(90deg)" : "none",
                          }}
                        >
                          ▶
                        </span>
                      </button>
                    </td>

                    <td className="px-3 py-2.5">
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-semibold text-slate-900 dark:text-slate-100">
                          {finding.package}
                        </span>
                        {finding.isDevDependency ? (
                          <span
                            className="badge border-slate-300 bg-slate-100 text-slate-500 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-400"
                            title="Dependência de desenvolvimento"
                          >
                            dev
                          </span>
                        ) : null}
                        {finding.analyzedByAi ? (
                          <span
                            className="badge border-indigo-300 bg-indigo-50 text-indigo-600 dark:border-indigo-700 dark:bg-indigo-950/50 dark:text-indigo-300"
                            title="Também analisado por IA"
                          >
                            ✦
                          </span>
                        ) : null}
                      </div>
                      <span className="text-xs text-slate-400">
                        {finding.section
                          ? (SECTION_LABELS[finding.section] ?? finding.section)
                          : "—"}
                      </span>
                    </td>

                    <td className="px-3 py-2.5">
                      <SeverityBadge severity={finding.severity} />
                    </td>

                    <td className="px-3 py-2.5 font-mono text-xs text-slate-700 dark:text-slate-300">
                      {finding.requestedVersion}
                      {finding.resolvedVersion &&
                      finding.resolvedVersion !== finding.requestedVersion ? (
                        <span className="block text-[11px] text-slate-400">
                          → {finding.resolvedVersion}
                        </span>
                      ) : null}
                    </td>

                    <td className="px-3 py-2.5 font-mono text-xs text-slate-600 dark:text-slate-400">
                      {finding.latestVersion ?? "—"}
                      {finding.latestPublishedAt ? (
                        <span className="block text-[11px] text-slate-400">
                          {formatDate(finding.latestPublishedAt)}
                        </span>
                      ) : null}
                    </td>

                    <td className="px-3 py-2.5">
                      {finding.issues.length === 0 ? (
                        <span className="text-xs text-ok-600 dark:text-ok-400">
                          nenhum
                        </span>
                      ) : (
                        <div className="flex flex-wrap gap-1">
                          {[
                            ...new Set(
                              finding.issues.map((issue) => issue.type),
                            ),
                          ].map((type) => (
                            <span
                              key={type}
                              className="badge border-slate-200 bg-slate-50 text-slate-600 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300"
                              title={type}
                            >
                              <span aria-hidden="true">
                                {ISSUE_TYPE_ICONS[type]}
                              </span>
                              {
                                finding.issues.filter(
                                  (issue) => issue.type === type,
                                ).length
                              }
                            </span>
                          ))}
                        </div>
                      )}
                    </td>

                    <td className="max-w-md px-3 py-2.5">
                      <p
                        className="text-xs leading-relaxed text-slate-600 dark:text-slate-400"
                        title={finding.recommendation}
                      >
                        {finding.recommendation}
                      </p>
                      <span
                        className={`text-[11px] font-medium ${BREAKING_RISK_STYLES[finding.breakingChangeRisk]}`}
                      >
                        breaking:{" "}
                        {BREAKING_RISK_LABELS[
                          finding.breakingChangeRisk
                        ].toLowerCase()}
                      </span>
                    </td>
                  </tr>

                  {isOpen ? <DetailRow finding={finding} /> : null}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </div>

      <p className="border-t border-slate-200 px-4 py-2.5 text-xs text-slate-500 dark:border-slate-800 dark:text-slate-400">
        {findings.length} dependência(s) exibida(s)
      </p>
    </div>
  );
}
