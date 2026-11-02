/** Cartões de resumo do projeto e do resultado da análise. */

import { formatDate, formatDuration, SEVERITY_STYLES } from "@/lib/format";
import type { AnalysisReport, Severity } from "@/types/api";
import { SEVERITIES } from "@/types/api";

function StatCard({
  label,
  value,
  hint,
  severity,
}: {
  label: string;
  value: string | number;
  hint?: string;
  severity?: Severity;
}) {
  return (
    <div className="card p-4">
      <p className="text-xs font-medium uppercase tracking-wide text-slate-500 dark:text-slate-400">
        {label}
      </p>
      <p
        className={`mt-1 text-2xl font-bold tabular-nums ${
          severity
            ? SEVERITY_STYLES[severity].text
            : "text-slate-900 dark:text-white"
        }`}
      >
        {value}
      </p>
      {hint ? (
        <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
          {hint}
        </p>
      ) : null}
    </div>
  );
}

export function ProjectCard({ report }: { report: AnalysisReport }) {
  const { project, meta } = report;

  return (
    <div className="card p-5">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="truncate text-xl font-bold text-slate-900 dark:text-white">
              {project.name}
            </h2>
            {project.version ? (
              <span className="badge border-slate-300 bg-slate-100 font-mono text-slate-600 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">
                v{project.version}
              </span>
            ) : null}
            <span
              className={`badge ${
                project.source === "github"
                  ? "border-slate-300 bg-slate-100 text-slate-600 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300"
                  : "border-sky-300 bg-sky-50 text-sky-700 dark:border-sky-700 dark:bg-sky-950/50 dark:text-sky-300"
              }`}
            >
              {project.source === "github" ? "GitHub" : "Upload"}
            </span>
          </div>

          {project.sourceUrl ? (
            <a
              href={project.sourceUrl}
              target="_blank"
              rel="noreferrer noopener"
              className="mt-1 inline-block break-all font-mono text-sm text-blue-600 hover:underline dark:text-blue-400"
            >
              {project.sourceUrl}
            </a>
          ) : null}

          <dl className="mt-3 flex flex-wrap gap-x-6 gap-y-1.5 text-sm">
            {project.engineNode ? (
              <div className="flex gap-1.5">
                <dt className="text-slate-500 dark:text-slate-400">Node:</dt>
                <dd className="font-mono font-medium text-slate-800 dark:text-slate-200">
                  {project.engineNode}
                </dd>
              </div>
            ) : null}
            {project.license ? (
              <div className="flex gap-1.5">
                <dt className="text-slate-500 dark:text-slate-400">Licença:</dt>
                <dd className="font-medium text-slate-800 dark:text-slate-200">
                  {project.license}
                </dd>
              </div>
            ) : null}
            {project.manifests.length > 0 ? (
              <div className="flex gap-1.5">
                <dt className="text-slate-500 dark:text-slate-400">
                  Manifests:
                </dt>
                <dd className="font-medium text-slate-800 dark:text-slate-200">
                  {project.manifests.join(", ")}
                </dd>
              </div>
            ) : null}
          </dl>
        </div>

        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-500 dark:text-slate-400 sm:justify-end">
          <time dateTime={meta.analyzedAt}>{formatDate(meta.analyzedAt)}</time>
          <span>{formatDuration(meta.durationMs)}</span>
          {meta.aiEnabled ? <span className="rounded-full bg-blue-50 px-2 py-1 font-medium text-blue-700 dark:bg-blue-950/50 dark:text-blue-300">Análise inteligente</span> : null}
        </div>
      </div>
    </div>
  );
}

export function SummaryCards({
  summary,
  total,
}: {
  summary: AnalysisReport["summary"];
  total: number;
}) {
  const totalIssues = SEVERITIES.filter((s) => s !== "ok").reduce(
    (acc, s) => acc + summary[s],
    0,
  );

  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
      <StatCard
        label="Dependências"
        value={total}
        hint={`${totalIssues} com problemas`}
      />
      {SEVERITIES.map((severity) => (
        <StatCard
          key={severity}
          label={SEVERITY_STYLES[severity].label}
          value={summary[severity]}
          hint={severity === "ok" ? "sem pendências" : undefined}
          severity={severity}
        />
      ))}
    </div>
  );
}
