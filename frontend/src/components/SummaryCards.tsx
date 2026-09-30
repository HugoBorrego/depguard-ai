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

        <div className="text-right text-xs leading-relaxed text-slate-500 dark:text-slate-400">
          <p>
            Analisado em{" "}
            <time dateTime={meta.analyzedAt}>
              {formatDate(meta.analyzedAt)}
            </time>
          </p>
          <p>{formatDuration(meta.durationMs)}</p>
          <p>
            {meta.aiEnabled ? (
              <span
                title={meta.aiModel ?? undefined}
                className="text-indigo-600 dark:text-indigo-400"
              >
                ✦ IA {meta.aiBatches} lote(s)
                {meta.aiFailures > 0 ? ` · ${meta.aiFailures} falha(s)` : ""}
              </span>
            ) : (
              <span title="Sem ANTHROPIC_API_KEY configurada">
                Somente regras locais
              </span>
            )}
          </p>
          {meta.npmEtagCache ? (
            <p>{meta.npmEtagCache} resposta(s) do npm em cache</p>
          ) : null}
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
