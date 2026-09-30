/** Barra de progresso do pipeline de análise. */

import { STEPS } from "@/hooks/useAnalysis";
import { STEP_LABELS, type ProgressStep } from "@/types/api";
import { Spinner } from "./ui";

export function ProgressBar({
  stepIndex,
  progress,
  onCancel,
}: {
  stepIndex: number;
  progress: number;
  onCancel: () => void;
}) {
  const percent = Math.round(Math.max(0.04, Math.min(1, progress)) * 100);
  const currentIndex = stepIndex >= 0 ? stepIndex : 0;

  return (
    <div
      className="card animate-fade-in space-y-4 p-5"
      role="status"
      aria-live="polite"
    >
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <Spinner className="h-4 w-4 text-blue-600 dark:text-blue-400" />
          <p className="text-sm font-semibold text-slate-800 dark:text-slate-100">
            {STEP_LABELS[STEPS[currentIndex] as ProgressStep]}
            <span aria-hidden="true">…</span>
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="font-mono text-sm tabular-nums text-slate-500 dark:text-slate-400">
            {percent}%
          </span>
          <button
            type="button"
            onClick={onCancel}
            className="btn-ghost h-8 !px-2.5 !py-1 text-xs"
          >
            Cancelar
          </button>
        </div>
      </div>

      <div
        className="h-2 w-full overflow-hidden rounded-full bg-slate-200 dark:bg-slate-800"
        role="progressbar"
        aria-valuenow={percent}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label="Progresso da análise"
      >
        <div
          className="h-full rounded-full bg-blue-600 transition-all duration-500 ease-out dark:bg-blue-500"
          style={{ width: `${percent}%` }}
        />
      </div>

      <ol className="grid gap-1.5 sm:grid-cols-2 lg:grid-cols-3">
        {STEPS.map((step, index) => {
          const state =
            index < currentIndex
              ? "done"
              : index === currentIndex
                ? "active"
                : "pending";
          return (
            <li key={step} className="flex items-center gap-2 text-xs">
              <span
                aria-hidden="true"
                className={`flex h-4 w-4 shrink-0 items-center justify-center rounded-full text-[10px] font-bold ${
                  state === "done"
                    ? "bg-ok-500 text-white"
                    : state === "active"
                      ? "bg-blue-600 text-white dark:bg-blue-500 dark:text-slate-950"
                      : "bg-slate-200 text-slate-400 dark:bg-slate-700 dark:text-slate-500"
                }`}
              >
                {state === "done" ? "✓" : index + 1}
              </span>
              <span
                className={
                  state === "pending"
                    ? "text-slate-400 dark:text-slate-500"
                    : state === "active"
                      ? "font-semibold text-blue-700 dark:text-blue-300"
                      : "text-slate-600 dark:text-slate-400"
                }
              >
                {STEP_LABELS[step]}
              </span>
            </li>
          );
        })}
      </ol>
    </div>
  );
}
