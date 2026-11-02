/** Componentes de UI reutilizáveis. */

import type { ReactNode } from "react";

import { SEVERITY_STYLES } from "@/lib/format";
import type { Severity } from "@/types/api";
import { Icon, type IconName } from "./Icon";

// ==========================================================
// Badge
// ==========================================================

export function SeverityBadge({
  severity,
  size = "sm",
}: {
  severity: Severity;
  size?: "sm" | "md";
}) {
  const style = SEVERITY_STYLES[severity];
  return (
    <span
      className={`badge ${style.badge} ${size === "md" ? "px-2.5 py-1 text-sm" : ""}`}
      aria-label={`Severidade ${style.label}`}
    >
      <span
        aria-hidden="true"
        className="h-1.5 w-1.5 rounded-full bg-current opacity-70"
      />
      {style.label}
    </span>
  );
}

// ==========================================================
// Spinner
// ==========================================================

export function Spinner({ className = "h-4 w-4" }: { className?: string }) {
  return (
    <svg
      className={`animate-spin ${className}`}
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <circle
        className="opacity-20"
        cx="12"
        cy="12"
        r="10"
        stroke="currentColor"
        strokeWidth="4"
      />
      <path
        className="opacity-90"
        fill="currentColor"
        d="M4 12a8 8 0 0 1 8-8v4a4 4 0 0 0-4 4H4Z"
      />
    </svg>
  );
}

// ==========================================================
// Estado vazio
// ==========================================================

export function EmptyState({
  icon,
  title,
  description,
  action,
}: {
  icon?: IconName;
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="card flex flex-col items-center gap-3 px-6 py-14 text-center">
      <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-emerald-50 text-emerald-600 dark:bg-emerald-950/50 dark:text-emerald-400" aria-hidden="true">
        <Icon name={icon ?? "check"} className="h-7 w-7" />
      </div>
      <h3 className="text-base font-semibold text-slate-800 dark:text-slate-100">
        {title}
      </h3>
      <p className="max-w-md text-sm text-slate-500 dark:text-slate-400">
        {description}
      </p>
      {action}
    </div>
  );
}

// ==========================================================
// Alerta
// ==========================================================

const ALERT_STYLES: Record<"error" | "warning" | "info", string> = {
  error:
    "border-red-300 bg-red-50 text-red-800 dark:border-red-800 dark:bg-red-950/50 dark:text-red-200",
  warning:
    "border-amber-300 bg-amber-50 text-amber-900 dark:border-amber-800 dark:bg-amber-950/50 dark:text-amber-200",
  info: "border-blue-300 bg-blue-50 text-blue-900 dark:border-blue-800 dark:bg-blue-950/50 dark:text-blue-200",
};

const ALERT_ICONS: Record<"error" | "warning" | "info", IconName> = {
  error: "alert",
  warning: "alert",
  info: "info",
};

export function Alert({
  variant,
  title,
  children,
  onDismiss,
}: {
  variant: "error" | "warning" | "info";
  title: string;
  children?: ReactNode;
  onDismiss?: () => void;
}) {
  return (
    <div
      role={variant === "error" ? "alert" : "status"}
      className={`animate-slide-down flex items-start gap-3 rounded-lg border px-4 py-3 text-sm ${ALERT_STYLES[variant]}`}
    >
      <Icon name={ALERT_ICONS[variant]} className="mt-0.5 h-4 w-4 shrink-0" />
      <div className="min-w-0 flex-1 space-y-1">
        <p className="font-semibold">{title}</p>
        {children ? (
          <div className="leading-relaxed opacity-90">{children}</div>
        ) : null}
      </div>
      {onDismiss ? (
        <button
          type="button"
          onClick={onDismiss}
          className="shrink-0 rounded p-1 opacity-60 transition-opacity hover:opacity-100"
          aria-label="Fechar aviso"
        >
          <Icon name="close" className="h-4 w-4" />
        </button>
      ) : null}
    </div>
  );
}

// ==========================================================
// Copiar para a área de transferência
// ==========================================================

export function CopyButton({
  value,
  label = "Copiar",
}: {
  value: string;
  label?: string;
}) {
  return (
    <button
      type="button"
      className="rounded px-1.5 py-0.5 font-mono text-xs text-slate-500 transition-colors hover:bg-slate-200 hover:text-slate-800 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-slate-200"
      onClick={() => {
        void navigator.clipboard?.writeText(value);
      }}
      title="Copiar para a área de transferência"
    >
      {label}
    </button>
  );
}
