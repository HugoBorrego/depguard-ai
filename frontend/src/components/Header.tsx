/** Cabeçalho: marca, status da API, status da IA e alternância de tema. */

import { useHealth } from "@/hooks/useHealth";
import type { Theme } from "@/hooks/useTheme";
import { Spinner } from "./ui";

function ApiStatusBadge() {
  const { status, health, error, refresh } = useHealth();

  if (status === "checking") {
    return (
      <span className="badge border-slate-300 bg-slate-100 text-slate-600 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">
        <Spinner className="h-3 w-3" />
        Conectando…
      </span>
    );
  }

  if (status === "offline") {
    return (
      <button
        type="button"
        onClick={refresh}
        title={error ?? "Backend inacessível. Clique para tentar de novo."}
        className="badge border-red-300 bg-red-50 text-red-700 hover:bg-red-100 dark:border-red-800 dark:bg-red-950/50 dark:text-red-300"
      >
        <span
          className="h-1.5 w-1.5 rounded-full bg-red-500"
          aria-hidden="true"
        />
        API offline — clique para reconectar
      </button>
    );
  }

  return (
    <button
      type="button"
      onClick={refresh}
      title={`API ${health?.status ?? "online"} (v${health?.version ?? "?"})`}
      className="badge border-ok-300 bg-ok-50 text-ok-700 hover:bg-ok-100 dark:border-ok-700 dark:bg-ok-950/50 dark:text-ok-300"
    >
      <span className="h-1.5 w-1.5 rounded-full bg-ok-500" aria-hidden="true" />
      API online
    </button>
  );
}

function AiBadge() {
  const { status, health } = useHealth();
  if (status !== "online" || !health) return null;

  return health.aiEnabled ? (
    <span
      className="badge border-indigo-300 bg-indigo-50 text-indigo-700 dark:border-indigo-700 dark:bg-indigo-950/50 dark:text-indigo-300"
      title={`Análise por IA ativa: ${health.environment}`}
    >
      ✦ IA ativa
    </span>
  ) : (
    <span
      className="badge border-slate-300 bg-slate-100 text-slate-600 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300"
      title="Sem ANTHROPIC_API_KEY no backend: somente regras determinísticas"
    >
      IA desativada
    </span>
  );
}

export function Header({
  theme,
  onToggleTheme,
}: {
  theme: Theme;
  onToggleTheme: () => void;
}) {
  return (
    <header className="sticky top-0 z-20 border-b border-slate-200 bg-white/85 backdrop-blur dark:border-slate-800 dark:bg-slate-900/85">
      <div className="mx-auto flex max-w-7xl items-center gap-4 px-4 py-3 sm:px-6">
        <a
          href="/"
          className="flex items-center gap-2.5 rounded"
          aria-label="DepGuard AI — início"
        >
          <img
            src="/shield.svg"
            alt=""
            className="h-8 w-8"
            width={32}
            height={32}
          />
          <span className="flex flex-col leading-none">
            <span className="text-lg font-bold tracking-tight text-slate-900 dark:text-white">
              DepGuard
            </span>
            <span className="text-[11px] font-semibold uppercase tracking-widest text-blue-600 dark:text-blue-400">
              AI
            </span>
          </span>
        </a>

        <p className="ml-2 hidden text-sm text-slate-500 dark:text-slate-400 md:block">
          Análise de dependências Node.js com dados reais do npm e do OSV
        </p>

        <div className="ml-auto flex items-center gap-2">
          <AiBadge />
          <ApiStatusBadge />
          <button
            type="button"
            onClick={onToggleTheme}
            className="btn-ghost h-9 w-9 !p-0"
            aria-label={
              theme === "dark" ? "Ativar tema claro" : "Ativar tema escuro"
            }
            title={theme === "dark" ? "Tema claro" : "Tema escuro"}
          >
            <span aria-hidden="true" className="text-base">
              {theme === "dark" ? "☀" : "☾"}
            </span>
          </button>
        </div>
      </div>
    </header>
  );
}
