import { useHealth } from "@/hooks/useHealth";
import type { Theme } from "@/hooks/useTheme";
import { Icon } from "@/components/Icon";

export function Header({
  theme,
  onToggleTheme,
}: {
  theme: Theme;
  onToggleTheme: () => void;
}) {
  const { status, refresh } = useHealth();
  const connected = status === "online";
  return (
    <header className="sticky top-0 z-20 border-b border-slate-200/80 bg-white/85 backdrop-blur-xl dark:border-slate-800 dark:bg-slate-950/85">
      <div className="mx-auto flex max-w-7xl items-center gap-4 px-4 py-3.5 sm:px-6">
        <a href="/" className="flex items-center gap-3 rounded" aria-label="DepGuard, início">
          <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-blue-600 text-white shadow-sm shadow-blue-600/20">
            <Icon name="shield" className="h-5 w-5" />
          </span>
          <span className="text-lg font-bold tracking-tight text-slate-950 dark:text-white">DepGuard</span>
        </a>

        <div className="ml-auto flex items-center gap-2.5">
          <button
            type="button"
            onClick={refresh}
            title={connected ? "Tudo pronto" : status === "offline" ? "Tentar novamente" : "Conectando"}
            aria-label={connected ? "Serviço pronto" : status === "offline" ? "Serviço indisponível, tentar novamente" : "Conectando"}
            className="inline-flex h-9 items-center gap-2 rounded-full border border-slate-200 px-3 text-xs font-medium text-slate-600 transition-colors hover:bg-slate-50 dark:border-slate-800 dark:text-slate-300 dark:hover:bg-slate-900"
          >
            <span className={`h-1.5 w-1.5 rounded-full ${connected ? "bg-emerald-500" : status === "offline" ? "bg-red-500" : "animate-pulse bg-amber-500"}`} />
            <span className="hidden sm:inline">{connected ? "Pronto" : status === "offline" ? "Indisponível" : "Conectando"}</span>
          </button>
          <button
            type="button"
            onClick={onToggleTheme}
            className="btn-ghost h-9 w-9 !p-0"
            aria-label={theme === "dark" ? "Ativar tema claro" : "Ativar tema escuro"}
            title={theme === "dark" ? "Tema claro" : "Tema escuro"}
          >
            <Icon name={theme === "dark" ? "sun" : "moon"} className="h-[18px] w-[18px]" />
          </button>
        </div>
      </div>
    </header>
  );
}
