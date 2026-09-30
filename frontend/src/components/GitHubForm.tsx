/** Formulário de análise por URL de repositório GitHub. */

import { useId, useState, type FormEvent } from "react";

import { Spinner } from "./ui";

const EXAMPLES = [
  { label: "express", url: "https://github.com/expressjs/express" },
  { label: "vite", url: "https://github.com/vitejs/vite" },
  { label: "axios", url: "https://github.com/axios/axios" },
] as const;

export function GitHubForm({
  onSubmit,
  loading,
}: {
  onSubmit: (url: string) => void;
  loading: boolean;
}) {
  const inputId = useId();
  const [url, setUrl] = useState("");
  const [touched, setTouched] = useState(false);

  const trimmed = url.trim();
  const looksValid = /^https:\/\/github\.com\/[^/\s]+\/[^/\s#?]+/i.test(
    trimmed,
  );
  const showError = touched && trimmed.length > 0 && !looksValid;

  function handleSubmit(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    setTouched(true);
    if (looksValid && !loading) onSubmit(trimmed);
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-3" noValidate>
      <div>
        <label htmlFor={inputId} className="label">
          URL do repositório público no GitHub
        </label>
        <div className="flex flex-col gap-2 sm:flex-row">
          <input
            id={inputId}
            type="url"
            inputMode="url"
            autoComplete="url"
            spellCheck={false}
            placeholder="https://github.com/usuario/repositorio"
            value={url}
            onChange={(event) => setUrl(event.target.value)}
            onBlur={() => setTouched(true)}
            disabled={loading}
            aria-invalid={showError}
            aria-describedby={
              showError ? `${inputId}-error` : `${inputId}-help`
            }
            className="field font-mono sm:flex-1"
          />
          <button
            type="submit"
            className="btn-primary shrink-0 sm:w-40"
            disabled={loading || !looksValid}
          >
            {loading ? <Spinner /> : "🛡"}
            {loading ? "Analisando…" : "Analisar"}
          </button>
        </div>

        {showError ? (
          <p
            id={`${inputId}-error`}
            className="mt-1.5 text-sm text-red-600 dark:text-red-400"
          >
            Use o formato{" "}
            <span className="font-mono">
              https://github.com/usuario/repositorio
            </span>
            . Apenas repositórios públicos são suportados.
          </p>
        ) : (
          <p
            id={`${inputId}-help`}
            className="mt-1.5 text-sm text-slate-500 dark:text-slate-400"
          >
            Lemos o <span className="font-mono">package.json</span> da branch
            padrão. Monorepos são detectados automaticamente.
          </p>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs text-slate-500 dark:text-slate-400">
          Exemplos:
        </span>
        {EXAMPLES.map((example) => (
          <button
            key={example.url}
            type="button"
            disabled={loading}
            onClick={() => {
              setUrl(example.url);
              setTouched(false);
            }}
            className="chip"
          >
            {example.label}
          </button>
        ))}
      </div>
    </form>
  );
}
