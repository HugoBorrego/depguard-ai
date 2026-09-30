/** Formulário de análise por upload de package.json (com drag-and-drop). */

import { useCallback, useId, useRef, useState, type DragEvent } from "react";

import { formatDownloads } from "@/lib/format";
import { Spinner } from "./ui";

const MAX_SIZE_BYTES = 1024 * 1024; // mesmo limite do backend
const MAX_SIZE_LABEL = formatDownloads(MAX_SIZE_BYTES).replace("/semana", "");

export function UploadForm({
  onSubmit,
  loading,
}: {
  onSubmit: (file: File) => void;
  loading: boolean;
}) {
  const inputId = useId();
  const inputRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const validate = useCallback((candidate: File): string | null => {
    if (candidate.size > MAX_SIZE_BYTES) {
      return `Arquivo muito grande (${(candidate.size / 1024).toFixed(0)} KB). O limite é ${MAX_SIZE_LABEL}.`;
    }
    if (candidate.size === 0) return "O arquivo está vazio.";
    if (!/\.json$/i.test(candidate.name))
      return "O arquivo precisa ter extensão .json.";
    return null;
  }, []);

  const accept = useCallback(
    (candidate: File) => {
      const problem = validate(candidate);
      if (problem) {
        setError(problem);
        setFile(null);
        return;
      }
      setError(null);
      setFile(candidate);
    },
    [validate],
  );

  function handleDrop(event: DragEvent<HTMLLabelElement>): void {
    event.preventDefault();
    setDragging(false);
    if (loading) return;
    const dropped = event.dataTransfer.files.item(0);
    if (dropped) accept(dropped);
  }

  function clear(): void {
    setFile(null);
    setError(null);
    if (inputRef.current) inputRef.current.value = "";
  }

  return (
    <div className="space-y-3">
      <label
        htmlFor={inputId}
        onDragOver={(event) => {
          event.preventDefault();
          if (!loading) setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={handleDrop}
        className={`flex cursor-pointer flex-col items-center justify-center gap-2 rounded-xl border-2 border-dashed px-6 py-10 text-center transition-colors ${
          dragging
            ? "border-blue-500 bg-blue-50 dark:bg-blue-500/10"
            : "border-slate-300 hover:border-blue-400 hover:bg-slate-50 dark:border-slate-700 dark:hover:border-blue-600 dark:hover:bg-slate-800/50"
        } ${loading ? "pointer-events-none opacity-60" : ""}`}
      >
        <span className="text-3xl" aria-hidden="true">
          {file ? "📄" : "📦"}
        </span>

        {file ? (
          <span className="space-y-1">
            <span className="block font-semibold text-slate-800 dark:text-slate-100">
              {file.name}
            </span>
            <span className="block text-sm text-slate-500 dark:text-slate-400">
              {(file.size / 1024).toFixed(1).replace(".", ",")} KB — clique para
              trocar o arquivo
            </span>
          </span>
        ) : (
          <span className="space-y-1">
            <span className="block font-semibold text-slate-800 dark:text-slate-100">
              Arraste seu <span className="font-mono">package.json</span> aqui
            </span>
            <span className="block text-sm text-slate-500 dark:text-slate-400">
              ou clique para escolher o arquivo (até {MAX_SIZE_LABEL})
            </span>
          </span>
        )}

        <input
          ref={inputRef}
          id={inputId}
          type="file"
          accept="application/json,.json"
          className="sr-only"
          disabled={loading}
          onChange={(event) => {
            const selected = event.target.files?.item(0);
            if (selected) accept(selected);
          }}
        />
      </label>

      {error ? (
        <p role="alert" className="text-sm text-red-600 dark:text-red-400">
          {error}
        </p>
      ) : null}

      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          className="btn-primary"
          disabled={loading || !file}
          onClick={() => file && onSubmit(file)}
        >
          {loading ? <Spinner /> : "🛡"}
          {loading ? "Analisando…" : "Analisar arquivo"}
        </button>
        {file ? (
          <button
            type="button"
            className="btn-ghost"
            onClick={clear}
            disabled={loading}
          >
            Limpar
          </button>
        ) : null}
        <p className="text-xs text-slate-500 dark:text-slate-400">
          O arquivo é processado em memória e nunca é armazenado no servidor.
        </p>
      </div>
    </div>
  );
}
