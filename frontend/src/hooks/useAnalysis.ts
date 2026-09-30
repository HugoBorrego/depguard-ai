/** Hook que gerencia o estado da análise: loading, progresso, resultado e erro. */

import { useCallback, useEffect, useRef, useState } from "react";

import { analyzeGitHub, analyzeUpload, ApiError } from "@/lib/api";
import type { AnalysisReport, ProgressStep } from "@/types/api";

/** Etapas exibidas enquanto o backend trabalha (espelha `PROGRESS_STEPS`). */
export const STEPS: readonly ProgressStep[] = [
  "lendo_package_json",
  "consultando_npm",
  "consultando_vulnerabilidades",
  "aplicando_regras",
  "analisando_com_ia",
  "finalizando",
] as const;

export interface AnalysisState {
  status: "idle" | "loading" | "success" | "error";
  report: AnalysisReport | null;
  error: string | null;
  errorHint: string | null;
  /** Etapa atual (índice em `STEPS`), ou -1 antes de começar. */
  stepIndex: number;
  /** Progresso estimado 0..1 (a API não faz streaming no modo padrão). */
  progress: number;
}

const INITIAL: AnalysisState = {
  status: "idle",
  report: null,
  error: null,
  errorHint: null,
  stepIndex: -1,
  progress: 0,
};

export interface UseAnalysisResult extends AnalysisState {
  analyzeUrl: (url: string) => Promise<void>;
  analyzeFile: (file: File) => Promise<void>;
  reset: () => void;
  cancel: () => void;
}

/**
 * Simula o avanço das etapas enquanto a requisição está em voo.
 *
 * A API `POST /api/analyze/*` é síncrona (o relatório só chega no fim), mas o
 * usuário precisa saber o que está acontecendo. Este ticker avança pelas etapas
 * na ordem real do pipeline e para sozinho se a resposta chegar antes.
 */
function useStepTicker(active: boolean): number {
  const [stepIndex, setStepIndex] = useState(-1);
  const timerRef = useRef<number | null>(null);

  useEffect(() => {
    if (!active) {
      if (timerRef.current !== null) {
        window.clearInterval(timerRef.current);
        timerRef.current = null;
      }
      return;
    }

    let index = 0;
    setStepIndex(0);
    // A IA é a etapa mais lenta: damos mais tempo a ela antes de parar em 100%.
    const delays = [700, 1400, 1900, 1200, 2600, 1500];

    timerRef.current = window.setInterval(() => {
      if (index >= STEPS.length - 1) {
        if (timerRef.current !== null) {
          window.clearInterval(timerRef.current);
          timerRef.current = null;
        }
        return;
      }
      index += 1;
      setStepIndex(index);
    }, delays[0] ?? 1200);

    return () => {
      if (timerRef.current !== null) {
        window.clearInterval(timerRef.current);
        timerRef.current = null;
      }
    };
  }, [active]);

  return stepIndex;
}

export function useAnalysis(): UseAnalysisResult {
  const [state, setState] = useState<AnalysisState>(INITIAL);
  const abortRef = useRef<AbortController | null>(null);
  const stepIndex = useStepTicker(state.status === "loading");

  const progress =
    state.status === "loading"
      ? Math.min(0.95, (stepIndex + 1) / STEPS.length)
      : state.status === "success"
        ? 1
        : 0;

  const run = useCallback(
    async (task: (signal: AbortSignal) => Promise<AnalysisReport>) => {
      abortRef.current?.abort();
      const controller = new AbortController();
      abortRef.current = controller;

      setState({ ...INITIAL, status: "loading" });

      try {
        const report = await task(controller.signal);
        setState({
          status: "success",
          report,
          error: null,
          errorHint: null,
          stepIndex: STEPS.length - 1,
          progress: 1,
        });
      } catch (error) {
        if (controller.signal.aborted) {
          setState(INITIAL);
          return;
        }
        if (error instanceof ApiError) {
          setState({
            status: "error",
            report: null,
            error: error.message,
            errorHint: buildHint(error),
            stepIndex: -1,
            progress: 0,
          });
        } else {
          setState({
            status: "error",
            report: null,
            error: error instanceof Error ? error.message : "Erro inesperado.",
            errorHint: null,
            stepIndex: -1,
            progress: 0,
          });
        }
      } finally {
        if (abortRef.current === controller) abortRef.current = null;
      }
    },
    [],
  );

  const analyzeUrl = useCallback(
    (url: string) => run((signal) => analyzeGitHub({ url }, signal)),
    [run],
  );

  const analyzeFile = useCallback(
    (file: File) => run((signal) => analyzeUpload(file, signal)),
    [run],
  );

  const reset = useCallback(() => {
    abortRef.current?.abort();
    abortRef.current = null;
    setState(INITIAL);
  }, []);

  const cancel = useCallback(() => {
    abortRef.current?.abort();
    abortRef.current = null;
    setState(INITIAL);
  }, []);

  return {
    ...state,
    stepIndex,
    progress,
    analyzeUrl,
    analyzeFile,
    reset,
    cancel,
  };
}

/** Mensagem de ajuda conforme o status HTTP. */
function buildHint(error: ApiError): string | null {
  switch (error.status) {
    case 0:
      return "A API usa a variável VITE_API_URL (ou o proxy /api do Vite) para achar o backend.";
    case 400:
      return "Confira se o package.json tem dependências válidas e está em UTF-8.";
    case 404:
      return "O repositório existe? Pode ser privado, ter sido removido, ou não ter package.json na raiz.";
    case 413:
      return "Envie um package.json menor (o limite padrão é 1 MB).";
    case 422:
      return "A URL precisa ter o formato https://github.com/usuario/repositorio.";
    case 429:
      return error.retryAfter
        ? `Aguarde ${error.retryAfter}s antes de tentar de novo.`
        : "Você atingiu o limite de requisições. Aguarde um minuto.";
    case 503:
      return "O GitHub ou o registro npm podem estar indisponíveis. Tente novamente em instantes.";
    default:
      return null;
  }
}
