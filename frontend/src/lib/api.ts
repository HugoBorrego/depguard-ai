/**
 * Cliente HTTP da API do DepGuard AI.
 *
 * `VITE_API_URL` define a base em produção. Vazio = usa `/api` no mesmo host
 * (comportamento padrão do docker-compose e dos rewrites de Vercel/Netlify).
 *
 * A chave da API **nunca** trafega pelo navegador: a IA roda só no backend.
 */

import type {
  AnalysisReport,
  AnalyzeGitHubRequest,
  HealthResponse,
} from "@/types/api";

const RAW_BASE =
  (import.meta.env.VITE_API_URL as string | undefined)?.trim() ?? "";

/** Base da API sem barra final. */
export const API_BASE: string = RAW_BASE.replace(/\/+$/, "");

/** Endpoint completo (ex.: ``/api/analyze/upload``). */
export function apiUrl(path: string): string {
  const suffix = path.startsWith("/") ? path : `/${path}`;
  return `${API_BASE}${suffix}`;
}

/** Erro de API com mensagem já amigável para o usuário. */
export class ApiError extends Error {
  readonly status: number;
  readonly hint: string | null;
  readonly retryAfter: number | null;

  constructor(
    message: string,
    status: number,
    hint: string | null = null,
    retryAfter: number | null = null,
  ) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.hint = hint;
    this.retryAfter = retryAfter;
  }

  /** Verdadeiro quando uma nova tentativa pode resolver. */
  get isRetryable(): boolean {
    return this.status === 429 || this.status >= 500;
  }
}

function extractDetail(payload: unknown, fallback: string): string {
  if (typeof payload === "string" && payload.trim()) return payload.trim();
  if (payload && typeof payload === "object") {
    const record = payload as Record<string, unknown>;
    const detail = record.detail;
    if (typeof detail === "string" && detail.trim()) return detail.trim();
    if (Array.isArray(detail)) {
      // Formato padrão de erro de validação do FastAPI
      const messages = detail
        .map((item) => {
          if (item && typeof item === "object" && "msg" in item) {
            const msg = String((item as { msg: unknown }).msg);
            const loc = (item as { loc?: unknown[] }).loc;
            const field = Array.isArray(loc)
              ? String(loc[loc.length - 1] ?? "")
              : "";
            return field ? `${field}: ${msg}` : msg;
          }
          return String(item);
        })
        .filter(Boolean);
      if (messages.length) return messages.join(" | ");
    }
  }
  return fallback;
}

/** Converte erros de rede/HTTP em `ApiError` com mensagem em português. */
function toApiError(error: unknown, context: string): ApiError {
  if (error instanceof ApiError) return error;

  if (error instanceof DOMException && error.name === "AbortError") {
    return new ApiError(
      "A requisição foi cancelada ou demorou demais para responder.",
      0,
      null,
      null,
    );
  }

  if (error instanceof TypeError) {
    return new ApiError(
      `Não foi possível conectar ao backend. Verifique se a API está no ar e se o CORS está configurado.`,
      0,
      "Detalhe técnico: " + error.message,
      null,
    );
  }

  const message = error instanceof Error ? error.message : String(error);
  return new ApiError(message || `Falha inesperada durante ${context}.`, 500);
}

async function request<T>(
  path: string,
  init: RequestInit,
  signal?: AbortSignal,
): Promise<T> {
  let response: Response;
  try {
    response = await fetch(apiUrl(path), { ...init, signal: signal ?? null });
  } catch (error) {
    throw toApiError(error, path);
  }

  if (!response.ok) {
    let payload: unknown = null;
    try {
      payload = await response.json();
    } catch {
      /* resposta sem JSON (ex.: página de erro do proxy) */
    }
    const detail = extractDetail(
      payload,
      `Erro ${response.status} ao chamar ${path}.`,
    );
    const retryAfterHeader = response.headers.get("Retry-After");
    const retryAfter = retryAfterHeader
      ? Number.parseInt(retryAfterHeader, 10)
      : null;
    throw new ApiError(
      detail,
      response.status,
      null,
      Number.isNaN(retryAfter) ? null : retryAfter,
    );
  }

  try {
    return (await response.json()) as T;
  } catch {
    throw new ApiError(
      "O backend devolveu uma resposta que não é JSON válido.",
      response.status,
    );
  }
}

/** `GET /api/health` */
export async function fetchHealth(
  signal?: AbortSignal,
): Promise<HealthResponse> {
  return request<HealthResponse>("/api/health", { method: "GET" }, signal);
}

/** `POST /api/analyze/github` */
export async function analyzeGitHub(
  body: AnalyzeGitHubRequest,
  signal?: AbortSignal,
): Promise<AnalysisReport> {
  return request<AnalysisReport>(
    "/api/analyze/github",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    },
    signal,
  );
}

/** `POST /api/analyze/upload` (multipart) */
export async function analyzeUpload(
  file: File,
  signal?: AbortSignal,
): Promise<AnalysisReport> {
  const form = new FormData();
  form.append("file", file, file.name || "package.json");
  return request<AnalysisReport>(
    "/api/analyze/upload",
    { method: "POST", body: form },
    signal,
  );
}
