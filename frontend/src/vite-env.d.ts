/// <reference types="vite/client" />

/**
 * Variáveis de ambiente injetadas pelo Vite.
 * Declaradas aqui para que o TypeScript strict reconheça `import.meta.env.VITE_API_URL`.
 */
interface ImportMetaEnv {
  /** URL pública do backend. Vazio = usa `/api` no mesmo host. */
  readonly VITE_API_URL?: string;
  /** Backend usado pelo proxy de desenvolvimento (padrão: http://127.0.0.1:8000). */
  readonly VITE_BACKEND_PROXY_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
