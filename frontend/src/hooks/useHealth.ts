/** Hook que consulta o health do backend e mostra o status da IA. */

import { useEffect, useState } from "react";

import { fetchHealth } from "@/lib/api";
import type { HealthResponse } from "@/types/api";

export type ApiStatus = "checking" | "online" | "offline";

export interface UseHealthResult {
  status: ApiStatus;
  health: HealthResponse | null;
  error: string | null;
  refresh: () => void;
}

export function useHealth(): UseHealthResult {
  const [status, setStatus] = useState<ApiStatus>("checking");
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [nonce, setNonce] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    let cancelled = false;

    (async () => {
      try {
        const data = await fetchHealth(controller.signal);
        if (cancelled) return;
        setHealth(data);
        setError(null);
        setStatus("online");
      } catch (err) {
        if (cancelled) return;
        setHealth(null);
        setError(
          err instanceof Error
            ? err.message
            : "Falha ao consultar /api/health.",
        );
        setStatus("offline");
      }
    })();

    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [nonce]);

  return { status, health, error, refresh: () => setNonce((n) => n + 1) };
}
