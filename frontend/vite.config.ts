import { fileURLToPath, URL } from 'node:url';

import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

/**
 * Configuração do Vite.
 *
 * - `VITE_API_URL` (produção): URL pública do backend. Se vazio, o frontend
 *   assume que a API está no mesmo host, no prefixo `/api` (configuração
 *   padrão do docker-compose e de Vercel/Netlify com rewrites).
 * - Em desenvolvimento, o proxy abaixo encaminha `/api` para o backend local,
 *   evitando CORS e mantendo a URL relativa.
 */
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const backendUrl = env.VITE_BACKEND_PROXY_URL || 'http://127.0.0.1:8000';

  return {
    plugins: [react()],
    resolve: {
      alias: {
        '@': fileURLToPath(new URL('./src', import.meta.url)),
      },
    },
    server: {
      port: 5173,
      strictPort: false,
      proxy: {
        '/api': {
          target: backendUrl,
          changeOrigin: true,
          secure: false,
        },
      },
    },
    preview: {
      port: 4173,
      proxy: {
        '/api': {
          target: backendUrl,
          changeOrigin: true,
          secure: false,
        },
      },
    },
    build: {
      outDir: 'dist',
      sourcemap: mode !== 'production',
      target: 'es2022',
      rollupOptions: {
        output: {
          manualChunks: {
            react: ['react', 'react-dom'],
          },
        },
      },
    },
  };
});
