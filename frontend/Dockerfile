# ---- Etapa 1: build dos assets estáticos ------------------------------------
FROM node:22-alpine AS build

WORKDIR /app

# URL pública do backend embutida no bundle. Vazio = usa /api no mesmo host,
# que é o padrão quando o nginx desta imagem faz o proxy reverso.
ARG VITE_API_URL
ARG VITE_BACKEND_PROXY_URL
ENV VITE_API_URL=$VITE_API_URL
ENV VITE_BACKEND_PROXY_URL=$VITE_BACKEND_PROXY_URL

# Dependências primeiro (cache reaproveitado enquanto o lockfile não muda)
COPY package.json package-lock.json ./
RUN npm ci

# Código-fonte e build
COPY . .
RUN npm run build

# ---- Etapa 2: imagem final com nginx ---------------------------------------
FROM nginx:1.27-alpine AS runtime

# Só as variáveis API_* são substituídas em runtime; $host, $uri etc. ficam intactos.
ENV NGINX_ENVSUBST_FILTER="^API_"
ENV API_UPSTREAM="http://backend:8000"

# Template: o entrypoint oficial do nginx roda envsubst em /etc/nginx/templates
COPY nginx.conf /etc/nginx/templates/default.conf.template
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://127.0.0.1/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
