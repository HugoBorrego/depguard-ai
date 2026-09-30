# DepGuard AI

Analisador de dependências Node.js. Recebe a URL de um repositório público no GitHub
ou um `package.json` enviado por upload, consulta o registro npm e a base de
vulnerabilidades [OSV.dev](https://osv.dev), e devolve um relatório com achados por
dependência, impacto e recomendação.

A análise por IA é **opcional**: o relatório é sempre produzido por regras
determinísticas, e a camada de IA apenas acrescenta leitura e contexto quando há
`ANTHROPIC_API_KEY` configurada.

---

## Índice

- [Como funciona](#como-funciona)
- [Subindo com Docker](#subindo-com-docker)
- [Rodando localmente](#rodando-localmente)
- [Variáveis de ambiente](#variáveis-de-ambiente)
- [API](#api)
- [Regras de detecção](#regras-de-detecção)
- [Testes e qualidade](#testes-e-qualidade)
- [Estrutura do projeto](#estrutura-do-projeto)
- [Segurança](#segurança)
- [Limitações conhecidas](#limitações-conhecidas)

---

## Como funciona

```
                    ┌──────────────────────────────────────────┐
  GitHub URL  ──────▶│  app/services/analyzer.py (orquestração)  │
  ou upload   ──────▶│  coleta → registry → OSV → regras → IA    │
                    └───────────────┬──────────────────────────┘
                                    │
        ┌───────────────┬───────────┼────────────┬──────────────┐
        ▼               ▼           ▼            ▼              ▼
  github.py     npm_registry.py  osv.py     rules.py     llm_analyzer.py
  (manifests)   (versões,        (CVEs)     (achados)    (Contexto +
                 depreciação,               (severidade)  recomendação)
                 autores)
```

O pipeline é sequencial e cada etapa é idempotente:

1. **Coleta** — baixa o(s) `package.json` (GitHub) ou valida o arquivo enviado.
2. **npm Registry** — uma chamada por pacote, em paralelo limitado, com cache
   ETag/TTL. Distingue três estados: **existe**, **não existe (404)** e
   **indisponível (timeout/5xx)**. Essa distinção evita accuse um pacote de
   "não encontrado" só porque a rede falhou.
3. **OSV.dev** — um `querybatch` para todas as dependências de uma vez, com
   cálculo de severidade CVSS v3.1 quando o advisory não traz nota.
4. **Regras locais** — avalia depreciação, faixa de versão permissiva,
   ausência de manutenção, versão desatualizada, possível typosquatting e
   conflito de `engines.node`.
5. **IA (opcional)** — envia apenas os fatos coletados, em lotes, e exige
   resposta em JSON estrito que é validado e reconciliado com as regras.

Se qualquer serviço externo falhar, a análise **continua** com o que deu certo e
registra um aviso em `meta.warnings`. O relatório nunca é descartado por causa de
uma indisponibilidade externa.

---

## Subindo com Docker

Pré-requisito: Docker Desktop ou Docker Engine com Compose v2.

```bash
cp .env.example .env
# opcional: edite .env e defina ANTHROPIC_API_KEY para ligar a IA

docker compose up --build
```

- Frontend: <http://localhost:5173>
- API (docs interativas): <http://localhost:8000/docs>

O container do frontend serve a SPA pelo nginx e faz proxy de `/api` para o
backend, então o navegador só conversa com uma origem. O proxy é montado em
runtime via `API_UPSTREAM`, sem rebuild.

Para desligar a IA, basta deixar `ANTHROPIC_API_KEY` vazio no `.env` — não é
preciso alterar código nem rebuildar a imagem.

---

## Rodando localmente

### Backend

Requer Python 3.12 ou superior.

```bash
cd backend
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
uvicorn app.main:app --reload --port 8000
```

### Frontend

Requer Node 20 ou superior.

```bash
cd frontend
npm ci
npm run dev
```

O Vite faz proxy de `/api` para `http://127.0.0.1:8000` em desenvolvimento
(configurável em `frontend/.env`). Em produção, `VITE_API_URL` é embutido no
bundle em build time; vazio significa "mesma origem, prefixo `/api`".

Para testar a interface sem subir o backend, existe um manifesto propositalmente
problemático em `examples/problematic-project/package.json` — arraste-o para a
aba de upload.

---

## Variáveis de ambiente

Todas vivem no `.env` da raiz (veja `.env.example`). As mais relevantes:

| Variável | Padrão | Efeito |
| --- | --- | --- |
| `ANTHROPIC_API_KEY` | *(vazia)* | Liga a análise por IA. Vazia = só regras determinísticas. |
| `ANTHROPIC_MODEL` | `claude-sonnet-4-5` | Modelo usado nos lotes. |
| `GITHUB_TOKEN` | *(vazia)* | Sobe o rate limit do GitHub de 60 para 5000 req/h **e habilita repositórios privados**. |
| `CORS_ORIGINS` | `http://localhost:5173,...` | Origens permitidas, separadas por vírgula. |
| `RATE_LIMIT_PER_MINUTE` | `10` | Requisições por IP por minuto, na API. |
| `MAX_UPLOAD_BYTES` | `1048576` | Tamanho máximo do `package.json` enviado. |
| `REGISTRY_CACHE_TTL_SECONDS` | `3600` | Validade do cache do registro npm. |
| `HTTP_MAX_RETRIES` | `3` | Tentativas extras em erro de rede ou 5xx. |
| `CACHE_ENABLED` | `true` | Cache em memória do registry. |
| `VITE_API_URL` | *(vazia)* | URL pública do backend para o bundle do frontend. |

A chave da Anthropic é usada **apenas no backend**. Ela nunca é exposta ao
navegador, não aparece nos logs e não é devolvida por `/api/health` (que responde
só com booleanos como `aiEnabled`).

---

## API

Base: `http://localhost:8000`

### `GET /api/health`

Estado do serviço e dos recursos opcionais. Nunca expõe segredos.

```json
{
  "status": "ok",
  "version": "1.0.0",
  "environment": "development",
  "aiEnabled": false,
  "githubTokenConfigured": false,
  "cacheEntries": 0,
  "serverTime": "2026-09-30T15:12:13.055748+00:00"
}
```

### `POST /api/analyze/upload`

`multipart/form-data` com o campo **`file`** contendo o `package.json`.

```bash
curl -X POST http://localhost:8000/api/analyze/upload \
  -F "file=@examples/problematic-project/package.json"
```

Erros: `400` (JSON inválido ou sem seções de dependência), `413` (acima do
limite), `415` (não é `package.json`), `429` (rate limit).

### `POST /api/analyze/github`

```json
{ "url": "https://github.com/facebook/react" }
```

Analisa o `package.json` da branch padrão. Em monorepos, detecta até 5 manifestos
com o padrão `packages/*/package.json` e os analisa em conjunto.

Erros: `404` (sem `package.json` ou inacessível), `422` (corpo inválido ou URL fora
do `github.com`), `429`, `503` (GitHub ou registry indisponíveis).

### `GET /api/analyze/github/stream?url=...`

Mesma análise, porém com progresso por **Server-Sent Events** — eventos
`progress` (`{"step": ..., "progress": 0.35}`) e um evento final com o relatório.
Útil para analyses grandes sem polling.

### Formato da resposta

A mesma estrutura vale para `/upload` e `/github`. Exemplo real, com a lista de
achados truncada:

```jsonc
{
  "project": {
    "name": "meu-projeto",
    "version": "1.0.0",
    "source": "github",                                // "github" | "upload"
    "sourceUrl": "https://github.com/acme/meu-projeto", // null no upload
    "manifests": ["package.json"],        // caminhos dos arquivos analisados
    "totalDependencies": 3,
    "runtimeDependencies": 3,
    "devDependencies": 0,
    "engineNode": ">=18",
    "license": "MIT"
  },
  "summary": { "critical": 0, "high": 2, "medium": 0, "low": 0, "ok": 1 },
  "findings": [
    {
      "package": "minimist",
      "requestedVersion": "0.0.8",
      "resolvedVersion": "0.0.8",
      "latestVersion": "1.2.8",
      "severity": "high",
      "issues": [
        {
          "type": "vulnerability",
          "description": "GHSA-VH95-RMGR-6W4M: afeta a versão 0.0.8 de 'minimist'...",
          "source": "osv",          // osv | npm_registry | regra_local | analise_ia
          "references": ["https://osv.dev/vulnerability/GHSA-vh95-rmgr-6w4m"]
        },
        {
          "type": "outdated",
          "description": "'minimist' está defasado dentro da mesma major: 0.0.8 contra 1.2.8...",
          "source": "npm_registry",
          "references": ["https://www.npmjs.com/package/minimist"]
        }
      ],
      "recommendation": "Procurar uma alternativa mantida ou um fork seguro.",
      "breakingChangeRisk": "high",
      "section": "dependencies",
      "description": "parse argument options",
      "latestPublishedAt": "2023-02-09T20:59:49.233Z",
      "maintainers": ["shadowspawn", "ljharb", "emilbayes"],
      "engines": {},
      "licenses": ["MIT"],
      "weeklyDownloads": null,
      "deprecatedMessage": null,
      "repository": "github.com/minimistjs/minimist",
      "isDevDependency": false,
      "analyzedByAi": false,
      "issueCount": 4
    }
  ],
  "meta": {
    "analyzedAt": "2026-09-30T15:12:13.055748+00:00",
    "durationMs": 1820,
    "aiEnabled": false,
    "aiModel": null,
    "aiBatches": 0,
    "aiFailures": 0,
    "npmEtagCache": 3,
    "warnings": []   // indisponibilidades e ressalvas da análise
  }
}
```

---

## Regras de detecção

| Tipo | Severidade | O que significa |
| --- | --- | --- |
| `not_found` | crítica | A versão declarada não existe no registro. |
| `vulnerability` | alta (ou a do advisory) | CVE conhecida para a versão resolvida, via OSV.dev. |
| `deprecated` | alta | O pacote marca a versão (ou a si) como depreciada. |
| `unmaintained` | média | Sem publicação há mais de 2 anos, ou com poucos autores. |
| `outdated` | média | Versão muito atrás da última publicada, ou dentro da mesma major. |
| `suspicious` | alta | Nome parecido com um pacote popular (possível typosquatting). |
| `loose_range` | baixa | `*`, `latest` ou faixa aberta: a instalação pode variar sozinha. |
| `prerelease` | baixa | Fixado em `beta`/`rc`/`next`. |
| `engine_conflict` | média | O pacote exige um Node mais novo que o declarado pelo projeto. |

A versão **resolvida** é a que o npm instalaria de fato: a mais alta que satisfaz
a faixa declarada, caindo para a base da faixa quando ela existe. Isso evita o
falso positivo mais comum — acusar `^4.17.15` de "desatualizado" quando a `latest`
já está dentro da faixa.

---

## Testes e qualidade

```bash
cd backend
pytest              # 210 testes
ruff check app tests
python -m pyright
```

A suíte não toca a rede: GitHub, registro npm e OSV são mockados com `respx`.
Cobrem parsing de `package.json`, proteção contra SSRF, rate limit, semver e
faixas, CVSS, degradação graciosa quando um serviço externo cai, e o formato
completo da resposta.

No frontend:

```bash
cd frontend
npm run typecheck
npm run lint
npm run build
```

---

## Estrutura do projeto

```
.
├── backend/
│   ├── app/
│   │   ├── core/          config, http_client (retry+cache), security (SSRF/rate limit), semver, logging
│   │   ├── schemas/       contrato Pydantic v2 da API
│   │   ├── services/      analyzer, github, npm_registry, osv, rules, llm_analyzer
│   │   ├── routers/       health, analyze
│   │   └── prompts/       analyze.md (instrução da IA)
│   └── tests/             210 testes
├── frontend/
│   └── src/
│       ├── components/    abas, cartões, tabela, filtros, progresso, tema
│       ├── lib/           cliente HTTP, formatação, exportação
│       └── types/         tipos espelhando o contrato do backend
├── examples/             package.json de teste
└── docker-compose.yml
```

---

## Segurança

- **SSRF**: URLs do GitHub são validadas por allowlist de host e de rede privada
  (`localhost`, RFC1918, link-local, IPv6 loopback). O download do `package.json`
  acontece apenas contra `raw.githubusercontent.com`.
- **Rate limit** por IP na API, com resposta `429`.
- **Upload** limitado em tamanho, com validação de nome, encoding e estrutura antes
  do parse.
- **Segredos** ficam no backend; `/api/health` responde apenas com booleanos e os
  logs passam por um filtro de redação.
- **A IA não executa nada**: recebe fatos já coletados e devolve JSON que é
  validado contra o schema antes de entrar no relatório. Achados da IA nunca
  substituem os das regras — são mesclados e reconciliados.

---

## Limitações conhecidas

- **Repositórios privados**: o requisito original é análise de repositórios
  públicos. Definir `GITHUB_TOKEN` amplia a functionality para repositórios
  privados do próprio usuário; o token nunca é exposto ao frontend.
- **Não existe instalação nem execução de código**: a análise é estática, sobre
  metadados. Não substitui `npm audit` para a árvore completa de transitivas.
- **Faixas**: versões por git (`github:user/repo`), tarball e tags móveis não têm
  semver para comparar. Recebem `loose_range`, e a comparação com a `latest` é
  ignorada de propósito.
- **Rate limits de terceiros**: sem `GITHUB_TOKEN` o GitHub limita a 60 req/h por
  IP. O OSV e o registro npm podem aplicar limites próprios em-ip, que se
  manifestam como avisos em `meta.warnings`, não como erro.
- **Cache em memória**: cada processo tem o seu. Em deploy com múltiplos workers,
  o cache não é compartilhado.
- **Análise por IA**: os lotes usam 1 tentativa + 2 retries. Falhas do modelo são
  registradas em `meta.aiFailures` e nunca invalidam o relatório determinístico.
