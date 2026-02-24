# X MCP Server — Plan de contribución a xdevplatform/xmcp

## 1. Análisis del repo actual

### Estado (Feb 2026)

- **Autor**: Vardhan Agnihotri (`vagnihotri@twitter.com`) — empleado de X
- **Commits**: 2 (30 ene - 6 feb 2026) — muy reciente
- **Archivos**: 5 (`server.py`, `test_grok_mcp.py`, `requirements.txt`, `env.example`, `README.md`)
- **Líneas de código**: ~470 en server.py
- **Stars**: 11 | Forks: 5 | Watchers: 0
- **Licencia**: Ninguna ⚠️
- **Releases/Tags**: Ninguno
- **CI/CD**: Ninguno
- **Tests**: Solo un test manual con Grok (`test_grok_mcp.py`)
- **Docker**: No existe

### Cómo funciona

```
Startup:
1. Carga .env
2. Ejecuta OAuth 1.0a flow → abre browser → callback local → tokens en memoria
3. Descarga OpenAPI spec de X (https://api.twitter.com/2/openapi.json)
4. Filtra endpoints de streaming/webhooks
5. FastMCP.from_openapi() genera ~100+ tools automáticamente
6. Arranca server HTTP en localhost:8000/mcp

Cada request:
1. httpx event hooks → firma la request con OAuth1
2. Envía a X API
3. Devuelve resultado
```

### Arquitectura clave: auto-generación de tools

El server NO define tools manualmente. Usa `FastMCP.from_openapi()` que lee el
OpenAPI spec de X y genera tools automáticamente. Esto significa:

**Ventajas**:

- 100+ tools disponibles sin código manual
- Se actualiza automáticamente cuando X añade endpoints
- Tool filtering via env vars (`X_API_TOOL_ALLOWLIST`, `X_API_TOOL_DENYLIST`, `X_API_TOOL_TAGS`)

**Problemas**:

- Sin safety annotations (auto-generated tools no las tienen)
- Sin validación custom de inputs
- Sin formateo inteligente de respuestas
- Tool names son los operationIds de X (ej: `getUsersByUsername`, `createPosts`)

### Lo que falta para ser production-ready

| Categoría          | Estado actual                           | Necesario                                  |
| ------------------ | --------------------------------------- | ------------------------------------------ |
| Auth               | OAuth 1.0a (browser, tokens en memoria) | OAuth 2.0 PKCE (multi-user, persistente)   |
| Transporte         | `http` (legacy)                         | `streamable-http` (spec 2025-06-18)        |
| Safety annotations | Ninguna                                 | Obligatorio para directorio Anthropic      |
| Multi-user         | No (single session)                     | Sí (tokens por usuario)                    |
| Token persistence  | En memoria (se pierde al reiniciar)     | Base de datos/KV/archivo                   |
| Token refresh      | No                                      | Sí (tokens OAuth2 expiran en 2h)           |
| Containerización   | No                                      | Dockerfile + docker-compose                |
| Remote deploy      | Solo localhost                          | HTTPS, CORS, health check                  |
| Licencia           | No existe                               | MIT o Apache 2.0                           |
| Tests              | Solo test_grok_mcp.py (manual)          | Unit tests + integration tests             |
| CI/CD              | No                                      | GitHub Actions                             |
| Docs               | README básico                           | Setup guide, examples, privacy policy      |
| Error handling     | Logging básico                          | Rate limits, retries, user-friendly errors |

---

## 2. Estrategia: fork funcional primero, upstream después

### Principio: ship primero, contribuir después

No PRs incrementales. Construir todo en un fork propio hasta tener un producto
funcional y desplegado. Una vez que funcione en Claude.ai como conector real,
entonces decidir si abrir un PR único al upstream o mantener el fork como
proyecto independiente.

**Por qué**:

- Un fork funcionando habla más que 6 PRs abiertos sin revisar
- Libertad total para iterar sin esperar aprobación de nadie
- La narrativa de build in public es "mira, funciona" no "he abierto un PR"
- Si X ignora el repo (2 commits, 11 stars), tu fork se convierte en la referencia
- Si X quiere adoptar tus cambios, pueden cherry-pick o pedirte un PR

### Milestones del fork

```
M1: Setup + Dockerfile + transport ── Funciona en Docker              (~1 día)
M2: Safety annotations ────────────── Tools con hints correctos       (~0.5 día)
M3: OAuth 2.0 Authorization Proxy ─── Funciona en Claude.ai           (~5 días)
M4: Tests + CI ────────────────────── Quality gate                    (~1.5 días)
M5: Docs + deploy ─────────────────── Production-ready                (~1.5 días)
M6: Rate limits + polish ──────────── Robusto                         (~1 día)
    ────────────────────────────────────────────────────────────
    TOTAL                                                       ~10.5 días
```

### Cuándo contactar a X/upstream

Una vez M5 completado (server desplegado y funcionando en Claude.ai):

- Opción A: Abrir UN solo PR con todos los cambios + demo en vídeo
- Opción B: Mantener el fork como proyecto propio con atribución
- Opción C: Publicar el fork y esperar a que X te contacte

La decisión se toma en ese momento, no ahora.

---

## 3. Milestones detallados

### M1: Dockerfile + Streamable HTTP + estructura del proyecto

**Objetivo**: Hacer que xmcp sea desplegable como container remoto.

**Cambios**:

1. **`Dockerfile`** (nuevo):

   ```dockerfile
   FROM python:3.12-slim
   WORKDIR /app
   COPY requirements.txt .
   RUN pip install --no-cache-dir -r requirements.txt
   COPY . .
   EXPOSE 8000
   CMD ["python", "server.py"]
   ```

2. **`docker-compose.yml`** (nuevo):

   ```yaml
   services:
     xmcp:
       build: .
       ports:
         - "8000:8000"
       env_file: .env
       environment:
         - MCP_HOST=0.0.0.0
   ```

3. **`server.py`** — cambiar transport:

   ```python
   # Antes:
   mcp.run(transport="http", host=host, port=port)
   # Después:
   mcp.run(transport="streamable-http", host=host, port=port)
   ```

4. **`server.py`** — bind a `0.0.0.0` por defecto para containers:

   ```python
   host = os.getenv("MCP_HOST", "0.0.0.0")
   ```

5. **`.dockerignore`** (nuevo):

   ```
   .env
   .venv
   __pycache__
   .git
   ```

6. **README.md** — añadir sección "Docker deployment"

**Impacto**: Cualquiera puede deployar xmcp en un container con `docker compose up`.
Cambio no-breaking: el modo local sigue funcionando igual.

---

### M2: Safety annotations en tools auto-generados

**Objetivo**: Cumplir el requisito obligatorio de Anthropic para el directorio.

**Solución confirmada**: FastMCP 2.5+ soporta `mcp_component_fn` — un callback
en `from_openapi()` que permite modificar cada componente in-place después de
crearlo. Esto resuelve el problema limpiamente sin tocar internals de FastMCP
ni contribuir al upstream.

> _"For fine-grained customization, you can provide a `mcp_component_fn` when
> creating the MCP server. After each MCP component has been created, this
> function is called on it and has the opportunity to modify it in-place."_
> — Docs FastMCP (gofastmcp.com/integrations/openapi)

**Cambios en `server.py`**:

1. **Construir mapeo operationId → HTTP method** durante el parsing del spec:

   ```python
   def build_method_map(spec: dict) -> dict[str, dict]:
       """Mapea cada operationId a su método HTTP y path."""
       method_map = {}
       for path, item in spec.get("paths", {}).items():
           if not isinstance(item, dict):
               continue
           for method, operation in item.items():
               if method.lower() not in HTTP_METHODS:
                   continue
               op_id = operation.get("operationId")
               if op_id:
                   method_map[op_id] = {"method": method.lower(), "path": path}
       return method_map
   ```

2. **Callback `mcp_component_fn` para inyectar annotations**:

   ```python
   from mcp.types import ToolAnnotations

   def make_annotation_fn(method_map: dict):
       """Factory que crea el callback con acceso al method_map."""
       def add_safety_annotations(component):
           op_id = component.name
           info = method_map.get(op_id, {})
           method = info.get("method", "get")

           if method in ("get", "head", "options"):
               component.annotations = ToolAnnotations(
                   readOnlyHint=True,
                   destructiveHint=False,
                   openWorldHint=True,
               )
           elif method == "delete":
               component.annotations = ToolAnnotations(
                   readOnlyHint=False,
                   destructiveHint=True,
                   openWorldHint=True,
               )
           else:
               # POST/PUT/PATCH — write pero no destructive por defecto
               component.annotations = ToolAnnotations(
                   readOnlyHint=False,
                   destructiveHint=False,
                   openWorldHint=True,
               )
       return add_safety_annotations
   ```

3. **Integrar en `create_mcp()`**:

   ```python
   method_map = build_method_map(filtered_spec)
   annotation_fn = make_annotation_fn(method_map)

   return FastMCP.from_openapi(
       openapi_spec=filtered_spec,
       client=client,
       name="X API MCP",
       mcp_component_fn=annotation_fn,   # ← inyecta annotations
   )
   ```

4. **Override manual** (opcional): archivo `annotation_overrides.json` para
   casos ambiguos donde el HTTP method no refleja la intención real:
   ```json
   {
     "hideReply": { "readOnlyHint": false, "destructiveHint": true },
     "unfollow": { "readOnlyHint": false, "destructiveHint": true }
   }
   ```
   El callback aplica primero la regla por method, luego overrides del archivo.

**No se necesita**:

- ~~Contribuir a FastMCP~~ — `mcp_component_fn` ya existe (v2.5+)
- ~~Post-processing de internals~~ — API pública, no hace falta hackear
- ~~Monkey-patching~~ — solución limpia y mantenible

**Impacto**: Todas las tools (~100+) tendrán safety annotations correctas.
Requisito obligatorio del directorio de Anthropic cumplido.

**Estimación**: 0.5-1 día. Es el milestone más sencillo del roadmap.

---

### M3: OAuth 2.0 — Authorization Server proxy para Claude.ai

**Objetivo**: Convertir xmcp en un conector remoto compatible con Claude.ai,
donde cada usuario de Claude se autentica con su propia cuenta de X.

**⚠️ Cambio de modelo mental importante**: El server actual tiene un solo usuario
que se autentica al arrancar (OAuth1 + browser). Para funcionar como conector
remoto en Claude.ai, el server necesita ser un **OAuth Authorization Server proxy**
que orqueste la autenticación entre Claude y X para cada usuario individual.

#### Cómo funciona el flujo real en Claude.ai

```
1. Usuario hace click en "Connect" en Claude.ai Settings > Connectors
                    ↓
2. Claude descubre el server OAuth:
   GET https://tu-server.com/.well-known/oauth-authorization-server
   ← Tu server responde con metadata (RFC 8414):
     {
       "issuer": "https://tu-server.com",
       "authorization_endpoint": "https://tu-server.com/authorize",
       "token_endpoint": "https://tu-server.com/token",
       "registration_endpoint": "https://tu-server.com/register",
       "response_types_supported": ["code"],
       "code_challenge_methods_supported": ["S256"],
       "scopes_supported": ["tweet.read", "tweet.write", "users.read", ...]
     }
                    ↓
3. Claude se auto-registra como cliente OAuth (Dynamic Client Registration):
   POST https://tu-server.com/register  (RFC 7591)
   Body: { "client_name": "Claude", "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"] }
   ← Tu server devuelve: { "client_id": "xxx", "client_secret": "yyy" }
                    ↓
4. Claude redirige al usuario a TU endpoint /authorize
   GET https://tu-server.com/authorize?
       client_id=xxx&
       redirect_uri=https://claude.ai/api/mcp/auth_callback&
       code_challenge=HASH&
       code_challenge_method=S256&
       state=abc&
       scope=tweet.read+tweet.write+users.read
                    ↓
5. TU server redirige al usuario a X para login real:
   → https://x.com/i/oauth2/authorize?
       client_id=TU_X_CLIENT_ID&
       redirect_uri=https://tu-server.com/x/callback&
       code_challenge=NUEVO_HASH&
       scope=tweet.read+tweet.write+users.read+offline.access&
       state=INTERNAL_STATE
                    ↓
6. El usuario ve la pantalla de login/consentimiento de X en su browser
   → Acepta → X redirige a tu server
                    ↓
7. TU server recibe el code de X:
   GET https://tu-server.com/x/callback?code=X_AUTH_CODE&state=INTERNAL_STATE
   → Intercambia X_AUTH_CODE por tokens de X (access + refresh)
   → Almacena tokens de X asociados al usuario
   → Genera un code propio para Claude
   → Redirige al usuario a Claude:
     https://claude.ai/api/mcp/auth_callback?code=TU_CODE&state=abc
                    ↓
8. Claude intercambia el code en tu endpoint /token:
   POST https://tu-server.com/token
   Body: { grant_type: "authorization_code", code: "TU_CODE", code_verifier: "..." }
   ← Tu server devuelve: { access_token: "SESSION_TOKEN", refresh_token: "..." }
                    ↓
9. En cada request MCP, Claude envía el Bearer token:
   Authorization: Bearer SESSION_TOKEN
   → Tu server busca los tokens de X asociados a esa sesión
   → Firma la request a X API con el token del usuario
   → Si el token de X expiró, usa refresh_token para renovarlo
```

**Dato clave de Anthropic**: "OAuth is the only way to uniquely identify users.
We do not forward IP addresses, user IDs, or other metadata from end-users to
MCP servers." — Esto confirma que el OAuth proxy es obligatorio, no opcional.

#### Archivos nuevos

1. **`auth/oauth_server.py`** — el OAuth Authorization Server proxy:
   - `GET  /.well-known/oauth-authorization-server` — metadata (RFC 8414)
   - `POST /register` — Dynamic Client Registration (RFC 7591)
   - `GET  /authorize` — inicia el flow, redirige a X
   - `GET  /x/callback` — recibe code de X, genera code propio, redirige a Claude
   - `POST /token` — intercambia codes, devuelve tokens a Claude
   - `POST /token` (refresh) — renueva tokens cuando expiran

2. **`auth/x_oauth2.py`** — cliente OAuth 2.0 PKCE hacia X API:
   - Generación de `code_verifier` + `code_challenge` (S256)
   - Authorization URL builder → `https://x.com/i/oauth2/authorize`
   - Token exchange → `https://api.x.com/2/oauth2/token`
   - Token refresh automático (tokens de X expiran en 2h)

3. **`auth/token_store.py`** — almacenamiento multi-usuario:
   - Interface `TokenStore` (abstracta)
   - `FileTokenStore` — tokens en archivo JSON (default, desarrollo)
   - `MemoryTokenStore` — para tests
   - Keyed por session_token → { x_access_token, x_refresh_token, expires_at }
   - Preparado para Redis/KV en producción

4. **`auth/client_registry.py`** — registro de clientes DCR:
   - Almacena client_id/client_secret generados para cada cliente (Claude)
   - En la práctica solo habrá 1-2 clientes (Claude.ai, Claude Desktop)

#### Cambios en `server.py`

5. Nuevo env var `X_AUTH_MODE`:
   - `oauth1` (default) — mantiene el flow actual con browser, backward compat
   - `oauth2-local` — OAuth2 PKCE con browser local (para desarrollo)
   - `oauth2-remote` — OAuth Authorization Server proxy (para Claude.ai)

6. Cuando `X_AUTH_MODE=oauth2-remote`:
   - NO ejecuta OAuth al arrancar
   - Monta los endpoints del OAuth server en la misma app HTTP
   - Cada request MCP extrae el session_token del header Authorization
   - Busca los tokens de X del usuario en el TokenStore
   - Inyecta el Bearer token de X en las requests a la API

7. Middleware de autenticación per-request:
   ```python
   async def auth_middleware(request: httpx.Request) -> None:
       """Inyecta el token de X del usuario actual en cada request a X API."""
       session_token = get_current_session_token()  # del contexto MCP
       x_tokens = await token_store.get(session_token)
       if x_tokens.is_expired():
           x_tokens = await x_oauth2.refresh(x_tokens.refresh_token)
           await token_store.update(session_token, x_tokens)
       request.headers["Authorization"] = f"Bearer {x_tokens.access_token}"
   ```

#### Cambios en `env.example`

8. Nuevas variables:

   ```
   # Auth mode: oauth1, oauth2-local, oauth2-remote
   X_AUTH_MODE=oauth1

   # OAuth2 settings (required for oauth2-local and oauth2-remote)
   X_OAUTH2_CLIENT_ID=        # Tu X Developer App client ID
   X_OAUTH2_CLIENT_SECRET=    # Tu X Developer App client secret
   X_OAUTH2_SCOPES=tweet.read tweet.write users.read offline.access

   # Remote OAuth server settings (required for oauth2-remote)
   X_MCP_PUBLIC_URL=          # URL pública del server (ej: https://xmcp.railway.app)
   X_TOKEN_STORE_PATH=.tokens.json
   ```

#### CORS requerido para Claude.ai

9. Allowlist de origins para Claude:

   ```python
   CLAUDE_ORIGINS = [
       "https://claude.ai",
       "https://claude.com",
       "https://www.anthropic.com",
       "https://api.anthropic.com",
   ]
   ```

10. Allowlist de callback URLs:
    - `https://claude.ai/api/mcp/auth_callback`
    - `http://localhost:*/callback` (para Claude Code / MCP Inspector)

#### Complejidad y riesgo

Este milestone es el **más complejo** del proyecto. El server pasa de ser un simple proxy
HTTP a ser un OAuth Authorization Server + proxy HTTP. Esto implica:

- **Seguridad**: generación segura de codes, PKCE validation, token storage
- **Estado**: hay que mantener state entre el redirect a X y el callback
- **Multi-user**: cada sesión MCP tiene sus propios tokens de X
- **Token lifecycle**: refresh automático, revocación, expiración

**Estimación realista**: 3-5 días de desarrollo, no 2.

**Backward compatible**: `X_AUTH_MODE=oauth1` mantiene el comportamiento actual.

---

### M4: Tests + CI/CD

**Objetivo**: Calidad y confianza en los cambios.

**Archivos nuevos**:

1. **`tests/`** directorio:
   - `test_filter_spec.py` — tests para `filter_openapi_spec()`, `should_exclude_operation()`
   - `test_oauth2.py` — tests para el flow OAuth2 PKCE (mocked)
   - `test_safety_annotations.py` — tests para `classify_tool_safety()`
   - `test_token_store.py` — tests para FileTokenStore
   - `test_comma_params.py` — tests para `collect_comma_params()`, `normalize_query_params()`
   - `conftest.py` — fixtures compartidos (mock OpenAPI spec, etc.)

2. **`pyproject.toml`** (nuevo) — configuración moderna de Python:

   ```toml
   [project]
   name = "xmcp"
   version = "0.1.0"
   requires-python = ">=3.9"
   dependencies = [
       "fastmcp",
       "httpx",
       "python-dotenv",
       "requests-oauthlib",
   ]

   [project.optional-dependencies]
   dev = ["pytest", "pytest-asyncio", "pytest-httpx", "ruff"]
   grok = ["xai-sdk", "xdk"]

   [tool.pytest.ini_options]
   asyncio_mode = "auto"

   [tool.ruff]
   line-length = 100
   ```

3. **`.github/workflows/ci.yml`** (nuevo):

   ```yaml
   name: CI
   on: [push, pull_request]
   jobs:
     test:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4
         - uses: actions/setup-python@v5
           with: { python-version: "3.12" }
         - run: pip install -e ".[dev]"
         - run: ruff check .
         - run: pytest
   ```

4. **Mover `xai-sdk` y `xdk` a optional dependencies** — no deberían ser
   requeridos para el server base, solo para el test client de Grok.

---

### M5: Documentación + Examples

**Objetivo**: Cumplir requisitos de documentación del directorio de Anthropic.

**Archivos nuevos/modificados**:

1. **`LICENSE`** (nuevo) — MIT License

2. **`PRIVACY.md`** (nuevo):
   - Qué datos se almacenan (solo tokens OAuth)
   - No se almacena contenido de tweets ni datos de usuario
   - Cómo revocar acceso
   - No se comparten datos con terceros

3. **`docs/DEPLOYMENT.md`** (nuevo):
   - Deploy con Docker
   - Deploy en Railway (1-click)
   - Deploy en Cloudflare Containers
   - Deploy en Cloud Run
   - Variables de entorno referencia

4. **`docs/EXAMPLES.md`** (nuevo) — mínimo 3 ejemplos para Anthropic:

   ```
   Ejemplo 1: "Search for recent tweets about artificial intelligence"
   → Tool: searchPostsRecent
   → El server busca tweets de los últimos 7 días

   Ejemplo 2: "Post a tweet saying: Just shipped our new MCP integration!"
   → Tool: createPosts
   → El server publica el tweet y devuelve el ID + URL

   Ejemplo 3: "Show me the profile of @xdevelopers and their latest tweets"
   → Tools: getUsersByUsername + getUsersPosts
   → El server devuelve perfil + tweets recientes
   ```

5. **`docs/CLAUDE_CONNECTOR.md`** (nuevo):
   - Cómo conectar xmcp como conector custom en Claude.ai
   - Configuración de callbacks de Claude
   - Troubleshooting

6. **`README.md`** — reescritura completa:
   - Badges (CI, license, Python version)
   - Descripción clara
   - Quick start (local + Docker + remote)
   - Tool list con categorías
   - Architecture diagram
   - Contributing guide
   - Link a docs/

---

### M6: Rate limiting + error handling + caching (polish)

**Objetivo**: Hacer el server robusto para uso en producción.

**Nota**: Multi-user y remote OAuth flow han sido absorbidos por M3, ya que
la arquitectura de OAuth Authorization Server proxy inherentemente soporta
múltiples usuarios (cada uno con su propia sesión y tokens de X).

**Cambios**:

1. **Rate limit awareness** — leer headers de X API:

   ```python
   async def handle_rate_limits(response: httpx.Response) -> None:
       remaining = response.headers.get("x-rate-limit-remaining")
       reset = response.headers.get("x-rate-limit-reset")
       if remaining == "0":
           wait_seconds = int(reset) - int(time.time())
           # Devolver error informativo al usuario con tiempo de espera
   ```

2. **Retry con backoff** para errores 429 y 5xx

3. **Response caching** opcional para GET requests (TTL corto, configurable)

4. **Health check endpoint** — `GET /health` para monitoring y probes de k8s/Railway

5. **Graceful error messages** — transformar errores crípticos de X API en
   mensajes útiles para el LLM

---

## 4. Plan de ejecución

### Semana 1: Fundamentos (M1 + M2)

| Día | Tarea                                            | Entregable                     |
| --- | ------------------------------------------------ | ------------------------------ |
| 1   | Fork repo, setup local, probar que funciona      | Fork funcional                 |
| 1   | Crear X Developer App con OAuth 2.0 configurado  | App lista                      |
| 2   | M1: Dockerfile + streamable-http + .dockerignore | Container funcional            |
| 3   | M2: Safety annotations con mcp_component_fn      | Annotations en todas las tools |

**Post Build in Public (día 2)**: "Forking the official X MCP server to make it
production-ready for Claude.ai. Day 1: Docker + Streamable HTTP." + demo gif.

### Semana 2: OAuth proxy (M3 — el gordo)

| Día | Tarea                                               | Entregable        |
| --- | --------------------------------------------------- | ----------------- |
| 4   | auth/x_oauth2.py — cliente PKCE hacia X API         | Módulo OAuth2     |
| 5   | auth/token_store.py + auth/client_registry.py       | Storage layer     |
| 6-7 | auth/oauth_server.py — endpoints RFC 8414/7591/6749 | OAuth server      |
| 8   | Integrar en server.py, CORS, 3 modos de auth        | Integración       |
| 9   | Test end-to-end con MCP Inspector + Claude.ai       | OAuth funcionando |

**Post Build in Public (día 6)**: "Building an OAuth 2.0 Authorization Server
proxy so Claude.ai users can connect their X accounts. Here's the double-redirect
flow." + diagrama del flujo.

### Semana 3: Polish + Deploy + Launch (M4-M6)

| Día | Tarea                                           | Entregable          |
| --- | ----------------------------------------------- | ------------------- |
| 10  | M4: Tests + CI + pyproject.toml                 | Quality gate        |
| 11  | M5: LICENSE, PRIVACY.md, docs, README           | Docs completas      |
| 12  | M6: Rate limits + health check + error handling | Production polish   |
| 12  | Deploy en Railway/Cloudflare Containers         | Server live         |
| 13  | Probar como custom connector en Claude.ai       | Demo funcional      |
| 13  | Decidir: PR upstream vs fork independiente      | Estrategia definida |

**Post Build in Public (día 13)**: "The X MCP server is live. Connect your X
account in Claude.ai and search tweets, post, manage bookmarks — all from chat."

- demo en vídeo.

### Post-launch: Anthropic directory submission

| Tarea                                             | Entregable         |
| ------------------------------------------------- | ------------------ |
| Preparar cuenta de test con sample data           | Cuenta lista       |
| Configurar Claude IP allowlists                   | IPs permitidas     |
| Submit al directorio de Anthropic                 | Submission enviada |
| (Opcional) Abrir PR al upstream con enlace a demo | Visibility         |

---

## 5. Relación con X/upstream

### Antes de empezar

- [ ] NO abrir Issues ni PRs todavía
- [ ] Fork silencioso, construir, deployar

### Una vez el fork esté live y funcional (semana 3)

Evaluar la situación y elegir una de estas opciones:

**Opción A: Abrir UN solo PR al upstream**

- Un PR grande con todos los cambios + enlace a demo funcional
- Mensaje: "He mejorado el server con OAuth2, Docker, annotations, y docs.
  Aquí está funcionando como conector de Claude.ai: [URL]. Happy to discuss."
- Pros: máxima visibilidad como contributor, posible merge
- Contras: pueden ignorarlo o tardar meses

**Opción B: Mantener el fork como proyecto propio**

- Publicar como `santiagoxyz/xmcp` (o nombre custom) con atribución
- Narrativa: "Enhanced fork of the official X MCP server, ready for Claude.ai"
- Pros: control total, velocidad de iteración, tu nombre como autor
- Contras: menos "oficial", potencial confusión con upstream

**Opción C: Publicar y esperar**

- Publicar el fork, hacer ruido en Twitter/LinkedIn con demos
- Si funciona bien y tiene tracción, X puede contactarte
- Pros: la tracción habla por sí sola
- Contras: pueden no enterarse

**Recomendación**: empezar con C (publicar + build in public), y si hay
tracción, abrir el PR (A) con la demo como evidencia. El peor caso es que
tienes un proyecto funcional y visible con tu nombre.

---

## 6. Consideraciones técnicas clave

### FastMCP.from_openapi() y safety annotations ✅ RESUELTO

`mcp_component_fn` (FastMCP 2.5+) permite modificar componentes in-place durante
la generación. No hace falta contribuir a FastMCP ni hackear internals.

```python
mcp = FastMCP.from_openapi(
    openapi_spec=spec,
    client=client,
    mcp_component_fn=add_safety_annotations,  # callback que modifica in-place
)
```

Verificar que la versión de FastMCP en requirements.txt sea >= 2.5.0.

### OAuth 2.0: tu server es un Authorization Server proxy

**Modelo mental correcto**: tu MCP server NO es solo un proxy HTTP hacia X.
Para Claude.ai, es un **OAuth Authorization Server** completo que:

1. Expone metadata de discovery (RFC 8414)
2. Acepta registros de clientes dinámicos (RFC 7591 / DCR)
3. Orquesta un doble redirect: Claude → tu server → X → tu server → Claude
4. Almacena tokens de X por usuario
5. Sirve tokens de sesión propios a Claude
6. Refresca tokens de X transparentemente

**Implicaciones arquitecturales**:

- El server pasa de ~470 líneas a ~1500+ líneas estimadas
- Necesita estado persistente (tokens, client registrations, pending auth flows)
- Necesita HTTPS obligatorio (los redirects OAuth no funcionan sin TLS)
- Necesita CORS configurado para orígenes de Claude
- El httpx client ya no puede ser singleton con un solo OAuth1 signer;
  cada request necesita buscar los tokens del usuario actual

**Referencia clave de Anthropic**: "OAuth is the only way to uniquely identify
users. We do not forward IP addresses, user IDs, or other metadata."

**Callback URL de Claude**: `https://claude.ai/api/mcp/auth_callback`

**Specs a implementar**:

- RFC 8414 — OAuth 2.0 Authorization Server Metadata
- RFC 7591 — Dynamic Client Registration (DCR)
- RFC 7636 — PKCE (doble: Claude→tuserver y tuserver→X)
- RFC 6749 — OAuth 2.0 core (authorization code grant)

### Flujos OAuth por modo de uso

| Modo           | Config                      | Flujo auth                    | Quién tiene los tokens   |
| -------------- | --------------------------- | ----------------------------- | ------------------------ |
| Local (actual) | `X_AUTH_MODE=oauth1`        | Browser → callback local      | En memoria del server    |
| Local OAuth2   | `X_AUTH_MODE=oauth2-local`  | Browser → callback local      | FileTokenStore           |
| Claude.ai      | `X_AUTH_MODE=oauth2-remote` | Claude→server→X→server→Claude | TokenStore (por usuario) |

### Rate limits de X API

El server actual no maneja rate limits. Necesitamos:

1. Leer headers `x-rate-limit-remaining` y `x-rate-limit-reset` de las respuestas
2. Si `remaining` = 0, devolver un error claro al usuario con el tiempo de espera
3. Opcionalmente: cache de respuestas para GET requests (con TTL corto)

### X API pricing vs modelo de deploy

Cada usuario de Claude se autentica con su propia cuenta de X. Esto significa
que los rate limits aplican **por usuario**, no por tu server. Tu X Developer
App define los tiers de acceso (Free/Basic/Pro), pero los límites de rate se
distribuyen entre todos los usuarios.

**Implicación**: no necesitas X API Basic ($200/mo) para un deploy multi-usuario.
El Free tier podría funcionar si los rate limits por usuario son suficientes.
Investigar los límites exactos del Free tier per-user antes de decidir.

---

## 7. Costes y recursos

| Concepto                         | Coste         | Notas                                        |
| -------------------------------- | ------------- | -------------------------------------------- |
| X Developer App (Free tier)      | $0            | Podría ser suficiente (rate limits per-user) |
| X API Basic (si Free no alcanza) | $200/mes      | Solo si necesitas más capacidad              |
| Railway (deploy)                 | ~$5/mes       | Pay per use                                  |
| Cloudflare Containers            | ~$5/mes       | Alternativa                                  |
| Dominio (opcional)               | $12/año       | x-mcp.dev o similar                          |
| **Total desarrollo**             | **$0**        |                                              |
| **Total producción (mínimo)**    | **~$5/mes**   | Si Free tier de X alcanza                    |
| **Total producción (máximo)**    | **~$205/mes** | Si necesitas X API Basic                     |

**Nota sobre pricing de X**: Como cada usuario de Claude se autentica con su
propia cuenta de X, los rate limits aplican per-user, no per-app. Investigar
si el Free tier es suficiente antes de pagar $200/mes por Basic.

---

## 8. Métricas de éxito

| Métrica                             | Target semana 3 | Target 3 meses  |
| ----------------------------------- | --------------- | --------------- |
| Fork desplegado y funcional         | Sí              | Sí              |
| Funciona como conector en Claude.ai | Sí              | Sí              |
| En directorio Anthropic             | Submitted       | Approved        |
| GitHub stars en el fork             | 10+             | 100+            |
| Posts Build in Public               | 4-5             | 15+             |
| Usuarios reales conectados          | 1 (tú)          | 20+             |
| Contacto con equipo de X            | No necesario    | Si hay tracción |
