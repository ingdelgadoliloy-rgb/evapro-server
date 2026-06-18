# EVALUAPRO-UTCH — Servidor (Render)

Servidor WebSocket + REST para sincronización de resultados en tiempo real.

## Variables de entorno (Render → Environment)

| Variable | Requerida | Descripción |
|---|---|---|
| `PORT` | No | Puerto (Render lo asigna automáticamente) |
| `ADMIN_SECRET` | **Sí** | Clave secreta para endpoints admin (DELETE results, POST teachers). Configura un valor aleatorio largo. |
| `ALLOWED_ORIGINS` | **Sí** | URLs de Netlify permitidas, separadas por coma. Ej: `https://evaluapro-utch.netlify.app` |
| `CLAUDE_API_KEY` | No | Clave Claude para fallback de YouTube transcripts |

## Seguridad aplicada v2.1

- **Rate limiting**: 30 req/min por IP para resultados; 20 para publicar examen; 10 para docentes.
- **ADMIN_SECRET**: endpoints destructivos (DELETE, POST /teachers, POST /exam) requieren header `x-admin-secret`.
- **CORS**: solo origenes configurados en `ALLOWED_ORIGINS`.
- **Cabeceras HTTP**: X-Content-Type-Options, X-Frame-Options, Referrer-Policy, X-XSS-Protection.
- **Sanitización**: todos los payloads de entrada son validados y recortados.
- **Límites**: máx. 500 sesiones, 300 resultados/sesión, 200 preguntas/paquete.
- **TTL sesiones**: sesiones inactivas por más de 12h se eliminan automáticamente.
- **Sin claves AI en servidor**: el servidor elimina geminiApiKey/claudeApiKey de los paquetes antes de almacenarlos.

## Configurar en Render

1. Crea un **Web Service** nuevo en https://render.com
2. Conecta este repositorio
3. Build command: `npm install`
4. Start command: `npm start`
5. En **Environment**, agrega:
   - `ADMIN_SECRET` → genera con `openssl rand -hex 32`
   - `ALLOWED_ORIGINS` → `https://TU-SITIO.netlify.app`
   - `CLAUDE_API_KEY` → (opcional)

## Endpoints

| Método | Ruta | Auth |
|---|---|---|
| `GET` | `/` | Pública |
| `GET` | `/api/exam/:sessionId` | Pública |
| `POST` | `/api/exam/:sessionId` | Abierta (rate limited) |
| `POST` | `/api/result` | Abierta (rate limited) |
| `POST` | `/api/closure` | Abierta (rate limited) |
| `GET` | `/api/results/:sessionId` | Pública |
| `GET` | `/api/attempt-status/:sessionId/:doc` | Pública |
| `DELETE` | `/api/results/:sessionId` | **ADMIN_SECRET** |
| `POST` | `/api/teachers/:adminId` | **ADMIN_SECRET** |
| `GET` | `/api/teacher-access/:adminId/:token` | Pública |
| `GET` | `/api/youtube/transcript` | Pública (rate limited) |
