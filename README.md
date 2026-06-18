# EVALUAPRO-UTCH Server

Servidor de sincronización en tiempo real para el aplicativo EVALUAPRO-UTCH.

## Funcionalidades
- Recibe resultados de estudiantes desde cualquier red (WiFi, datos móviles)
- Transmite resultados al docente en tiempo real via WebSocket
- Guarda el examen activo del docente para que el estudiante lo cargue desde cualquier dispositivo
- Aisla examenes, resultados, bloqueos y cierres por `tenantId` para soportar varios docentes en simultaneo
- Proxy para transcripciones de YouTube (evita bloqueos CORS del navegador)
- Deduplicación automática de resultados

## Despliegue en Render (gratis)

1. Sube este código a un repositorio de GitHub
2. Ve a https://render.com → New Web Service → conecta el repo
3. Render detecta el `render.yaml` automáticamente
4. En **Environment Variables**, agrega:
   - `CLAUDE_API_KEY` = tu clave de Anthropic (`sk-ant-...`) — opcional, mejora el proxy de YouTube
5. Deploy → en ~2 minutos tendrás tu URL pública

## Variables de entorno

| Variable | Descripción | Requerido |
|----------|-------------|-----------|
| `PORT` | Puerto del servidor (default: 3000) | No |
| `CLAUDE_API_KEY` | Clave API de Anthropic para proxy YouTube | No |

## Endpoints

| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | `/` | Health check |
| POST | `/api/result` | Estudiante envía resultado |
| POST | `/api/closure` | Estudiante envía cierre |
| GET | `/api/results/:sessionId` | Docente consulta resultados |
| GET | `/api/attempt-status/:sessionId/:doc` | Consulta si un estudiante ya presento el examen |
| DELETE | `/api/results/:sessionId` | Docente borra resultados |
| POST | `/api/exam/:sessionId` | Docente publica el examen activo |
| GET | `/api/exam/:sessionId` | Estudiante descarga el examen activo |
| GET | `/api/youtube/transcript?videoId=X` | Proxy transcripción YouTube |

Endpoints docentes:
- `POST /api/teachers/:adminId`: publica la lista de docentes autorizados del admin.
- `GET /api/teacher-access/:adminId/:token`: valida el link de acceso docente.

Los endpoints de examen y resultados aceptan `tenantId` por query string, body JSON o header `x-tenant-id`. Si no se envia, se usa `default` para mantener compatibilidad con enlaces antiguos.

## WebSocket

Conectar como admin: `wss://tu-server.onrender.com/ws?sessionId=XXX&tenantId=DOCENTE_1&role=admin`

Mensajes recibidos:
- `{ type: "init", results: [...], closures: [...] }` — al conectar
- `{ type: "result", entry: {...} }` — resultado nuevo en tiempo real  
- `{ type: "cleared" }` — ranking borrado por admin
