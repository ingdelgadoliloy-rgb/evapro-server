# EVALUAPRO-UTCH Server

Servidor de sincronización en tiempo real para el aplicativo EVALUAPRO-UTCH.

## Funcionalidades
- Recibe resultados de estudiantes desde cualquier red (WiFi, datos móviles)
- Transmite resultados al docente en tiempo real via WebSocket
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
| DELETE | `/api/results/:sessionId` | Docente borra resultados |
| GET | `/api/youtube/transcript?videoId=X` | Proxy transcripción YouTube |

## WebSocket

Conectar como admin: `wss://tu-server.onrender.com/ws?sessionId=XXX&role=admin`

Mensajes recibidos:
- `{ type: "init", results: [...], closures: [...] }` — al conectar
- `{ type: "result", entry: {...} }` — resultado nuevo en tiempo real  
- `{ type: "cleared" }` — ranking borrado por admin
