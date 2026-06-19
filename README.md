# EVALUAPRO-UTCH - Servidor Render

Servidor REST + WebSocket para sincronizar examenes, resultados, cierres y docentes autorizados.

## Variables de entorno

| Variable | Requerida | Descripcion |
|---|---|---|
| `PORT` | No | Puerto del servidor. Render lo asigna automaticamente. |
| `ADMIN_SECRET` | Si | Clave privada del administrador. Debe ser larga y aleatoria. |
| `ALLOWED_ORIGINS` | Si | URLs de Netlify permitidas, separadas por coma. |
| `EVAPRO_DATA_FILE` | No | Ruta del archivo JSON persistente. Ejemplo: `/tmp/evapro-store.json`. |
| `JSON_BODY_LIMIT` | No | Limite del cuerpo JSON para IA con archivos. Por defecto `70mb`. |
| `MAX_AI_FILE_BYTES` | No | Tamano maximo total de PDF/imagenes aceptados para Gemini. Por defecto 45 MB. |
| `MAX_AI_INLINE_FILE_BYTES` | No | Alias compatible de `MAX_AI_FILE_BYTES`. |
| `GEMINI_INLINE_TOTAL_LIMIT` | No | Tamano maximo que se envia inline a Gemini; por encima se usa subida temporal. Por defecto 18 MB. |
| `CLAUDE_API_KEY` | No | Clave Claude para generacion IA desde backend y fallback de YouTube. |
| `GEMINI_API_KEY` | No | Clave Gemini para generacion IA desde backend. |
| `CLAUDE_MODELS` | No | Lista de modelos Claude separados por coma. Por defecto usa `claude-sonnet-4-6`, `claude-sonnet-4-5-20250929`, `claude-haiku-4-5-20251001`. |
| `GEMINI_MODELS` | No | Lista de modelos Gemini separados por coma. Por defecto usa `gemini-2.5-flash`, `gemini-2.5-flash-lite`, `gemini-2.0-flash`. |

## Seguridad aplicada

- El servidor recalcula `score`, `percent` y `grade`; no confia en la nota enviada por el navegador.
- El paquete que descarga el estudiante no incluye `correct`, `correctAnswer`, `acceptedAnswers` ni `rationale`.
- Publicar examenes, consultar/borrar resultados y abrir WebSocket admin requiere `ADMIN_SECRET` o token docente valido del tenant.
- Los estudiantes solo descargan el examen seguro y envian respuestas.
- Los examenes, docentes, resultados y cierres se guardan en `EVAPRO_DATA_FILE`.
- El servidor elimina claves IA de los paquetes antes de almacenarlos.
- `POST /api/ai/generate` permite usar claves IA desde variables de entorno de Render con `ADMIN_SECRET` o token docente valido.
- Gemini puede recibir PDF o imagenes compatibles desde el frontend para generar cuando el texto editable/OCR sea insuficiente. Si superan el limite inline, el servidor usa subida temporal a Gemini.
- CORS queda restringido a los dominios definidos en `ALLOWED_ORIGINS`.
- Se aplica rate limiting y limites de tamano/cantidad para reducir abuso.

## Configuracion en Render

1. Crea un Web Service en Render.
2. Conecta el repositorio del servidor.
3. Build command: `npm install`.
4. Start command: `npm start`.
5. En Environment agrega:
   - `ADMIN_SECRET`: genera una clave larga.
   - `ALLOWED_ORIGINS`: por ejemplo `https://evaluapro-utch.netlify.app`.
   - `EVAPRO_DATA_FILE`: por ejemplo `/tmp/evapro-store.json`.
   - `JSON_BODY_LIMIT`: por ejemplo `70mb`.
   - `MAX_AI_FILE_BYTES`: por ejemplo `47185920`.
   - `GEMINI_INLINE_TOTAL_LIMIT`: por ejemplo `18874368`.
   - `CLAUDE_API_KEY`: opcional.
   - `GEMINI_API_KEY`: opcional.
   - `CLAUDE_MODELS` / `GEMINI_MODELS`: opcionales para cambiar el orden de modelos.

Para persistencia institucional fuerte, usa un disco persistente de Render o una base de datos. `/tmp` puede perderse si Render recrea el servicio.

## Endpoints

| Metodo | Ruta | Auth |
|---|---|---|
| `GET` | `/` | Publica |
| `GET` | `/api/exam/:sessionId` | Publica, pero sin respuestas correctas |
| `POST` | `/api/exam/:sessionId` | `ADMIN_SECRET` o token docente |
| `POST` | `/api/result` | Publica; califica el servidor |
| `POST` | `/api/closure` | Publica; califica el servidor |
| `GET` | `/api/results/:sessionId` | `ADMIN_SECRET` o token docente |
| `GET` | `/api/attempt-status/:sessionId/:doc` | Publica, solo estado minimo |
| `DELETE` | `/api/results/:sessionId` | `ADMIN_SECRET` o token docente |
| `POST` | `/api/teachers/:adminId` | `ADMIN_SECRET` |
| `GET` | `/api/teacher-access/:adminId/:token` | Publica |
| `POST` | `/api/ai/generate` | `ADMIN_SECRET` o token docente |
| `GET` | `/api/youtube/transcript` | Publica con rate limit |
