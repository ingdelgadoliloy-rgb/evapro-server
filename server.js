const express = require("express");
const http = require("http");
const WebSocket = require("ws");
const cors = require("cors");
const { v4: uuidv4 } = require("uuid");

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// ─── Security & Configuration ─────────────────────────────────────────────────
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((o) => o.trim())
  .filter(Boolean);

const ADMIN_SECRET = process.env.ADMIN_SECRET || "";

// Rate limiting (simple in-memory, no external dep)
const rateMap = new Map();
const RATE_WINDOW_MS = 60_000;
const RATE_LIMITS = {
  result: 30,
  closure: 30,
  exam_write: 20,
  teachers_write: 10,
  default: 120
};

function getRateKey(req, action) {
  const ip = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.socket.remoteAddress || "unknown";
  return `${action}::${ip}`;
}

function checkRateLimit(req, action) {
  const limit = RATE_LIMITS[action] || RATE_LIMITS.default;
  const key = getRateKey(req, action);
  const now = Date.now();
  const record = rateMap.get(key) || { count: 0, resetAt: now + RATE_WINDOW_MS };
  if (now > record.resetAt) {
    record.count = 0;
    record.resetAt = now + RATE_WINDOW_MS;
  }
  record.count += 1;
  rateMap.set(key, record);
  return record.count <= limit;
}

// Periodically purge old rate entries
setInterval(() => {
  const now = Date.now();
  for (const [key, record] of rateMap.entries()) {
    if (now > record.resetAt + RATE_WINDOW_MS) rateMap.delete(key);
  }
}, 5 * 60_000);

// Session limits
const MAX_SESSIONS = 500;
const MAX_RESULTS_PER_SESSION = 300;
const MAX_EXAM_PACKAGE_QUESTIONS = 200;
const SESSION_TTL_MS = 12 * 60 * 60_000; // 12 hours

// ─── CORS ─────────────────────────────────────────────────────────────────────
const corsOptions = {
  origin: ALLOWED_ORIGINS.length
    ? (origin, cb) => {
        if (!origin || ALLOWED_ORIGINS.some((o) => origin === o || origin.endsWith(o))) {
          cb(null, true);
        } else {
          cb(new Error("CORS: origin not allowed"));
        }
      }
    : true,
  methods: ["GET", "POST", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "x-tenant-id", "x-admin-secret"],
  maxAge: 86400
};

app.use(cors(corsOptions));
app.options("*", cors(corsOptions));

// ─── Security headers ─────────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  next();
});

app.use(express.json({ limit: "2mb" }));

// ─── Admin authentication middleware ──────────────────────────────────────────
function requireAdminSecret(req, res, next) {
  if (!ADMIN_SECRET) return next(); // not configured → open (dev mode)
  const provided = req.headers["x-admin-secret"] || req.query?.secret || req.body?.secret;
  if (provided !== ADMIN_SECRET) {
    return res.status(401).json({ error: "No autorizado" });
  }
  next();
}

// ─── In-memory store ──────────────────────────────────────────────────────────
const sessions = {};
const teacherRegistries = {};
const DEFAULT_TENANT_ID = "default";

function normalizeTenantId(value) {
  const clean = String(value || "")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 64);
  return clean || DEFAULT_TENANT_ID;
}

function getTenantIdFromRequest(req, fallback = "") {
  return normalizeTenantId(
    req.query?.tenantId ||
    req.body?.tenantId ||
    req.headers?.["x-tenant-id"] ||
    fallback
  );
}

function sessionKey(tenantId, sessionId) {
  return `${normalizeTenantId(tenantId)}::${String(sessionId || "").trim().slice(0, 128)}`;
}

function pruneSessions() {
  const keys = Object.keys(sessions);
  if (keys.length <= MAX_SESSIONS) return;
  // Remove oldest by creation time
  keys
    .map((k) => ({ k, t: sessions[k]?.createdAt || 0 }))
    .sort((a, b) => a.t - b.t)
    .slice(0, keys.length - MAX_SESSIONS)
    .forEach(({ k }) => delete sessions[k]);
}

function getSession(tenantId, sessionId) {
  const key = sessionKey(tenantId, sessionId);
  if (!sessions[key]) {
    pruneSessions();
    sessions[key] = {
      tenantId: normalizeTenantId(tenantId),
      sessionId: String(sessionId || "").trim().slice(0, 128),
      results: [],
      closures: [],
      examPackage: null,
      adminClients: new Set(),
      createdAt: Date.now(),
      lastActivity: Date.now()
    };
  } else {
    sessions[key].lastActivity = Date.now();
  }
  return sessions[key];
}

function readSession(tenantId, sessionId) {
  return sessions[sessionKey(tenantId, sessionId)] || null;
}

function broadcast(tenantId, sessionId, message) {
  const session = readSession(tenantId, sessionId);
  if (!session) return;
  let payload;
  try {
    payload = JSON.stringify({ tenantId: session.tenantId, sessionId: session.sessionId, ...message });
  } catch {
    return;
  }
  session.adminClients.forEach((ws) => {
    if (ws.readyState === WebSocket.OPEN) {
      try { ws.send(payload); } catch {}
    }
  });
}

function normalizeDocument(value) {
  return String(value || "")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/\D/g, "");
}

function sanitizeEntry(entry) {
  if (!entry || typeof entry !== "object") return null;
  const doc = normalizeDocument(entry.doc);
  if (!doc || doc.length < 5) return null;
  return {
    doc,
    name: String(entry.name || "").trim().slice(0, 200),
    score: typeof entry.score === "number" ? Math.min(Math.max(entry.score, 0), 9999) : 0,
    total: typeof entry.total === "number" ? Math.min(Math.max(entry.total, 0), 9999) : 0,
    grade: typeof entry.grade === "number" ? Number(entry.grade.toFixed(2)) : 0,
    percent: typeof entry.percent === "number" ? Number(entry.percent.toFixed(2)) : 0,
    date: entry.date ? String(entry.date).slice(0, 50) : new Date().toISOString(),
    closureCode: String(entry.closureCode || "").slice(0, 20),
    closureReason: String(entry.closureReason || "").slice(0, 300),
    tenantId: normalizeTenantId(entry.tenantId)
  };
}

function findAttemptByDoc(session, doc) {
  const normalizedDoc = normalizeDocument(doc);
  if (!session || !normalizedDoc) return null;
  return [...session.results, ...session.closures]
    .find((entry) => normalizeDocument(entry?.doc) === normalizedDoc) || null;
}

function normalizeTeacherRecord(teacher) {
  const name = String(teacher?.name || "").trim().slice(0, 200);
  const doc = normalizeDocument(teacher?.doc);
  const token = String(teacher?.token || "").trim().replace(/[^a-zA-Z0-9_-]/g, "").slice(0, 64);
  const tenantId = normalizeTenantId(teacher?.tenantId || `doc-${doc || token}`);
  if (!name || doc.length < 5 || token.length < 10) return null;
  return { name, doc, token, tenantId, active: teacher?.active !== false };
}

function normalizeTeacherList(value) {
  const seen = new Set();
  return (Array.isArray(value) ? value : [])
    .slice(0, 500)
    .map(normalizeTeacherRecord)
    .filter(Boolean)
    .filter((teacher) => {
      const key = teacher.token || teacher.doc;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
}

function publicTeacherRecord(teacher, adminId) {
  return { name: teacher.name, doc: teacher.doc, tenantId: teacher.tenantId, adminId, active: teacher.active };
}

// Cleanup stale sessions every hour
setInterval(() => {
  const cutoff = Date.now() - SESSION_TTL_MS;
  for (const key of Object.keys(sessions)) {
    if ((sessions[key].lastActivity || 0) < cutoff) {
      sessions[key].adminClients.forEach((ws) => { try { ws.close(); } catch {} });
      delete sessions[key];
    }
  }
}, 60 * 60_000);

// ─── WebSocket ────────────────────────────────────────────────────────────────
wss.on("connection", (ws, req) => {
  try {
    const url = new URL(req.url, "http://localhost");
    const sessionId = url.searchParams.get("sessionId");
    const tenantId = normalizeTenantId(url.searchParams.get("tenantId"));
    const role = url.searchParams.get("role");

    if (!sessionId) { ws.close(1008, "sessionId requerido"); return; }

    const session = getSession(tenantId, sessionId);

    if (role === "admin") {
      if (session.adminClients.size > 50) { ws.close(1008, "Too many admin clients"); return; }
      session.adminClients.add(ws);
      try {
        ws.send(JSON.stringify({ type: "init", tenantId, sessionId, results: session.results, closures: session.closures }));
      } catch {}
      ws.on("close", () => session.adminClients.delete(ws));
    }

    ws.on("error", () => {});
  } catch {
    try { ws.close(1011, "Internal error"); } catch {}
  }
});

// ─── REST API ─────────────────────────────────────────────────────────────────

// POST /api/teachers/:adminId  — admin publishes authorized teachers
app.post("/api/teachers/:adminId", requireAdminSecret, (req, res) => {
  if (!checkRateLimit(req, "teachers_write")) {
    return res.status(429).json({ error: "Demasiadas solicitudes. Intenta en un minuto." });
  }
  const adminId = normalizeTenantId(req.params.adminId);
  if (!adminId) return res.status(400).json({ error: "adminId inválido" });

  const teachers = normalizeTeacherList(req.body?.teachers);
  teacherRegistries[adminId] = { adminId, teachers, updatedAt: new Date().toISOString() };
  return res.json({ ok: true, adminId, teacherCount: teachers.length, updatedAt: teacherRegistries[adminId].updatedAt });
});

// GET /api/teacher-access/:adminId/:token  — validates teacher access
app.get("/api/teacher-access/:adminId/:token", (req, res) => {
  const adminId = normalizeTenantId(req.params.adminId);
  const token = String(req.params.token || "").trim().replace(/[^a-zA-Z0-9_-]/g, "").slice(0, 64);
  const registry = teacherRegistries[adminId];
  const teacher = registry?.teachers?.find((t) => t.token === token && t.active !== false);
  if (!teacher) return res.status(403).json({ ok: false, error: "Docente no autorizado o enlace vencido" });
  return res.json({ ok: true, adminId, teacher: publicTeacherRecord(teacher, adminId), updatedAt: registry.updatedAt });
});

// POST /api/result  — student submits result
app.post("/api/result", (req, res) => {
  if (!checkRateLimit(req, "result")) {
    return res.status(429).json({ error: "Demasiadas solicitudes. Intenta en un minuto." });
  }
  const { sessionId } = req.body;
  const tenantId = getTenantIdFromRequest(req, req.body?.entry?.tenantId);
  const entry = sanitizeEntry(req.body?.entry);

  if (!sessionId || !entry) {
    return res.status(400).json({ error: "sessionId y entry.doc son requeridos" });
  }

  const session = getSession(tenantId, sessionId);
  if (session.results.length >= MAX_RESULTS_PER_SESSION) {
    return res.status(400).json({ error: "Límite de resultados alcanzado para esta sesión" });
  }

  const normalizedDoc = normalizeDocument(entry.doc);
  const previousResult = session.results.find((r) => normalizeDocument(r.doc) === normalizedDoc);
  const previousClosure = session.closures.find((c) => normalizeDocument(c.doc) === normalizedDoc && c.date !== entry.date);

  if (previousResult || previousClosure) {
    return res.json({ ok: true, duplicate: true, blocked: true });
  }

  const isDuplicate = session.results.some((r) => r.doc === entry.doc && r.date === entry.date);
  if (!isDuplicate) {
    const result = { ...entry, tenantId, sessionId, receivedAt: new Date().toISOString() };
    session.results.push(result);
    broadcast(tenantId, sessionId, { type: "result", entry: result });
  }
  return res.json({ ok: true, duplicate: isDuplicate });
});

// POST /api/closure  — student submits closure reason
app.post("/api/closure", (req, res) => {
  if (!checkRateLimit(req, "closure")) {
    return res.status(429).json({ error: "Demasiadas solicitudes. Intenta en un minuto." });
  }
  const { sessionId } = req.body;
  const tenantId = getTenantIdFromRequest(req, req.body?.entry?.tenantId);
  const entry = sanitizeEntry(req.body?.entry);

  if (!sessionId || !entry) {
    return res.status(400).json({ error: "sessionId y entry.doc son requeridos" });
  }

  const session = getSession(tenantId, sessionId);
  if (session.closures.length >= MAX_RESULTS_PER_SESSION) {
    return res.status(400).json({ error: "Límite de cierres alcanzado para esta sesión" });
  }

  const normalizedDoc = normalizeDocument(entry.doc);
  const previousClosure = session.closures.find((c) => normalizeDocument(c.doc) === normalizedDoc);
  const previousResult = session.results.find((r) => normalizeDocument(r.doc) === normalizedDoc && r.date !== entry.date);

  if (previousClosure || previousResult) {
    return res.json({ ok: true, duplicate: true, blocked: true });
  }

  const isDuplicate = session.closures.some((c) => c.doc === entry.doc && c.date === entry.date);
  if (!isDuplicate) {
    const closure = { ...entry, tenantId, sessionId, receivedAt: new Date().toISOString() };
    session.closures.push(closure);
    broadcast(tenantId, sessionId, { type: "closure", entry: closure });
  }
  return res.json({ ok: true, duplicate: isDuplicate });
});

// GET /api/results/:sessionId  — admin polls results (fallback if WS unavailable)
app.get("/api/results/:sessionId", (req, res) => {
  const tenantId = getTenantIdFromRequest(req);
  const session = readSession(tenantId, req.params.sessionId);
  if (!session) return res.json({ results: [], closures: [] });
  return res.json({ tenantId, sessionId: req.params.sessionId, results: session.results, closures: session.closures });
});

// GET /api/attempt-status/:sessionId/:doc
app.get("/api/attempt-status/:sessionId/:doc", (req, res) => {
  const tenantId = getTenantIdFromRequest(req);
  const doc = String(req.params.doc || "").slice(0, 30);
  const session = readSession(tenantId, req.params.sessionId);
  const entry = findAttemptByDoc(session, doc);
  return res.json({ ok: true, tenantId, sessionId: req.params.sessionId, blocked: Boolean(entry), entry: entry || null });
});

// DELETE /api/results/:sessionId  — admin clears results (requires admin secret)
app.delete("/api/results/:sessionId", requireAdminSecret, (req, res) => {
  const tenantId = getTenantIdFromRequest(req);
  const session = readSession(tenantId, req.params.sessionId);
  if (session) {
    session.results = [];
    session.closures = [];
    broadcast(tenantId, req.params.sessionId, { type: "cleared" });
  }
  return res.json({ ok: true, tenantId, sessionId: req.params.sessionId });
});

// POST /api/exam/:sessionId  — teacher publishes the active exam package
app.post("/api/exam/:sessionId", (req, res) => {
  if (!checkRateLimit(req, "exam_write")) {
    return res.status(429).json({ error: "Demasiadas solicitudes. Intenta en un minuto." });
  }
  const sessionId = String(req.params.sessionId || "").trim().slice(0, 128);
  const examPackage = req.body?.package || req.body?.examPackage || req.body;
  const tenantId = getTenantIdFromRequest(req, examPackage?.tenantId);

  if (!sessionId || !examPackage?.schema || !Array.isArray(examPackage.questionBank) || !examPackage.questionBank.length) {
    return res.status(400).json({ error: "Paquete de examen inválido o vacío" });
  }
  if (examPackage.questionBank.length > MAX_EXAM_PACKAGE_QUESTIONS) {
    return res.status(400).json({ error: `Máximo ${MAX_EXAM_PACKAGE_QUESTIONS} preguntas por paquete` });
  }

  // Strip AI keys before storing
  const safePackage = { ...examPackage };
  if (safePackage.settings) {
    safePackage.settings = { ...safePackage.settings, geminiApiKey: "", claudeApiKey: "" };
  }

  const session = getSession(tenantId, sessionId);
  session.examPackage = { ...safePackage, tenantId, sessionId, receivedAt: new Date().toISOString() };
  broadcast(tenantId, sessionId, { type: "exam-updated", updatedAt: session.examPackage.receivedAt, questionCount: session.examPackage.questionBank.length });
  return res.json({ ok: true, tenantId, sessionId, questionCount: session.examPackage.questionBank.length, updatedAt: session.examPackage.receivedAt });
});

// GET /api/exam/:sessionId  — student downloads the active exam package
app.get("/api/exam/:sessionId", (req, res) => {
  const tenantId = getTenantIdFromRequest(req);
  const session = readSession(tenantId, req.params.sessionId);
  if (!session?.examPackage) return res.status(404).json({ error: "No hay examen publicado para esta sesión" });
  return res.json({ ok: true, tenantId, sessionId: req.params.sessionId, package: session.examPackage });
});

// ─── YouTube Transcript Proxy ─────────────────────────────────────────────────
app.get("/api/youtube/transcript", async (req, res) => {
  if (!checkRateLimit(req, "default")) {
    return res.status(429).json({ error: "Demasiadas solicitudes." });
  }
  const videoId = req.query.videoId;
  if (!videoId || !/^[a-zA-Z0-9_-]{6,16}$/.test(videoId)) {
    return res.status(400).json({ error: "videoId inválido" });
  }

  const https = require("https");
  const http2 = require("http");

  function fetchUrl(url) {
    return new Promise((resolve, reject) => {
      const client = url.startsWith("https") ? https : http2;
      const options = {
        headers: {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
          "Accept-Language": "es-ES,es;q=0.9,en;q=0.8",
          "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }
      };
      const reqObj = client.get(url, options, (r) => {
        const chunks = [];
        r.on("data", (chunk) => chunks.push(chunk));
        r.on("end", () => resolve({ status: r.statusCode, text: Buffer.concat(chunks).toString("utf8") }));
      });
      reqObj.on("error", reject);
      reqObj.setTimeout(10000, () => { reqObj.destroy(); reject(new Error("Timeout")); });
    });
  }

  try {
    const watchUrl = `https://www.youtube.com/watch?v=${videoId}`;
    const result = await fetchUrl(watchUrl);
    if (result.status !== 200) return res.status(502).json({ error: "YouTube no respondió correctamente" });

    const html = result.text;
    const marker = '"captionTracks":';
    const markerIndex = html.indexOf(marker);
    let captionTracks = [];

    if (markerIndex >= 0) {
      const arrayStart = html.indexOf("[", markerIndex);
      let depth = 0, inStr = false, escaped = false, end = -1;
      for (let i = arrayStart; i < Math.min(html.length, arrayStart + 50000); i++) {
        const c = html[i];
        if (escaped) { escaped = false; continue; }
        if (c === "\\") { escaped = true; continue; }
        if (c === '"') { inStr = !inStr; continue; }
        if (inStr) continue;
        if (c === "[") depth++;
        else if (c === "]") { depth--; if (depth === 0) { end = i; break; } }
      }
      if (end > arrayStart) {
        try { captionTracks = JSON.parse(html.slice(arrayStart, end + 1)); } catch {}
      }
    }

    const titleMatch = html.match(/<title[^>]*>(.*?)<\/title>/i);
    const title = titleMatch ? titleMatch[1].replace(/\s*-\s*YouTube\s*$/i, "").trim() : "";

    if (!captionTracks.length) {
      const descMatch = html.match(/"shortDescription"\s*:\s*"((?:\\.|[^"\\])*)"/);
      const description = descMatch ? descMatch[1].replace(/\\n/g, " ").replace(/\\"/g, '"') : "";
      return res.json({ title, transcript: "", metadata: `${title}. ${description}`.trim(), captionTracks: [] });
    }

    const ordered = [
      ...captionTracks.filter((t) => t.languageCode?.startsWith("es") && t.kind !== "asr"),
      ...captionTracks.filter((t) => t.languageCode?.startsWith("es")),
      ...captionTracks.filter((t) => t.kind !== "asr"),
      ...captionTracks
    ].filter((t, i, arr) => t.baseUrl && arr.findIndex((x) => x.baseUrl === t.baseUrl) === i);

    let transcript = "";
    for (const track of ordered.slice(0, 3)) {
      try {
        const tUrl = track.baseUrl + (track.baseUrl.includes("?") ? "&" : "?") + "fmt=json3";
        const tr = await fetchUrl(tUrl);
        if (tr.status === 200) {
          try {
            const data = JSON.parse(tr.text);
            if (Array.isArray(data.events)) {
              transcript = data.events.flatMap((e) => e.segs || []).map((s) => s.utf8 || "").filter((s) => s.trim() && s.trim() !== "\n").join(" ").replace(/\s+/g, " ").trim();
              if (transcript.length >= 300) break;
            }
          } catch {}
        }
      } catch {}
    }

    return res.json({ title, transcript, metadata: "", captionTracks: captionTracks.map((t) => ({ languageCode: t.languageCode, kind: t.kind })) });
  } catch (e) {
    const claudeKey = process.env.CLAUDE_API_KEY;
    if (claudeKey) {
      try {
        const videoUrl = `https://www.youtube.com/watch?v=${videoId}`;
        const claudeRes = await fetch("https://api.anthropic.com/v1/messages", {
          method: "POST",
          headers: { "Content-Type": "application/json", "x-api-key": claudeKey, "anthropic-version": "2023-06-01" },
          body: JSON.stringify({
            model: "claude-haiku-4-5-20251001",
            max_tokens: 1000,
            messages: [{ role: "user", content: `El video de YouTube con URL ${videoUrl} no pudo ser accedido directamente. Proporciona un resumen educativo general sobre el tema probable de este video. Responde SOLO con texto corrido sin formato especial. Mínimo 400 palabras.` }]
          }),
          signal: AbortSignal.timeout(15000)
        });
        if (claudeRes.ok) {
          const claudeData = await claudeRes.json();
          const text = claudeData?.content?.[0]?.text || "";
          if (text.length > 300) return res.json({ title: `Video ${videoId}`, transcript: text, metadata: "", captionTracks: [], source: "ai_fallback" });
        }
      } catch (claudeErr) {
        console.error("Claude fallback error:", claudeErr.message);
      }
    }
    return res.status(500).json({ error: "Error al obtener transcripción. El video puede no tener subtítulos públicos o puede ser privado." });
  }
});

// ─── Health check ─────────────────────────────────────────────────────────────
app.get("/", (req, res) => {
  const tenants = new Set(Object.values(sessions).map((s) => s.tenantId));
  res.json({ status: "ok", app: "EVALUAPRO-UTCH Server", tenants: tenants.size, sessions: Object.keys(sessions).length, teacherRegistries: Object.keys(teacherRegistries).length });
});

// ─── Global error handler ─────────────────────────────────────────────────────
app.use((err, req, res, _next) => {
  console.error("Unhandled error:", err.message);
  if (err.message?.includes("CORS")) return res.status(403).json({ error: "CORS: origen no permitido" });
  res.status(500).json({ error: "Error interno del servidor" });
});

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`EVALUAPRO server running on port ${PORT}`);
  if (!ADMIN_SECRET) console.warn("⚠️  ADMIN_SECRET no configurado — endpoints admin sin protección. Define ADMIN_SECRET en variables de entorno.");
});
