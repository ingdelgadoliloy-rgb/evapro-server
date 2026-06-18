const express = require("express");
const http = require("http");
const WebSocket = require("ws");
const cors = require("cors");
const { v4: uuidv4 } = require("uuid");

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

app.use(cors());
app.use(express.json({ limit: "8mb" }));

// ─── In-memory store ──────────────────────────────────────────────────────────
// Sessions: { [tenantId::sessionId]: { tenantId, sessionId, results: [], closures: [], examPackage: null, adminClients: Set } }
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
  return `${normalizeTenantId(tenantId)}::${String(sessionId || "").trim()}`;
}

function getSession(tenantId, sessionId) {
  const key = sessionKey(tenantId, sessionId);
  if (!sessions[key]) {
    sessions[key] = {
      tenantId: normalizeTenantId(tenantId),
      sessionId: String(sessionId || "").trim(),
      results: [],
      closures: [],
      examPackage: null,
      adminClients: new Set()
    };
  }
  return sessions[key];
}

function readSession(tenantId, sessionId) {
  return sessions[sessionKey(tenantId, sessionId)] || null;
}

function broadcast(tenantId, sessionId, message) {
  const session = readSession(tenantId, sessionId);
  if (!session) return;
  const payload = JSON.stringify({ tenantId: session.tenantId, sessionId: session.sessionId, ...message });
  session.adminClients.forEach((ws) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(payload);
    }
  });
}

function normalizeDocument(value) {
  return String(value || "")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/\D/g, "");
}

function findAttemptByDoc(session, doc) {
  const normalizedDoc = normalizeDocument(doc);
  if (!session || !normalizedDoc) return null;
  return [...session.results, ...session.closures]
    .find((entry) => normalizeDocument(entry?.doc) === normalizedDoc) || null;
}

function normalizeTeacherRecord(teacher) {
  const name = String(teacher?.name || "").trim();
  const doc = normalizeDocument(teacher?.doc);
  const token = String(teacher?.token || "").trim();
  const tenantId = normalizeTenantId(teacher?.tenantId || `doc-${doc || token}`);
  if (!name || doc.length < 5 || token.length < 10) {
    return null;
  }
  return {
    name,
    doc,
    token,
    tenantId,
    active: teacher?.active !== false
  };
}

function normalizeTeacherList(value) {
  const seen = new Set();
  return (Array.isArray(value) ? value : [])
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
  return {
    name: teacher.name,
    doc: teacher.doc,
    tenantId: teacher.tenantId,
    adminId,
    active: teacher.active
  };
}

// ─── WebSocket ────────────────────────────────────────────────────────────────
wss.on("connection", (ws, req) => {
  const url = new URL(req.url, "http://localhost");
  const sessionId = url.searchParams.get("sessionId");
  const tenantId = normalizeTenantId(url.searchParams.get("tenantId"));
  const role = url.searchParams.get("role"); // "admin" | "student"

  if (!sessionId) {
    ws.close(1008, "sessionId requerido");
    return;
  }

  const session = getSession(tenantId, sessionId);

  if (role === "admin") {
    session.adminClients.add(ws);

    // Send all existing results immediately on connect
    ws.send(JSON.stringify({ type: "init", tenantId, sessionId, results: session.results, closures: session.closures }));

    ws.on("close", () => {
      session.adminClients.delete(ws);
    });
  }

  ws.on("error", () => {});
});

// ─── REST API ─────────────────────────────────────────────────────────────────

// POST /api/result  — student submits result
// POST /api/teachers/:adminId -- admin publishes authorized teachers
app.post("/api/teachers/:adminId", (req, res) => {
  const adminId = normalizeTenantId(req.params.adminId);
  const teachers = normalizeTeacherList(req.body?.teachers);

  teacherRegistries[adminId] = {
    adminId,
    teachers,
    updatedAt: new Date().toISOString()
  };

  return res.json({
    ok: true,
    adminId,
    teacherCount: teachers.length,
    updatedAt: teacherRegistries[adminId].updatedAt
  });
});

// GET /api/teacher-access/:adminId/:token -- validates teacher access link
app.get("/api/teacher-access/:adminId/:token", (req, res) => {
  const adminId = normalizeTenantId(req.params.adminId);
  const token = String(req.params.token || "").trim();
  const registry = teacherRegistries[adminId];
  const teacher = registry?.teachers?.find((item) => item.token === token && item.active !== false);

  if (!teacher) {
    return res.status(403).json({ ok: false, error: "Docente no autorizado o enlace vencido" });
  }

  return res.json({
    ok: true,
    adminId,
    teacher: publicTeacherRecord(teacher, adminId),
    updatedAt: registry.updatedAt
  });
});

app.post("/api/result", (req, res) => {
  const { sessionId, entry } = req.body;
  const tenantId = getTenantIdFromRequest(req, entry?.tenantId);

  if (!sessionId || !entry?.doc) {
    return res.status(400).json({ error: "sessionId y entry.doc son requeridos" });
  }

  const session = getSession(tenantId, sessionId);
  const normalizedDoc = normalizeDocument(entry.doc);
  const previousResult = session.results.find((r) => normalizeDocument(r.doc) === normalizedDoc);
  const previousClosure = session.closures.find((c) => normalizeDocument(c.doc) === normalizedDoc && c.date !== entry.date);

  if (previousResult || previousClosure) {
    return res.json({ ok: true, duplicate: true, blocked: true });
  }

  // Deduplicate: same doc + same date = same result
  const isDuplicate = session.results.some(
    (r) => r.doc === entry.doc && r.date === entry.date
  );

  if (!isDuplicate) {
    const result = { ...entry, tenantId, sessionId, receivedAt: new Date().toISOString() };
    session.results.push(result);

    // Notify all admin websocket clients in real time
    broadcast(tenantId, sessionId, { type: "result", entry: result });
  }

  return res.json({ ok: true, duplicate: isDuplicate });
});

// POST /api/closure  — student submits closure reason
app.post("/api/closure", (req, res) => {
  const { sessionId, entry } = req.body;
  const tenantId = getTenantIdFromRequest(req, entry?.tenantId);

  if (!sessionId || !entry?.doc) {
    return res.status(400).json({ error: "sessionId y entry.doc son requeridos" });
  }

  const session = getSession(tenantId, sessionId);
  const normalizedDoc = normalizeDocument(entry.doc);
  const previousClosure = session.closures.find((c) => normalizeDocument(c.doc) === normalizedDoc);
  const previousResult = session.results.find((r) => normalizeDocument(r.doc) === normalizedDoc && r.date !== entry.date);

  if (previousClosure || previousResult) {
    return res.json({ ok: true, duplicate: true, blocked: true });
  }

  const isDuplicate = session.closures.some(
    (c) => c.doc === entry.doc && c.date === entry.date
  );

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

// GET /api/attempt-status/:sessionId/:doc  -- checks whether a student already submitted this exam
app.get("/api/attempt-status/:sessionId/:doc", (req, res) => {
  const tenantId = getTenantIdFromRequest(req);
  const session = readSession(tenantId, req.params.sessionId);
  const entry = findAttemptByDoc(session, req.params.doc);
  return res.json({
    ok: true,
    tenantId,
    sessionId: req.params.sessionId,
    blocked: Boolean(entry),
    entry: entry || null
  });
});

// DELETE /api/results/:sessionId  — admin clears results
app.delete("/api/results/:sessionId", (req, res) => {
  const tenantId = getTenantIdFromRequest(req);
  const session = readSession(tenantId, req.params.sessionId);
  if (session) {
    session.results = [];
    session.closures = [];
    broadcast(tenantId, req.params.sessionId, { type: "cleared" });
  }
  return res.json({ ok: true, tenantId, sessionId: req.params.sessionId });
});

// POST /api/exam/:sessionId  -- teacher publishes the active exam package
app.post("/api/exam/:sessionId", (req, res) => {
  const sessionId = req.params.sessionId;
  const examPackage = req.body?.package || req.body?.examPackage || req.body;
  const tenantId = getTenantIdFromRequest(req, examPackage?.tenantId);

  if (
    !sessionId ||
    !examPackage?.schema ||
    !Array.isArray(examPackage.questionBank) ||
    examPackage.questionBank.length === 0
  ) {
    return res.status(400).json({ error: "Paquete de examen invalido o vacio" });
  }

  const session = getSession(tenantId, sessionId);
  session.examPackage = {
    ...examPackage,
    tenantId,
    sessionId,
    receivedAt: new Date().toISOString()
  };

  broadcast(tenantId, sessionId, {
    type: "exam-updated",
    updatedAt: session.examPackage.receivedAt,
    questionCount: session.examPackage.questionBank.length
  });

  return res.json({
    ok: true,
    tenantId,
    sessionId,
    questionCount: session.examPackage.questionBank.length,
    updatedAt: session.examPackage.receivedAt
  });
});

// GET /api/exam/:sessionId  -- student downloads the active exam package
app.get("/api/exam/:sessionId", (req, res) => {
  const tenantId = getTenantIdFromRequest(req);
  const session = readSession(tenantId, req.params.sessionId);

  if (!session?.examPackage) {
    return res.status(404).json({ error: "No hay examen publicado para esta sesion" });
  }

  return res.json({ ok: true, tenantId, sessionId: req.params.sessionId, package: session.examPackage });
});


// ─── YouTube Transcript Proxy ─────────────────────────────────────────────────
// Strategy: 1) Direct YouTube fetch  2) Claude AI summary fallback

app.get("/api/youtube/transcript", async (req, res) => {
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
      const req = client.get(url, options, (r) => {
        let data = "";
        r.on("data", chunk => data += chunk);
        r.on("end", () => resolve({ status: r.statusCode, text: data }));
      });
      req.on("error", reject);
      req.setTimeout(10000, () => { req.destroy(); reject(new Error("Timeout")); });
    });
  }

  try {
    const watchUrl = `https://www.youtube.com/watch?v=${videoId}`;
    const result = await fetchUrl(watchUrl);
    if (result.status !== 200) {
      return res.status(502).json({ error: "YouTube no respondió correctamente" });
    }

    const html = result.text;

    // Extract caption tracks
    const marker = '"captionTracks":';
    const markerIndex = html.indexOf(marker);
    let captionTracks = [];

    if (markerIndex >= 0) {
      const arrayStart = html.indexOf("[", markerIndex);
      let depth = 0, inStr = false, escaped = false, end = -1;
      for (let i = arrayStart; i < html.length; i++) {
        const c = html[i];
        if (escaped) { escaped = false; continue; }
        if (c === "\\") { escaped = true; continue; }
        if (c === '"') { inStr = !inStr; continue; }
        if (inStr) continue;
        if (c === "[") depth++;
        else if (c === "]") { depth--; if (depth === 0) { end = i; break; } }
      }
      if (end > arrayStart) {
        try { captionTracks = JSON.parse(html.slice(arrayStart, end + 1)); } catch(e) {}
      }
    }

    // Extract title
    const titleMatch = html.match(/<title[^>]*>(.*?)<\/title>/i);
    const title = titleMatch ? titleMatch[1].replace(/\s*-\s*YouTube\s*$/i, "").trim() : "";

    if (!captionTracks.length) {
      // Fallback: return metadata
      const descMatch = html.match(/"shortDescription"\s*:\s*"((?:\\.|[^"\\])*)"/);
      const description = descMatch ? descMatch[1].replace(/\\n/g, " ").replace(/\\"/g, '"') : "";
      return res.json({ title, transcript: "", metadata: `${title}. ${description}`.trim(), captionTracks: [] });
    }

    // Try to fetch best transcript
    const ordered = [
      ...captionTracks.filter(t => t.languageCode?.startsWith("es") && t.kind !== "asr"),
      ...captionTracks.filter(t => t.languageCode?.startsWith("es")),
      ...captionTracks.filter(t => t.kind !== "asr"),
      ...captionTracks
    ].filter((t, i, arr) => t.baseUrl && arr.findIndex(x => x.baseUrl === t.baseUrl) === i);

    let transcript = "";
    for (const track of ordered.slice(0, 3)) {
      try {
        const tUrl = track.baseUrl + (track.baseUrl.includes("?") ? "&" : "?") + "fmt=json3";
        const tr = await fetchUrl(tUrl);
        if (tr.status === 200) {
          try {
            const data = JSON.parse(tr.text);
            if (Array.isArray(data.events)) {
              transcript = data.events.flatMap(e => e.segs || []).map(s => s.utf8 || "").filter(s => s.trim() && s.trim() !== "\n").join(" ").replace(/\s+/g, " ").trim();
              if (transcript.length >= 300) break;
            }
          } catch(e) {}
        }
      } catch(e) {}
    }

    return res.json({ title, transcript, metadata: "", captionTracks: captionTracks.map(t => ({ languageCode: t.languageCode, kind: t.kind })) });
  } catch(e) {
    // Fallback: use Claude AI to summarize the video by URL if we have an API key
    const claudeKey = process.env.CLAUDE_API_KEY;
    if (claudeKey) {
      try {
        const videoUrl = `https://www.youtube.com/watch?v=${videoId}`;
        const claudeRes = await fetch("https://api.anthropic.com/v1/messages", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-api-key": claudeKey,
            "anthropic-version": "2023-06-01"
          },
          body: JSON.stringify({
            model: "claude-haiku-4-5-20251001",
            max_tokens: 1000,
            messages: [{
              role: "user",
              content: `El video de YouTube con URL ${videoUrl} no pudo ser accedido directamente. Por favor proporciona un resumen educativo general sobre el tema que probablemente trata este video basándote en el ID del video y cualquier contexto disponible. Responde SOLO con texto corrido sin formato especial, como si fuera una transcripción de contenido educativo. Mínimo 400 palabras.`
            }]
          })
        });
        if (claudeRes.ok) {
          const claudeData = await claudeRes.json();
          const text = claudeData?.content?.[0]?.text || "";
          if (text.length > 300) {
            return res.json({ title: `Video ${videoId}`, transcript: text, metadata: "", captionTracks: [], source: "ai_fallback" });
          }
        }
      } catch(claudeErr) {
        console.error("Claude fallback error:", claudeErr.message);
      }
    }
    return res.status(500).json({ error: e.message || "Error al obtener transcripción. El video puede no tener subtítulos públicos o puede ser privado." });
  }
});

// Health check
app.get("/", (req, res) => {
  const tenants = new Set(Object.values(sessions).map((session) => session.tenantId));
  res.json({
    status: "ok",
    app: "EVALUAPRO-UTCH Server",
    tenants: tenants.size,
    sessions: Object.keys(sessions).length,
    teacherRegistries: Object.keys(teacherRegistries).length
  });
});

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`EVALUAPRO server running on port ${PORT}`);
});
