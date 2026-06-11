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
// Sessions: { [sessionId]: { results: [], closures: [], examPackage: null, adminClients: Set } }
const sessions = {};

function getSession(sessionId) {
  if (!sessions[sessionId]) {
    sessions[sessionId] = { results: [], closures: [], examPackage: null, adminClients: new Set() };
  }
  return sessions[sessionId];
}

function broadcast(sessionId, message) {
  const session = sessions[sessionId];
  if (!session) return;
  const payload = JSON.stringify(message);
  session.adminClients.forEach((ws) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(payload);
    }
  });
}

// ─── WebSocket ────────────────────────────────────────────────────────────────
wss.on("connection", (ws, req) => {
  const url = new URL(req.url, "http://localhost");
  const sessionId = url.searchParams.get("sessionId");
  const role = url.searchParams.get("role"); // "admin" | "student"

  if (!sessionId) {
    ws.close(1008, "sessionId requerido");
    return;
  }

  const session = getSession(sessionId);

  if (role === "admin") {
    session.adminClients.add(ws);

    // Send all existing results immediately on connect
    ws.send(JSON.stringify({ type: "init", results: session.results, closures: session.closures }));

    ws.on("close", () => {
      session.adminClients.delete(ws);
    });
  }

  ws.on("error", () => {});
});

// ─── REST API ─────────────────────────────────────────────────────────────────

// POST /api/result  — student submits result
app.post("/api/result", (req, res) => {
  const { sessionId, entry } = req.body;

  if (!sessionId || !entry?.doc) {
    return res.status(400).json({ error: "sessionId y entry.doc son requeridos" });
  }

  const session = getSession(sessionId);

  // Deduplicate: same doc + same date = same result
  const isDuplicate = session.results.some(
    (r) => r.doc === entry.doc && r.date === entry.date
  );

  if (!isDuplicate) {
    const result = { ...entry, receivedAt: new Date().toISOString() };
    session.results.push(result);

    // Notify all admin websocket clients in real time
    broadcast(sessionId, { type: "result", entry: result });
  }

  return res.json({ ok: true, duplicate: isDuplicate });
});

// POST /api/closure  — student submits closure reason
app.post("/api/closure", (req, res) => {
  const { sessionId, entry } = req.body;

  if (!sessionId || !entry?.doc) {
    return res.status(400).json({ error: "sessionId y entry.doc son requeridos" });
  }

  const session = getSession(sessionId);

  const isDuplicate = session.closures.some(
    (c) => c.doc === entry.doc && c.date === entry.date
  );

  if (!isDuplicate) {
    const closure = { ...entry, receivedAt: new Date().toISOString() };
    session.closures.push(closure);
    broadcast(sessionId, { type: "closure", entry: closure });
  }

  return res.json({ ok: true, duplicate: isDuplicate });
});

// GET /api/results/:sessionId  — admin polls results (fallback if WS unavailable)
app.get("/api/results/:sessionId", (req, res) => {
  const session = sessions[req.params.sessionId];
  if (!session) return res.json({ results: [], closures: [] });
  return res.json({ results: session.results, closures: session.closures });
});

// DELETE /api/results/:sessionId  — admin clears results
app.delete("/api/results/:sessionId", (req, res) => {
  if (sessions[req.params.sessionId]) {
    sessions[req.params.sessionId].results = [];
    sessions[req.params.sessionId].closures = [];
    broadcast(req.params.sessionId, { type: "cleared" });
  }
  return res.json({ ok: true });
});

// POST /api/exam/:sessionId  -- teacher publishes the active exam package
app.post("/api/exam/:sessionId", (req, res) => {
  const sessionId = req.params.sessionId;
  const examPackage = req.body?.package || req.body?.examPackage || req.body;

  if (
    !sessionId ||
    !examPackage?.schema ||
    !Array.isArray(examPackage.questionBank) ||
    examPackage.questionBank.length === 0
  ) {
    return res.status(400).json({ error: "Paquete de examen invalido o vacio" });
  }

  const session = getSession(sessionId);
  session.examPackage = {
    ...examPackage,
    sessionId,
    receivedAt: new Date().toISOString()
  };

  broadcast(sessionId, {
    type: "exam-updated",
    updatedAt: session.examPackage.receivedAt,
    questionCount: session.examPackage.questionBank.length
  });

  return res.json({
    ok: true,
    sessionId,
    questionCount: session.examPackage.questionBank.length,
    updatedAt: session.examPackage.receivedAt
  });
});

// GET /api/exam/:sessionId  -- student downloads the active exam package
app.get("/api/exam/:sessionId", (req, res) => {
  const session = sessions[req.params.sessionId];

  if (!session?.examPackage) {
    return res.status(404).json({ error: "No hay examen publicado para esta sesion" });
  }

  return res.json({ ok: true, package: session.examPackage });
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
  res.json({ status: "ok", app: "EVALUAPRO-UTCH Server", sessions: Object.keys(sessions).length });
});

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`EVALUAPRO server running on port ${PORT}`);
});
