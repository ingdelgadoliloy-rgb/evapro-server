const express = require("express");
const http = require("http");
const WebSocket = require("ws");
const cors = require("cors");
const { v4: uuidv4 } = require("uuid");

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

app.use(cors());
app.use(express.json({ limit: "2mb" }));

// ─── In-memory store ──────────────────────────────────────────────────────────
// Sessions: { [sessionId]: { results: [], closures: [], adminClients: Set } }
const sessions = {};

function getSession(sessionId) {
  if (!sessions[sessionId]) {
    sessions[sessionId] = { results: [], closures: [], adminClients: new Set() };
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

// Health check
app.get("/", (req, res) => {
  res.json({ status: "ok", app: "EVALUAPRO-UTCH Server", sessions: Object.keys(sessions).length });
});

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`EVALUAPRO server running on port ${PORT}`);
});
