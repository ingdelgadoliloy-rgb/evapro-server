const express = require("express");
const http = require("http");
const fs = require("fs");
const path = require("path");
const WebSocket = require("ws");
const cors = require("cors");

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// ─── Security & Configuration ─────────────────────────────────────────────────
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((o) => o.trim())
  .filter(Boolean);

const ADMIN_SECRET = process.env.ADMIN_SECRET || "";
const DATA_FILE = process.env.EVAPRO_DATA_FILE || path.join(__dirname, "data", "evapro-store.json");
const JSON_BODY_LIMIT = process.env.JSON_BODY_LIMIT || "30mb";
const MAX_AI_INLINE_FILE_BYTES = Number(process.env.MAX_AI_INLINE_FILE_BYTES || 18 * 1024 * 1024);
const CLAUDE_MODEL_FALLBACKS = (process.env.CLAUDE_MODELS || process.env.CLAUDE_MODEL || "claude-sonnet-4-6,claude-sonnet-4-5-20250929,claude-haiku-4-5-20251001")
  .split(",")
  .map((model) => model.trim())
  .filter(Boolean);
const GEMINI_MODEL_FALLBACKS = (process.env.GEMINI_MODELS || process.env.GEMINI_MODEL || "gemini-2.5-flash,gemini-2.5-flash-lite,gemini-2.0-flash")
  .split(",")
  .map((model) => model.trim())
  .filter(Boolean);

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
  allowedHeaders: ["Content-Type", "Accept", "x-tenant-id", "x-admin-secret", "x-teacher-token"],
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

app.use(express.json({ limit: JSON_BODY_LIMIT }));

// ─── Admin authentication middleware ──────────────────────────────────────────
function requireAdminSecret(req, res, next) {
  if (!ADMIN_SECRET) return next(); // not configured → open (dev mode)
  const provided = req.headers["x-admin-secret"] || req.query?.secret || req.body?.secret;
  if (provided !== ADMIN_SECRET) {
    return res.status(401).json({ error: "No autorizado" });
  }
  next();
}

function isValidAdminSecret(value) {
  return Boolean(ADMIN_SECRET && value && String(value) === ADMIN_SECRET);
}

function isValidAdminRequest(req) {
  return isValidAdminSecret(req.headers["x-admin-secret"] || req.query?.secret || req.body?.secret || req.query?.adminSecret);
}

function findTeacherByToken(token) {
  const clean = String(token || "").trim();
  if (!clean) return null;
  for (const registry of Object.values(teacherRegistries)) {
    const teacher = registry?.teachers?.find((item) => item.token === clean && item.active !== false);
    if (teacher) return { ...teacher, adminId: registry.adminId };
  }
  return null;
}

function isValidTeacherTokenForTenant(tenantId, token) {
  const teacher = findTeacherByToken(token);
  return Boolean(teacher && normalizeTenantId(teacher.tenantId) === normalizeTenantId(tenantId));
}

function tenantHasRegisteredTeacher(tenantId) {
  const normalizedTenantId = normalizeTenantId(tenantId);
  return Object.values(teacherRegistries)
    .some((registry) => registry?.teachers?.some((teacher) => teacher.active !== false && normalizeTenantId(teacher.tenantId) === normalizedTenantId));
}

function isValidTenantWriter(req, tenantId) {
  if (isValidAdminRequest(req)) return true;
  const token = String(req.headers["x-teacher-token"] || req.query?.teacherToken || req.body?.teacherToken || "").trim();
  return isValidTeacherTokenForTenant(tenantId, token);
}

function requireTenantWriteAccess(req, res, tenantId) {
  if (isValidTenantWriter(req, tenantId)) return true;
  if (!ADMIN_SECRET && !tenantHasRegisteredTeacher(tenantId)) return true;
  res.status(401).json({ error: "No autorizado para este espacio de trabajo" });
  return false;
}

function requireAiAccess(req, res, next) {
  const tenantId = getTenantIdFromRequest(req, req.body?.tenantId);
  if (isValidAdminRequest(req) || isValidTenantWriter(req, tenantId)) {
    req.tenantId = tenantId;
    return next();
  }
  if (!ADMIN_SECRET && !tenantHasRegisteredTeacher(tenantId)) {
    req.tenantId = tenantId;
    return next();
  }
  return res.status(401).json({ error: "No autorizado para generar con IA en este espacio de trabajo" });
}

// ─── In-memory store ──────────────────────────────────────────────────────────
const sessions = {};
const teacherRegistries = {};
const DEFAULT_TENANT_ID = "default";
let persistTimer = null;

loadStore();

function createSessionRecord(tenantId, sessionId, seed = {}) {
  return {
    tenantId: normalizeTenantId(tenantId),
    sessionId: String(sessionId || "").trim().slice(0, 128),
    results: Array.isArray(seed.results) ? seed.results : [],
    closures: Array.isArray(seed.closures) ? seed.closures : [],
    examPackage: seed.examPackage || null,
    adminClients: new Set(),
    createdAt: Number(seed.createdAt) || Date.now(),
    lastActivity: Number(seed.lastActivity) || Date.now()
  };
}

function loadStore() {
  try {
    if (!fs.existsSync(DATA_FILE)) return;
    const data = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
    Object.entries(data.sessions || {}).forEach(([key, session]) => {
      sessions[key] = createSessionRecord(session.tenantId, session.sessionId, session);
    });
    Object.entries(data.teacherRegistries || {}).forEach(([key, registry]) => {
      teacherRegistries[key] = {
        adminId: normalizeTenantId(registry?.adminId || key),
        teachers: normalizeTeacherList(registry?.teachers || []),
        updatedAt: registry?.updatedAt || new Date().toISOString()
      };
    });
  } catch (error) {
    console.error("No se pudo cargar EVAPRO_DATA_FILE:", error.message);
  }
}

function serializeStore() {
  const serializableSessions = {};
  Object.entries(sessions).forEach(([key, session]) => {
    serializableSessions[key] = {
      tenantId: session.tenantId,
      sessionId: session.sessionId,
      results: session.results,
      closures: session.closures,
      examPackage: session.examPackage,
      createdAt: session.createdAt,
      lastActivity: session.lastActivity
    };
  });
  return {
    version: 1,
    savedAt: new Date().toISOString(),
    sessions: serializableSessions,
    teacherRegistries
  };
}

function schedulePersist() {
  if (persistTimer) clearTimeout(persistTimer);
  persistTimer = setTimeout(persistStore, 250);
}

function persistStore() {
  persistTimer = null;
  try {
    fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
    fs.writeFileSync(DATA_FILE, JSON.stringify(serializeStore(), null, 2));
  } catch (error) {
    console.error("No se pudo guardar EVAPRO_DATA_FILE:", error.message);
  }
}

function persistAndExit() {
  persistStore();
  process.exit(0);
}

process.once("SIGTERM", persistAndExit);
process.once("SIGINT", persistAndExit);

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
    sessions[key] = createSessionRecord(tenantId, sessionId);
    schedulePersist();
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
    score: Number(entry.score) || 0,
    total: Number(entry.total) || 0,
    grade: Number(entry.grade) || 0,
    percent: Number(entry.percent) || 0,
    answers: Array.isArray(entry.answers) ? entry.answers.slice(0, MAX_EXAM_PACKAGE_QUESTIONS) : [],
    elapsedSeconds: Math.max(0, Math.min(Number(entry.elapsedSeconds) || 0, 24 * 60 * 60)),
    date: entry.date ? String(entry.date).slice(0, 50) : new Date().toISOString(),
    closureCode: String(entry.closureCode || "").slice(0, 20),
    closureReason: String(entry.closureReason || "").slice(0, 300),
    closureKey: String(entry.closureKey || "").slice(0, 40),
    closureDetail: String(entry.closureDetail || "").slice(0, 500),
    tenantId: normalizeTenantId(entry.tenantId)
  };
}

function normalizeComparable(value) {
  return String(value || "")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9ñ\s]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function questionKey(value) {
  return normalizeComparable(value).slice(0, 260);
}

function clamp(value, min, max) {
  const number = Number.isFinite(Number(value)) ? Number(value) : min;
  return Math.min(max, Math.max(min, number));
}

function calculateGrade(score, total) {
  const safeTotal = Math.max(1, Number(total) || 1);
  return Math.round((clamp(score, 0, safeTotal) / safeTotal) * 5 * 10) / 10;
}

function selectedAnswerLabel(question, selected) {
  const type = question?.type || "multiple_choice";
  if (type === "matching") {
    const values = Array.isArray(selected) ? selected : [];
    return (question.pairs || [])
      .map((pair, index) => `${pair.left}: ${(question.matchOptions || [])[Number(values[index])] || "Sin responder"}`)
      .join(" | ");
  }
  if (type === "fill_blank") {
    return String(selected || "").trim() || "Sin responder";
  }
  return question?.options?.[Number(selected)] || "Sin responder";
}

function correctAnswerLabel(question) {
  const type = question?.type || "multiple_choice";
  if (type === "matching") {
    return (question.pairs || []).map((pair) => `${pair.left}: ${pair.right}`).join(" | ");
  }
  if (type === "fill_blank") {
    return question.acceptedAnswers?.[0] || question.correctAnswer || "";
  }
  return question.options?.[Number(question.correct)] || "";
}

function evaluateSubmittedAnswer(question, answer) {
  const type = question?.type || "multiple_choice";
  const selected = answer?.selected;
  let isCorrect = false;

  if (type === "matching") {
    const selectedValues = Array.isArray(selected) ? selected : [];
    const expected = (question.pairs || []).map((pair) => pair.right);
    isCorrect = expected.length > 0 && expected.every((value, index) => {
      const selectedLabel = (question.matchOptions || [])[Number(selectedValues[index])] || "";
      return normalizeComparable(value) === normalizeComparable(selectedLabel);
    });
  } else if (type === "fill_blank") {
    const accepted = question.acceptedAnswers || [question.correctAnswer || ""];
    isCorrect = accepted.some((value) => normalizeComparable(value) === normalizeComparable(selected));
  } else {
    isCorrect = Number(selected) === Number(question.correct);
  }

  return {
    type,
    question: String(answer?.question || question?.question || "").slice(0, 1000),
    selected,
    isCorrect,
    selectedAnswer: selectedAnswerLabel(question, selected),
    correctAnswer: correctAnswerLabel(question),
    rationale: String(question.rationale || question.explanation || "").slice(0, 1000),
    explanation: String(question.explanation || question.rationale || "").slice(0, 1000),
    hint: String(question.hint || answer?.hint || "").slice(0, 500)
  };
}

function verifyResultEntry(session, entry) {
  const bank = Array.isArray(session?.examPackage?.questionBank) ? session.examPackage.questionBank : [];
  const submittedAnswers = Array.isArray(entry?.answers) ? entry.answers : [];
  const configuredTotal = clamp(Number(session?.examPackage?.settings?.questionTotal) || bank.length || submittedAnswers.length || 1, 1, MAX_EXAM_PACKAGE_QUESTIONS);
  const expectedTotal = bank.length ? Math.min(configuredTotal, bank.length) : configuredTotal;

  if (!bank.length || !submittedAnswers.length) {
    return {
      ...entry,
      score: 0,
      total: expectedTotal,
      percent: 0,
      grade: 0,
      verifiedByServer: Boolean(bank.length),
      verificationWarning: bank.length ? "Resultado sin respuestas verificables" : "Examen no disponible para verificacion"
    };
  }

  const byQuestion = new Map();
  bank.forEach((question) => {
    const key = questionKey(question?.question);
    if (key && !byQuestion.has(key)) byQuestion.set(key, question);
  });

  const seen = new Set();
  const verifiedAnswers = [];
  submittedAnswers.forEach((answer) => {
    const key = questionKey(answer?.question);
    if (!key || seen.has(key)) return;
    seen.add(key);
    const question = byQuestion.get(key);
    if (!question) {
      verifiedAnswers.push({
        type: answer?.type || "multiple_choice",
        question: String(answer?.question || "").slice(0, 1000),
        selected: answer?.selected,
        isCorrect: false,
        selectedAnswer: "Sin responder",
        correctAnswer: "",
        verificationWarning: "Pregunta no encontrada en el examen publicado"
      });
      return;
    }
    verifiedAnswers.push(evaluateSubmittedAnswer(question, answer));
  });

  const total = expectedTotal;
  const score = clamp(verifiedAnswers.filter((answer) => answer.isCorrect).length, 0, total);
  const percent = Math.round((score / Math.max(1, total)) * 100);
  return {
    ...entry,
    answers: verifiedAnswers,
    score,
    total,
    percent,
    grade: calculateGrade(score, total),
    verifiedByServer: true
  };
}

function sanitizeQuestionForStudent(question) {
  const type = question?.type || "multiple_choice";
  const clean = {
    question: question.question,
    type,
    difficulty: question.difficulty,
    hint: question.hint || ""
  };
  if (type === "matching") {
    clean.pairs = (question.pairs || []).map((pair) => ({ left: pair.left }));
    clean.matchOptions = Array.isArray(question.matchOptions) ? question.matchOptions : [];
    return clean;
  }
  if (type === "fill_blank") {
    return clean;
  }
  clean.options = Array.isArray(question.options) ? question.options.map(sanitizeOptionForStudent).filter(Boolean) : [];
  return clean;
}

function sanitizeOptionForStudent(option) {
  if (option && typeof option === "object") {
    return String(option.text || option.label || option.value || "").trim().slice(0, 500);
  }
  return String(option || "").trim().slice(0, 500);
}

function stripSensitiveSettings(settings = {}) {
  return {
    ...settings,
    geminiApiKey: "",
    claudeApiKey: "",
    apiKeyGemini: "",
    apiKeyClaude: "",
    googleApiKey: "",
    anthropicApiKey: "",
    adminSecret: ""
  };
}

function sanitizeExamPackageForStudent(examPackage) {
  return {
    ...examPackage,
    settings: stripSensitiveSettings(examPackage.settings || {}),
    questionBank: (examPackage.questionBank || []).map(sanitizeQuestionForStudent)
  };
}

function findAttemptByDoc(session, doc) {
  const normalizedDoc = normalizeDocument(doc);
  if (!session || !normalizedDoc) return null;
  return [...session.results, ...session.closures]
    .find((entry) => normalizeDocument(entry?.doc) === normalizedDoc) || null;
}

function isAuthorizedStudent(session, entry) {
  const allowed = Array.isArray(session?.examPackage?.allowedAccess) ? session.examPackage.allowedAccess : [];
  if (!allowed.length) return true;
  const doc = normalizeDocument(entry?.doc);
  return Boolean(doc && allowed.some((student) => normalizeDocument(student?.doc) === doc));
}

function normalizeAiInlineFiles(files) {
  const allowedMimeTypes = new Set(["application/pdf", "image/png", "image/jpeg", "image/webp", "image/bmp", "image/tiff"]);
  const cleanFiles = [];
  let totalBytes = 0;
  (Array.isArray(files) ? files : []).slice(0, 5).forEach((file) => {
    const mimeType = String(file?.mimeType || "").trim().toLowerCase();
    const data = String(file?.data || "").trim();
    if (!allowedMimeTypes.has(mimeType) || !/^[A-Za-z0-9+/=\s]+$/.test(data)) {
      return;
    }
    const bytes = Buffer.byteLength(data.replace(/\s+/g, ""), "base64");
    if (!bytes || bytes > MAX_AI_INLINE_FILE_BYTES || totalBytes + bytes > MAX_AI_INLINE_FILE_BYTES) {
      return;
    }
    cleanFiles.push({
      name: String(file?.name || "fuente").replace(/[^\w.\- ()áéíóúüñÁÉÍÓÚÜÑ]/g, "").slice(0, 160),
      mimeType,
      data: data.replace(/\s+/g, "")
    });
    totalBytes += bytes;
  });
  return cleanFiles;
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
      schedulePersist();
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
    const secret = url.searchParams.get("secret") || url.searchParams.get("adminSecret");
    const teacherToken = url.searchParams.get("teacherToken");

    if (!sessionId) { ws.close(1008, "sessionId requerido"); return; }

    const session = getSession(tenantId, sessionId);

    if (role === "admin") {
      const allowed = isValidAdminSecret(secret) ||
        isValidTeacherTokenForTenant(tenantId, teacherToken) ||
        (!ADMIN_SECRET && !tenantHasRegisteredTeacher(tenantId));
      if (!allowed) { ws.close(1008, "No autorizado"); return; }
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
  schedulePersist();
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
  if (!isAuthorizedStudent(session, entry)) {
    return res.status(403).json({ error: "Estudiante no autorizado para esta sesión" });
  }
  if (session.results.length >= MAX_RESULTS_PER_SESSION) {
    return res.status(400).json({ error: "Límite de resultados alcanzado para esta sesión" });
  }

  const normalizedDoc = normalizeDocument(entry.doc);
  const previousResult = session.results.find((r) => normalizeDocument(r.doc) === normalizedDoc);
  const previousClosure = session.closures.find((c) => normalizeDocument(c.doc) === normalizedDoc && c.date !== entry.date);

  if (previousResult || previousClosure) {
    return res.json({ ok: true, duplicate: true, blocked: true, entry: previousResult || previousClosure });
  }

  const isDuplicate = session.results.some((r) => r.doc === entry.doc && r.date === entry.date);
  if (!isDuplicate) {
    const result = verifyResultEntry(session, { ...entry, tenantId, sessionId, receivedAt: new Date().toISOString() });
    session.results.push(result);
    schedulePersist();
    broadcast(tenantId, sessionId, { type: "result", entry: result });
  }
  return res.json({ ok: true, duplicate: isDuplicate, entry: isDuplicate ? session.results.find((r) => r.doc === entry.doc && r.date === entry.date) || null : session.results[session.results.length - 1] });
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
  if (!isAuthorizedStudent(session, entry)) {
    return res.status(403).json({ error: "Estudiante no autorizado para esta sesión" });
  }
  if (session.closures.length >= MAX_RESULTS_PER_SESSION) {
    return res.status(400).json({ error: "Límite de cierres alcanzado para esta sesión" });
  }

  const normalizedDoc = normalizeDocument(entry.doc);
  const previousClosure = session.closures.find((c) => normalizeDocument(c.doc) === normalizedDoc);
  const previousResult = session.results.find((r) => normalizeDocument(r.doc) === normalizedDoc && r.date !== entry.date);

  if (previousClosure || previousResult) {
    return res.json({ ok: true, duplicate: true, blocked: true, entry: previousClosure || previousResult });
  }

  const isDuplicate = session.closures.some((c) => c.doc === entry.doc && c.date === entry.date);
  if (!isDuplicate) {
    const closure = verifyResultEntry(session, { ...entry, tenantId, sessionId, receivedAt: new Date().toISOString() });
    session.closures.push(closure);
    schedulePersist();
    broadcast(tenantId, sessionId, { type: "closure", entry: closure });
  }
  return res.json({ ok: true, duplicate: isDuplicate, entry: isDuplicate ? session.closures.find((c) => c.doc === entry.doc && c.date === entry.date) || null : session.closures[session.closures.length - 1] });
});

// GET /api/results/:sessionId  — admin polls results (fallback if WS unavailable)
app.get("/api/results/:sessionId", (req, res) => {
  const tenantId = getTenantIdFromRequest(req);
  if (!requireTenantWriteAccess(req, res, tenantId)) return;
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
  return res.json({
    ok: true,
    tenantId,
    sessionId: req.params.sessionId,
    blocked: Boolean(entry),
    entry: entry ? { doc: entry.doc, name: entry.name, closureCode: entry.closureCode, closureReason: entry.closureReason } : null
  });
});

// DELETE /api/results/:sessionId  — admin clears results (requires admin secret)
app.delete("/api/results/:sessionId", (req, res) => {
  const tenantId = getTenantIdFromRequest(req);
  if (!requireTenantWriteAccess(req, res, tenantId)) return;
  const session = readSession(tenantId, req.params.sessionId);
  if (session) {
    session.results = [];
    session.closures = [];
    schedulePersist();
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
  if (!requireTenantWriteAccess(req, res, tenantId)) return;

  if (!sessionId || !examPackage?.schema || !Array.isArray(examPackage.questionBank) || !examPackage.questionBank.length) {
    return res.status(400).json({ error: "Paquete de examen inválido o vacío" });
  }
  if (examPackage.questionBank.length > MAX_EXAM_PACKAGE_QUESTIONS) {
    return res.status(400).json({ error: `Máximo ${MAX_EXAM_PACKAGE_QUESTIONS} preguntas por paquete` });
  }

  // Strip AI keys before storing
  const safePackage = { ...examPackage };
  if (safePackage.settings) {
    safePackage.settings = stripSensitiveSettings(safePackage.settings);
  }

  const session = getSession(tenantId, sessionId);
  session.examPackage = { ...safePackage, tenantId, sessionId, receivedAt: new Date().toISOString() };
  schedulePersist();
  broadcast(tenantId, sessionId, { type: "exam-updated", updatedAt: session.examPackage.receivedAt, questionCount: session.examPackage.questionBank.length });
  return res.json({ ok: true, tenantId, sessionId, questionCount: session.examPackage.questionBank.length, updatedAt: session.examPackage.receivedAt });
});

// GET /api/exam/:sessionId  — student downloads the active exam package
app.get("/api/exam/:sessionId", (req, res) => {
  const tenantId = getTenantIdFromRequest(req);
  const session = readSession(tenantId, req.params.sessionId);
  if (!session?.examPackage) return res.status(404).json({ error: "No hay examen publicado para esta sesión" });
  return res.json({ ok: true, tenantId, sessionId: req.params.sessionId, package: sanitizeExamPackageForStudent(session.examPackage) });
});

// ─── YouTube Transcript Proxy ─────────────────────────────────────────────────
app.post("/api/ai/generate", requireAiAccess, async (req, res) => {
  if (!checkRateLimit(req, "default")) {
    return res.status(429).json({ error: "Demasiadas solicitudes." });
  }
  const provider = String(req.body?.provider || "").toLowerCase();
  const prompt = String(req.body?.prompt || "");
  const maxTokens = clamp(Number(req.body?.maxTokens) || 8192, 1024, 32768);
  if (!prompt || prompt.length > 900000) {
    return res.status(400).json({ error: "Prompt vacio o demasiado grande" });
  }

  try {
    if (provider === "claude") {
      if (!process.env.CLAUDE_API_KEY) return res.status(400).json({ error: "CLAUDE_API_KEY no configurada en Render" });
      let lastStatus = 502;
      let lastError = "Claude no pudo completar la generacion";
      for (const model of CLAUDE_MODEL_FALLBACKS) {
        const response = await fetch("https://api.anthropic.com/v1/messages", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-api-key": process.env.CLAUDE_API_KEY,
            "anthropic-version": "2023-06-01"
          },
          body: JSON.stringify({
            model,
            max_tokens: maxTokens,
            messages: [{ role: "user", content: prompt }]
          })
        });
        const data = await response.json().catch(() => ({}));
        if (response.ok) return res.json({ ok: true, provider, model, text: data?.content?.[0]?.text || "" });
        lastStatus = response.status;
        lastError = data?.error?.message || `Claude no pudo completar la generacion con ${model}`;
        if (![400, 404].includes(response.status)) break;
      }
      return res.status(lastStatus).json({ error: lastError });
    }

    if (provider === "gemini") {
      if (!process.env.GEMINI_API_KEY) return res.status(400).json({ error: "GEMINI_API_KEY no configurada en Render" });
      const inlineFiles = normalizeAiInlineFiles(req.body?.files);
      const parts = [
        { text: prompt },
        ...inlineFiles.flatMap((file) => [
          { text: `Fuente adjunta: ${file.name}` },
          { inlineData: { mimeType: file.mimeType, data: file.data } }
        ])
      ];
      let lastStatus = 502;
      let lastError = "Gemini no pudo completar la generacion";
      for (const model of GEMINI_MODEL_FALLBACKS) {
        const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${process.env.GEMINI_API_KEY}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            contents: [{ parts }],
            generationConfig: { maxOutputTokens: maxTokens }
          })
        });
        const data = await response.json().catch(() => ({}));
        if (response.ok) return res.json({ ok: true, provider, model, text: data?.candidates?.[0]?.content?.parts?.[0]?.text || "" });
        lastStatus = response.status;
        lastError = data?.error?.message || `Gemini no pudo completar la generacion con ${model}`;
        if (![400, 404].includes(response.status)) break;
      }
      return res.status(lastStatus).json({ error: lastError });
    }

    return res.status(400).json({ error: "Proveedor IA no soportado" });
  } catch (error) {
    return res.status(502).json({ error: error.message || "Error al conectar con el proveedor IA" });
  }
});

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
