const express = require("express");
const http = require("http");
const fs = require("fs");
const path = require("path");
const WebSocket = require("ws");
const cors = require("cors");
const { Pool } = require("pg");

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// ─── Security & Configuration ─────────────────────────────────────────────────
const DEFAULT_ALLOWED_ORIGINS = [
  "https://evaluapro-utch.netlify.app",
  "http://localhost:4327",
  "http://localhost:4331",
  "http://localhost:4333",
  "http://127.0.0.1:4327",
  "http://127.0.0.1:4331",
  "http://127.0.0.1:4333"
];
const ALLOW_FILE_ORIGIN = process.env.ALLOW_FILE_ORIGIN !== "false";
const ALLOWED_ORIGINS = [
  ...DEFAULT_ALLOWED_ORIGINS,
  ...(process.env.ALLOWED_ORIGINS || "").split(",")
]
  .map(normalizeCorsOrigin)
  .filter(Boolean)
  .filter((origin, index, list) => list.indexOf(origin) === index);

const ADMIN_SECRET = process.env.ADMIN_SECRET || "";
const DATA_FILE = process.env.EVAPRO_DATA_FILE || path.join(__dirname, "data", "evapro-store.json");
const DATABASE_URL = process.env.DATABASE_URL || process.env.SUPABASE_DATABASE_URL || "";
const JSON_BODY_LIMIT = process.env.JSON_BODY_LIMIT || "70mb";
const LEGACY_INLINE_LIMIT = Number(process.env.MAX_AI_INLINE_FILE_BYTES || 0);
const MAX_AI_FILE_BYTES = Number(process.env.MAX_AI_FILE_BYTES || 45 * 1024 * 1024);
const GEMINI_INLINE_TOTAL_LIMIT = Number(process.env.GEMINI_INLINE_TOTAL_LIMIT || LEGACY_INLINE_LIMIT || 18 * 1024 * 1024);
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
const INPUT_LIMITS = {
  name: 160,
  shortText: 500,
  question: 1200,
  option: 700,
  rationale: 1400,
  prompt: 900000,
  url: 900
};
const ACADEMIC_MODES = ["institutional"];

// ─── CORS ─────────────────────────────────────────────────────────────────────
function normalizeCorsOrigin(origin) {
  const clean = String(origin || "").trim().replace(/\/$/, "");
  if (!clean) return "";
  if (clean === "*" || clean === "null") return clean;
  try {
    return new URL(clean).origin;
  } catch {
    return clean;
  }
}

function isAllowedCorsOrigin(origin) {
  const clean = normalizeCorsOrigin(origin);
  if (!clean) return true;
  if (ALLOW_FILE_ORIGIN && clean === "null") return true;
  if (ALLOWED_ORIGINS.includes("*")) return true;
  return ALLOWED_ORIGINS.includes(clean);
}

const corsOptions = {
  origin: (origin, cb) => {
    if (isAllowedCorsOrigin(origin)) {
      cb(null, true);
    } else {
      cb(new Error(`CORS: origin not allowed (${origin || "empty"})`));
    }
  },
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

app.use(async (_req, _res, next) => {
  try {
    await storeReady;
    next();
  } catch (error) {
    next(error);
  }
});

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
  const clean = sanitizeToken(token || "", 64);
  if (!clean) return null;
  for (const registry of Object.values(teacherRegistries)) {
    const teacher = registry?.teachers?.find((item) => item.token === clean && item.active !== false);
    if (teacher) return { ...teacher, adminId: registry.adminId };
  }
  return null;
}

function teacherCanUseAcademicMode(teacher, academicMode) {
  if (!academicMode) return true;
  return normalizeAcademicModes(teacher?.academicModes).includes(sanitizeAcademicMode(academicMode));
}

function isValidTeacherTokenForTenant(tenantId, token, academicMode = "") {
  const teacher = findTeacherByToken(token);
  return Boolean(
    teacher &&
    normalizeTenantId(teacher.tenantId) === normalizeTenantId(tenantId) &&
    teacherCanUseAcademicMode(teacher, academicMode)
  );
}

function tenantHasRegisteredTeacher(tenantId) {
  const normalizedTenantId = normalizeTenantId(tenantId);
  return Object.values(teacherRegistries)
    .some((registry) => registry?.teachers?.some((teacher) => teacher.active !== false && normalizeTenantId(teacher.tenantId) === normalizedTenantId));
}

function isValidTenantWriter(req, tenantId, academicMode = "") {
  if (isValidAdminRequest(req)) return true;
  const token = sanitizeToken(req.headers["x-teacher-token"] || req.query?.teacherToken || req.body?.teacherToken || "", 64);
  return isValidTeacherTokenForTenant(tenantId, token, academicMode);
}

function requireTenantWriteAccess(req, res, tenantId, academicMode = "") {
  if (isValidTenantWriter(req, tenantId, academicMode)) return true;
  if (!ADMIN_SECRET && !tenantHasRegisteredTeacher(tenantId)) return true;
  res.status(401).json({ error: "No autorizado para este espacio de trabajo" });
  return false;
}

function requireAiAccess(req, res, next) {
  const tenantId = getTenantIdFromRequest(req, req.body?.tenantId);
  const academicMode = sanitizeAcademicMode(req.body?.academicMode || req.query?.academicMode || "");
  if (isValidAdminRequest(req) || isValidTenantWriter(req, tenantId, academicMode)) {
    req.tenantId = tenantId;
    req.academicMode = academicMode;
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
let dbPool = null;
let storageMode = DATABASE_URL ? "postgres" : "json";
const storeReady = loadStore();

function createSessionRecord(tenantId, sessionId, seed = {}) {
  const normalizedTenantId = normalizeTenantId(tenantId);
  const normalizedSessionId = sanitizeSessionId(sessionId);
  const examPackage = seed.examPackage
    ? sanitizeExamPackageForStorage(seed.examPackage, normalizedTenantId, normalizedSessionId)
    : null;
  return {
    tenantId: normalizedTenantId,
    sessionId: normalizedSessionId,
    results: (Array.isArray(seed.results) ? seed.results : []).map(sanitizeEntry).filter(Boolean).slice(0, MAX_RESULTS_PER_SESSION),
    closures: (Array.isArray(seed.closures) ? seed.closures : []).map(sanitizeEntry).filter(Boolean).slice(0, MAX_RESULTS_PER_SESSION),
    examPackage: examPackage?.questionBank?.length ? examPackage : null,
    adminClients: new Set(),
    createdAt: Number(seed.createdAt) || Date.now(),
    lastActivity: Number(seed.lastActivity) || Date.now()
  };
}

function getDatabasePool() {
  if (!DATABASE_URL) return null;
  if (!dbPool) {
    dbPool = new Pool({
      connectionString: DATABASE_URL,
      ssl: { rejectUnauthorized: false },
      max: Number(process.env.DATABASE_POOL_MAX || 5),
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 15_000
    });
  }
  return dbPool;
}

async function ensureDatabaseTables() {
  const pool = getDatabasePool();
  if (!pool) return false;
  await pool.query(`
    create table if not exists evapro_sessions (
      tenant_id text not null,
      session_id text not null,
      results jsonb not null default '[]'::jsonb,
      closures jsonb not null default '[]'::jsonb,
      exam_package jsonb,
      created_at bigint not null,
      last_activity bigint not null,
      primary key (tenant_id, session_id)
    );
  `);
  await pool.query(`
    create index if not exists evapro_sessions_last_activity_idx
    on evapro_sessions (last_activity);
  `);
  await pool.query(`
    create table if not exists evapro_teacher_registries (
      admin_id text primary key,
      teachers jsonb not null default '[]'::jsonb,
      updated_at text not null
    );
  `);
  return true;
}

async function loadPostgresStore() {
  await ensureDatabaseTables();
  const pool = getDatabasePool();
  const [sessionRows, teacherRows] = await Promise.all([
    pool.query("select tenant_id, session_id, results, closures, exam_package, created_at, last_activity from evapro_sessions"),
    pool.query("select admin_id, teachers, updated_at from evapro_teacher_registries")
  ]);
  sessionRows.rows.forEach((row) => {
    const session = createSessionRecord(row.tenant_id, row.session_id, {
      results: Array.isArray(row.results) ? row.results : [],
      closures: Array.isArray(row.closures) ? row.closures : [],
      examPackage: row.exam_package || null,
      createdAt: Number(row.created_at) || Date.now(),
      lastActivity: Number(row.last_activity) || Date.now()
    });
    sessions[sessionKey(session.tenantId, session.sessionId)] = session;
  });
  teacherRows.rows.forEach((row) => {
    const adminId = normalizeTenantId(row.admin_id);
    teacherRegistries[adminId] = {
      adminId,
      teachers: normalizeTeacherList(row.teachers || []),
      updatedAt: sanitizeText(row.updated_at || new Date().toISOString(), { maxLength: 50 })
    };
  });
}

async function loadStore() {
  if (DATABASE_URL) {
    try {
      await loadPostgresStore();
      storageMode = "postgres";
      console.log("EVAPRO store conectado a Supabase/Postgres.");
      return;
    } catch (error) {
      storageMode = "json";
      console.error("No se pudo conectar a Supabase/Postgres. Se usara respaldo JSON:", error.message);
    }
  }

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
  persistTimer = setTimeout(() => {
    persistStore().catch((error) => {
      console.error("No se pudo persistir EVAPRO store:", error.message);
    });
  }, 250);
}

async function persistPostgresStore() {
  await ensureDatabaseTables();
  const pool = getDatabasePool();
  const client = await pool.connect();
  try {
    await client.query("begin");
    await client.query("delete from evapro_sessions");
    await client.query("delete from evapro_teacher_registries");

    for (const session of Object.values(sessions)) {
      await client.query(
        `insert into evapro_sessions
          (tenant_id, session_id, results, closures, exam_package, created_at, last_activity)
         values ($1, $2, $3::jsonb, $4::jsonb, $5::jsonb, $6, $7)`,
        [
          session.tenantId,
          session.sessionId,
          JSON.stringify(session.results || []),
          JSON.stringify(session.closures || []),
          session.examPackage ? JSON.stringify(session.examPackage) : null,
          Number(session.createdAt) || Date.now(),
          Number(session.lastActivity) || Date.now()
        ]
      );
    }

    for (const registry of Object.values(teacherRegistries)) {
      await client.query(
        `insert into evapro_teacher_registries (admin_id, teachers, updated_at)
         values ($1, $2::jsonb, $3)`,
        [
          normalizeTenantId(registry.adminId),
          JSON.stringify(normalizeTeacherList(registry.teachers || [])),
          sanitizeText(registry.updatedAt || new Date().toISOString(), { maxLength: 50 })
        ]
      );
    }
    await client.query("commit");
    storageMode = "postgres";
  } catch (error) {
    await client.query("rollback").catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

function persistJsonStore() {
  try {
    fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
    fs.writeFileSync(DATA_FILE, JSON.stringify(serializeStore(), null, 2));
  } catch (error) {
    console.error("No se pudo guardar EVAPRO_DATA_FILE:", error.message);
  }
}

async function persistStore() {
  if (persistTimer) {
    clearTimeout(persistTimer);
    persistTimer = null;
  }
  if (DATABASE_URL) {
    try {
      await persistPostgresStore();
      return;
    } catch (error) {
      storageMode = "json";
      console.error("No se pudo guardar en Supabase/Postgres. Se usara respaldo JSON:", error.message);
    }
  }
  persistJsonStore();
}

async function persistAndExit() {
  try {
    await persistStore();
    if (dbPool) {
      await dbPool.end();
    }
  } finally {
    process.exit(0);
  }
}

process.once("SIGTERM", () => { persistAndExit(); });
process.once("SIGINT", () => { persistAndExit(); });

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
  return `${normalizeTenantId(tenantId)}::${sanitizeSessionId(sessionId)}`;
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

function stripUnsafeText(value) {
  return String(value || "")
    .normalize("NFC")
    .replace(/\u0000/g, "")
    .replace(/[\u0001-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "")
    .replace(/<\s*(script|style|iframe|object|embed|meta|link|base|form)[^>]*>[\s\S]*?<\s*\/\s*\1\s*>/gi, " ")
    .replace(/<\s*(script|style|iframe|object|embed|meta|link|base|form)[^>]*\/?\s*>/gi, " ")
    .replace(/\s+on[a-z]+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, " ")
    .replace(/\b(?:javascript|vbscript|data)\s*:/gi, "");
}

function sanitizeText(value, options = {}) {
  const maxLength = Number(options.maxLength) || INPUT_LIMITS.shortText;
  const multiline = Boolean(options.multiline);
  let clean = stripUnsafeText(value);
  clean = multiline
    ? clean.replace(/[ \t]+\n/g, "\n").replace(/\n{4,}/g, "\n\n\n")
    : clean.replace(/\s+/g, " ");
  return clean.trim().slice(0, maxLength);
}

function sanitizeName(value) {
  return sanitizeText(value, { maxLength: INPUT_LIMITS.name })
    .replace(/[<>()[\]{}=+*/\\|~^`]/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

function sanitizeToken(value, maxLength = 128) {
  return String(value || "").trim().replace(/[^a-zA-Z0-9_.-]/g, "").slice(0, maxLength);
}

function sanitizeSessionId(value) {
  return sanitizeToken(value, 128);
}

function sanitizeDifficulty(value) {
  const clean = String(value || "").trim().toLowerCase();
  return ["low", "medium", "high"].includes(clean) ? clean : "medium";
}

function sanitizeAcademicMode(value) {
  return "institutional";
}

function normalizeAcademicModes(value) {
  return ["institutional"];
}

function sanitizeUrl(value) {
  const raw = sanitizeText(value, { maxLength: INPUT_LIMITS.url });
  if (!raw) return "";
  try {
    const url = new URL(raw);
    if (!["http:", "https:"].includes(url.protocol)) return "";
    url.hash = "";
    return url.href.replace(/\/$/, "");
  } catch {
    return "";
  }
}

function normalizeQuestionTypesForStorage(value) {
  const allowed = new Set(["multiple_choice", "true_false", "matching", "fill_blank"]);
  const selected = (Array.isArray(value) ? value : [])
    .map((type) => String(type || "").trim())
    .filter((type) => allowed.has(type));
  return selected.length ? [...new Set(selected)] : ["multiple_choice"];
}

function sanitizeEntry(entry) {
  if (!entry || typeof entry !== "object") return null;
  const doc = normalizeDocument(entry.doc);
  if (!doc || doc.length < 5) return null;
  const total = clamp(Number(entry.total) || 0, 0, MAX_EXAM_PACKAGE_QUESTIONS);
  const score = clamp(Number(entry.score) || 0, 0, Math.max(total, MAX_EXAM_PACKAGE_QUESTIONS));
  return {
    doc,
    name: sanitizeName(entry.name),
    score,
    total,
    exerciseTotal: clamp(Number(entry.exerciseTotal) || total, 0, MAX_EXAM_PACKAGE_QUESTIONS),
    pendingReview: clamp(Number(entry.pendingReview) || 0, 0, MAX_EXAM_PACKAGE_QUESTIONS),
    grade: clamp(Number(entry.grade) || 0, 0, 5),
    percent: clamp(Number(entry.percent) || 0, 0, 100),
    answers: sanitizeSubmittedAnswers(entry.answers),
    elapsedSeconds: Math.max(0, Math.min(Number(entry.elapsedSeconds) || 0, 24 * 60 * 60)),
    date: sanitizeText(entry.date || new Date().toISOString(), { maxLength: 50 }),
    closureCode: sanitizeText(entry.closureCode || "", { maxLength: 20 }),
    closureReason: sanitizeText(entry.closureReason || "", { maxLength: 300 }),
    closureKey: sanitizeText(entry.closureKey || "", { maxLength: 40 }),
    closureDetail: sanitizeText(entry.closureDetail || "", { maxLength: 500 }),
    academicMode: sanitizeAcademicMode(entry.academicMode || ""),
    tenantId: normalizeTenantId(entry.tenantId)
  };
}

function sanitizeSubmittedAnswers(answers) {
  return (Array.isArray(answers) ? answers : [])
    .slice(0, MAX_EXAM_PACKAGE_QUESTIONS)
    .map(sanitizeSubmittedAnswer)
    .filter(Boolean);
}

function sanitizeSubmittedAnswer(answer) {
  if (!answer || typeof answer !== "object") return null;
  const type = normalizeQuestionType(answer.type);
  const clean = {
    type,
    question: sanitizeText(answer.question || "", { maxLength: INPUT_LIMITS.question, multiline: true }),
    selected: sanitizeSelectedValue(answer.selected, type),
    isCorrect: Boolean(answer.isCorrect),
    selectedAnswer: sanitizeText(answer.selectedAnswer || "", { maxLength: 1000, multiline: true }),
    correctAnswer: sanitizeText(answer.correctAnswer || "", { maxLength: 1000, multiline: true }),
    explanation: sanitizeText(answer.explanation || answer.rationale || "", { maxLength: INPUT_LIMITS.rationale, multiline: true }),
    rationale: sanitizeText(answer.rationale || answer.explanation || "", { maxLength: INPUT_LIMITS.rationale, multiline: true }),
    hint: sanitizeText(answer.hint || "", { maxLength: INPUT_LIMITS.shortText, multiline: true })
  };
  clean.pendingReview = Boolean(answer.pendingReview);
  clean.area = sanitizeText(answer.area || "", { maxLength: 120 });
  clean.competency = sanitizeText(answer.competency || "", { maxLength: 240 });
  clean.module = sanitizeText(answer.module || "", { maxLength: 160 });
  if (Array.isArray(answer.options)) {
    clean.options = answer.options.map(sanitizeOptionText).filter(Boolean).slice(0, 5);
  }
  if (Array.isArray(answer.pairs)) {
    clean.pairs = answer.pairs
      .map((pair) => ({
        left: sanitizeText(pair?.left || "", { maxLength: 300 }),
        right: sanitizeText(pair?.right || "", { maxLength: 500 })
      }))
      .filter((pair) => pair.left || pair.right)
      .slice(0, 20);
  }
  if (Array.isArray(answer.matchOptions)) {
    clean.matchOptions = answer.matchOptions.map(sanitizeOptionText).filter(Boolean).slice(0, 30);
  }
  if (Array.isArray(answer.acceptedAnswers)) {
    clean.acceptedAnswers = answer.acceptedAnswers
      .map((value) => sanitizeText(value || "", { maxLength: 220 }))
      .filter(Boolean)
      .slice(0, 10);
  }
  return clean.question ? clean : null;
}

function sanitizeSelectedValue(selected, type) {
  if (type === "matching") {
    return Array.isArray(selected)
      ? selected.map((value) => {
          const index = Number(value);
          return Number.isInteger(index) && index >= 0 ? index : "";
        }).slice(0, 20)
      : [];
  }
  if (type === "fill_blank") {
    return sanitizeText(selected || "", { maxLength: 220 });
  }
  if (type === "open_response") {
    return sanitizeText(selected || "", { maxLength: 2400, multiline: true });
  }
  const index = Number(selected);
  return Number.isInteger(index) && index >= 0 ? index : null;
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
  if (type === "open_response") {
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
  if (type === "open_response") {
    return "Respuesta abierta pendiente de revision docente";
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
  } else if (type === "open_response") {
    return {
      type,
      question: sanitizeText(answer?.question || question?.question || "", { maxLength: 1000, multiline: true }),
      selected: sanitizeSelectedValue(selected, type),
      isCorrect: false,
      pendingReview: true,
      selectedAnswer: sanitizeText(selectedAnswerLabel(question, selected), { maxLength: 2400, multiline: true }),
      correctAnswer: "Respuesta abierta pendiente de revision docente",
      rationale: sanitizeText(question.rationale || question.explanation || "", { maxLength: 1000, multiline: true }),
      explanation: sanitizeText(question.explanation || question.rationale || "", { maxLength: 1000, multiline: true }),
      hint: sanitizeText(question.hint || answer?.hint || "", { maxLength: 500, multiline: true }),
      area: sanitizeText(question.area || answer?.area || "", { maxLength: 120 }),
      competency: sanitizeText(question.competency || answer?.competency || "", { maxLength: 240 }),
      module: sanitizeText(question.module || answer?.module || "", { maxLength: 160 }),
      rubric: (Array.isArray(question.rubric) ? question.rubric : []).map((item) => sanitizeText(item || "", { maxLength: 300 })).filter(Boolean).slice(0, 6)
    };
  } else {
    isCorrect = Number(selected) === Number(question.correct);
  }

  return {
    type,
    question: sanitizeText(answer?.question || question?.question || "", { maxLength: 1000, multiline: true }),
    selected: sanitizeSelectedValue(selected, type),
    isCorrect,
    selectedAnswer: sanitizeText(selectedAnswerLabel(question, selected), { maxLength: 1000, multiline: true }),
    correctAnswer: sanitizeText(correctAnswerLabel(question), { maxLength: 1000, multiline: true }),
    rationale: sanitizeText(question.rationale || question.explanation || "", { maxLength: 1000, multiline: true }),
    explanation: sanitizeText(question.explanation || question.rationale || "", { maxLength: 1000, multiline: true }),
    hint: sanitizeText(question.hint || answer?.hint || "", { maxLength: 500, multiline: true }),
    area: sanitizeText(question.area || answer?.area || "", { maxLength: 120 }),
    competency: sanitizeText(question.competency || answer?.competency || "", { maxLength: 240 }),
    module: sanitizeText(question.module || answer?.module || "", { maxLength: 160 })
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
      exerciseTotal: expectedTotal,
      pendingReview: 0,
      percent: 0,
      grade: 0,
      academicMode: sanitizeAcademicMode(entry.academicMode || session?.examPackage?.academicMode || session?.examPackage?.settings?.academicMode),
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
        type: normalizeQuestionType(answer?.type),
        question: sanitizeText(answer?.question || "", { maxLength: 1000, multiline: true }),
        selected: sanitizeSelectedValue(answer?.selected, normalizeQuestionType(answer?.type)),
        isCorrect: false,
        selectedAnswer: "Sin responder",
        correctAnswer: "",
        verificationWarning: "Pregunta no encontrada en el examen publicado"
      });
      return;
    }
    verifiedAnswers.push(evaluateSubmittedAnswer(question, answer));
  });

  const exerciseTotal = expectedTotal;
  const pendingReview = verifiedAnswers.filter((answer) => answer.pendingReview || answer.type === "open_response").length;
  const total = Math.max(1, exerciseTotal - pendingReview);
  const score = clamp(verifiedAnswers.filter((answer) => answer.isCorrect).length, 0, total);
  const percent = Math.round((score / Math.max(1, total)) * 100);
  return {
    ...entry,
    answers: verifiedAnswers,
    score,
    total,
    exerciseTotal,
    pendingReview,
    percent,
    grade: calculateGrade(score, total),
    academicMode: sanitizeAcademicMode(entry.academicMode || session?.examPackage?.academicMode || session?.examPackage?.settings?.academicMode),
    verifiedByServer: true
  };
}

function normalizeQuestionType(type) {
  const clean = String(type || "").trim();
  return ["multiple_choice", "true_false", "matching", "fill_blank"].includes(clean) ? clean : "multiple_choice";
}

function sanitizeOptionText(option) {
  if (option && typeof option === "object") {
    return sanitizeText(option.text || option.label || option.value || "", { maxLength: INPUT_LIMITS.option, multiline: true });
  }
  return sanitizeText(option || "", { maxLength: INPUT_LIMITS.option, multiline: true });
}

function sanitizeSettingsForStorage(settings = {}) {
  const clean = {
    readSeconds: clamp(Number(settings.readSeconds) || 50, 5, 3600),
    answerSeconds: clamp(Number(settings.answerSeconds) || 20, 5, 3600),
    questionTotal: clamp(Number(settings.questionTotal) || 10, 1, MAX_EXAM_PACKAGE_QUESTIONS),
    difficulty: sanitizeDifficulty(settings.difficulty),
    academicMode: "institutional",
    questionTypes: normalizeQuestionTypesForStorage(settings.questionTypes),
    serverUrl: sanitizeUrl(settings.serverUrl || "")
  };
  return stripSensitiveSettings(clean);
}

function sanitizeSimulatorConfigForStorage(value) {
  const input = value && typeof value === "object" ? value : {};
  const sanitizeIds = (items, max = 8) => (Array.isArray(items) ? items : [])
    .map((item) => String(item || "").trim())
    .filter((item, index, list) => /^[a-z_]{2,60}$/.test(item) && list.indexOf(item) === index)
    .slice(0, max);
  return {
    strategy: input.strategy === "focused" ? "focused" : "balanced",
    preicfesAreas: sanitizeIds(input.preicfesAreas, 5),
    presaberproModules: sanitizeIds(input.presaberproModules, 6),
    specificModule: sanitizeText(input.specificModule || "", { maxLength: 160 })
  };
}

function sanitizeAccessListForStorage(list) {
  const seen = new Set();
  return (Array.isArray(list) ? list : [])
    .map((student) => ({
      name: sanitizeName(student?.name || ""),
      doc: normalizeDocument(student?.doc)
    }))
    .filter((student) => student.name && student.doc.length >= 5)
    .filter((student) => {
      if (seen.has(student.doc)) return false;
      seen.add(student.doc);
      return true;
    })
    .slice(0, 1000);
}

function sanitizeQuestionForStorage(question) {
  if (!question || typeof question !== "object") return null;
  const type = String(question.type || "multiple_choice").trim();
  if (!["multiple_choice", "true_false", "matching", "fill_blank"].includes(type)) return null;
  const cleanQuestion = sanitizeText(question.question || "", { maxLength: INPUT_LIMITS.question, multiline: true });
  if (!cleanQuestion) return null;

  const rationale = sanitizeText(question.rationale || question.explanation || "", { maxLength: INPUT_LIMITS.rationale, multiline: true });
  const base = {
    question: cleanQuestion,
    type,
    difficulty: sanitizeDifficulty(question.difficulty),
    isCorrect: Boolean(question.isCorrect ?? true),
    rationale,
    explanation: rationale,
    hint: sanitizeText(question.hint || "", { maxLength: INPUT_LIMITS.shortText, multiline: true }),
    area: sanitizeText(question.area || "", { maxLength: 120 }),
    competency: sanitizeText(question.competency || "", { maxLength: 240 }),
    module: sanitizeText(question.module || "", { maxLength: 160 })
  };

  if (type === "open_response") {
    const rubric = (Array.isArray(question.rubric) ? question.rubric : [])
      .map((criterion) => sanitizeText(criterion || "", { maxLength: 300 }))
      .filter(Boolean)
      .slice(0, 6);
    if (rubric.length < 2) return null;
    return {
      ...base,
      expectedResponse: sanitizeText(question.expectedResponse || question.correctAnswer || "", { maxLength: 1200, multiline: true }),
      rubric
    };
  }

  if (type === "matching") {
    const pairs = (Array.isArray(question.pairs) ? question.pairs : [])
      .map((pair) => ({
        left: sanitizeText(pair?.left || "", { maxLength: 300 }),
        right: sanitizeText(pair?.right || "", { maxLength: 500 })
      }))
      .filter((pair) => pair.left && pair.right)
      .slice(0, 20);
    if (pairs.length < 2) return null;
    const matchOptions = [];
    [...(Array.isArray(question.matchOptions) ? question.matchOptions : []), ...pairs.map((pair) => pair.right)]
      .map(sanitizeOptionText)
      .filter(Boolean)
      .forEach((option) => {
        const key = normalizeComparable(option);
        if (!matchOptions.some((existing) => normalizeComparable(existing) === key)) matchOptions.push(option);
      });
    return { ...base, pairs, matchOptions: matchOptions.slice(0, 30) };
  }

  if (type === "fill_blank") {
    const acceptedAnswers = (Array.isArray(question.acceptedAnswers) ? question.acceptedAnswers : [question.correctAnswer])
      .map((answer) => sanitizeText(answer || "", { maxLength: 220 }))
      .filter(Boolean)
      .slice(0, 10);
    if (!acceptedAnswers.length) return null;
    return { ...base, correctAnswer: acceptedAnswers[0], acceptedAnswers };
  }

  const options = (Array.isArray(question.options) ? question.options : [])
    .map(sanitizeOptionText)
    .filter(Boolean)
    .slice(0, 5);
  const correct = Number(question.correct);
  const requiredOptions = type === "true_false" ? 2 : 3;
  if (options.length < requiredOptions || !Number.isInteger(correct) || correct < 0 || correct >= options.length) {
    return null;
  }
  return { ...base, type: type === "true_false" ? "true_false" : "multiple_choice", options, correct };
}

function sanitizeExamPackageForStorage(examPackage, tenantId, sessionId) {
  const questionBank = (Array.isArray(examPackage?.questionBank) ? examPackage.questionBank : [])
    .slice(0, MAX_EXAM_PACKAGE_QUESTIONS)
    .map(sanitizeQuestionForStorage)
    .filter(Boolean);
  return {
    schema: sanitizeText(examPackage?.schema || "evaluapro-utch.studentlink.v3", { maxLength: 80 }),
    settings: sanitizeSettingsForStorage({
      ...(examPackage?.settings || {}),
      academicMode: examPackage?.academicMode || examPackage?.settings?.academicMode
    }),
    allowedAccess: sanitizeAccessListForStorage(examPackage?.allowedAccess || []),
    questionBank,
    tenantId: normalizeTenantId(tenantId || examPackage?.tenantId),
    academicMode: sanitizeAcademicMode(examPackage?.academicMode || examPackage?.settings?.academicMode || ""),
    sessionId: sanitizeSessionId(sessionId || examPackage?.sessionId),
    updatedAt: sanitizeText(examPackage?.updatedAt || new Date().toISOString(), { maxLength: 50 }),
    receivedAt: new Date().toISOString()
  };
}

function sanitizeQuestionForStudent(question) {
  const type = String(question?.type || "multiple_choice").trim();
  if (!["multiple_choice", "true_false", "matching", "fill_blank"].includes(type)) return null;
  const clean = {
    question: sanitizeText(question.question || "", { maxLength: INPUT_LIMITS.question, multiline: true }),
    type,
    difficulty: sanitizeDifficulty(question.difficulty),
    hint: sanitizeText(question.hint || "", { maxLength: INPUT_LIMITS.shortText, multiline: true }),
    area: sanitizeText(question.area || "", { maxLength: 120 }),
    competency: sanitizeText(question.competency || "", { maxLength: 240 }),
    module: sanitizeText(question.module || "", { maxLength: 160 })
  };
  if (type === "matching") {
    clean.pairs = (question.pairs || []).map((pair) => ({ left: sanitizeText(pair.left || "", { maxLength: 300 }) })).filter((pair) => pair.left);
    clean.matchOptions = Array.isArray(question.matchOptions) ? question.matchOptions.map(sanitizeOptionText).filter(Boolean) : [];
    return clean;
  }
  if (type === "fill_blank") {
    return clean;
  }
  if (type === "open_response") {
    return clean;
  }
  clean.options = Array.isArray(question.options) ? question.options.map(sanitizeOptionForStudent).filter(Boolean) : [];
  return clean;
}

function sanitizeOptionForStudent(option) {
  return sanitizeOptionText(option).slice(0, 500);
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
    academicMode: "institutional",
    settings: stripSensitiveSettings(sanitizeSettingsForStorage(examPackage.settings || {})),
    allowedAccess: sanitizeAccessListForStorage(examPackage.allowedAccess || []),
    questionBank: (examPackage.questionBank || []).map(sanitizeQuestionForStudent).filter((question) => question?.question)
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
    if (!bytes || bytes > MAX_AI_FILE_BYTES || totalBytes + bytes > MAX_AI_FILE_BYTES) {
      return;
    }
    cleanFiles.push({
      name: String(file?.name || "fuente").replace(/[^\w.\- ()áéíóúüñÁÉÍÓÚÜÑ]/g, "").slice(0, 160),
      mimeType,
      data: data.replace(/\s+/g, ""),
      bytes
    });
    totalBytes += bytes;
  });
  return cleanFiles;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function geminiApiUrl(pathPart, upload = false) {
  const base = upload ? "https://generativelanguage.googleapis.com/upload/v1beta" : "https://generativelanguage.googleapis.com/v1beta";
  return `${base}/${String(pathPart || "").replace(/^\/+/, "")}?key=${encodeURIComponent(process.env.GEMINI_API_KEY || "")}`;
}

async function uploadGeminiFile(file) {
  const buffer = Buffer.from(file.data, "base64");
  const startResponse = await fetch(geminiApiUrl("files", true), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Goog-Upload-Protocol": "resumable",
      "X-Goog-Upload-Command": "start",
      "X-Goog-Upload-Header-Content-Length": String(buffer.length),
      "X-Goog-Upload-Header-Content-Type": file.mimeType
    },
    body: JSON.stringify({ file: { displayName: file.name || "fuente" } })
  });
  if (!startResponse.ok) {
    const err = await startResponse.json().catch(() => ({}));
    throw new Error(err?.error?.message || `Gemini no inicio la carga de ${file.name}`);
  }
  const uploadUrl = startResponse.headers.get("x-goog-upload-url");
  if (!uploadUrl) {
    throw new Error(`Gemini no entrego URL de carga para ${file.name}`);
  }

  const uploadResponse = await fetch(uploadUrl, {
    method: "POST",
    headers: {
      "Content-Length": String(buffer.length),
      "X-Goog-Upload-Offset": "0",
      "X-Goog-Upload-Command": "upload, finalize"
    },
    body: buffer
  });
  const uploadData = await uploadResponse.json().catch(() => ({}));
  if (!uploadResponse.ok || !uploadData?.file?.uri) {
    throw new Error(uploadData?.error?.message || `Gemini no recibio el archivo ${file.name}`);
  }
  return waitForGeminiFileReady(uploadData.file);
}

async function waitForGeminiFileReady(file) {
  let current = file;
  for (let attempt = 0; attempt < 12; attempt += 1) {
    const state = String(current?.state || "").toUpperCase();
    if (!state || state === "ACTIVE") {
      return current;
    }
    if (state === "FAILED") {
      throw new Error(`Gemini no pudo procesar ${current.displayName || current.name || "el archivo"}`);
    }
    await sleep(1000);
    const response = await fetch(geminiApiUrl(current.name || ""));
    current = response.ok ? await response.json().catch(() => current) : current;
  }
  return current;
}

async function deleteGeminiFile(file) {
  if (!file?.name) return;
  try {
    await fetch(geminiApiUrl(file.name), { method: "DELETE" });
  } catch {
    // Best-effort cleanup only.
  }
}

async function buildGeminiRequestParts(prompt, files) {
  const sourceFiles = Array.isArray(files) ? files : [];
  const totalBytes = sourceFiles.reduce((sum, file) => sum + (Number(file.bytes) || 0), 0);
  if (!sourceFiles.length || totalBytes <= GEMINI_INLINE_TOTAL_LIMIT) {
    return {
      uploadedFiles: [],
      parts: [
        { text: prompt },
        ...sourceFiles.flatMap((file) => [
          { text: `Fuente adjunta: ${file.name}` },
          { inlineData: { mimeType: file.mimeType, data: file.data } }
        ])
      ]
    };
  }

  const uploadedFiles = [];
  for (const file of sourceFiles) {
    uploadedFiles.push(await uploadGeminiFile(file));
  }
  return {
    uploadedFiles,
    parts: [
      { text: prompt },
      ...uploadedFiles.flatMap((file, index) => [
        { text: `Fuente adjunta: ${sourceFiles[index]?.name || file.displayName || file.name}` },
        { fileData: { mimeType: file.mimeType || sourceFiles[index]?.mimeType, fileUri: file.uri } }
      ])
    ]
  };
}

function normalizeTeacherRecord(teacher) {
  const name = sanitizeName(teacher?.name || "");
  const doc = normalizeDocument(teacher?.doc);
  const token = sanitizeToken(teacher?.token || "", 64);
  const tenantId = normalizeTenantId(teacher?.tenantId || `doc-${doc || token}`);
  if (!name || doc.length < 5 || token.length < 10) return null;
  return { name, doc, token, tenantId, academicModes: normalizeAcademicModes(teacher?.academicModes), active: teacher?.active !== false };
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
  return { name: teacher.name, doc: teacher.doc, tenantId: teacher.tenantId, academicModes: normalizeAcademicModes(teacher.academicModes), adminId, active: teacher.active };
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
wss.on("connection", async (ws, req) => {
  try {
    await storeReady;
    const url = new URL(req.url, "http://localhost");
    const sessionId = sanitizeSessionId(url.searchParams.get("sessionId"));
    const tenantId = normalizeTenantId(url.searchParams.get("tenantId"));
    const role = url.searchParams.get("role");
    const secret = url.searchParams.get("secret") || url.searchParams.get("adminSecret");
    const teacherToken = sanitizeToken(url.searchParams.get("teacherToken"), 64);

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
  const token = sanitizeToken(req.params.token || "", 64);
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
  const sessionId = sanitizeSessionId(req.body?.sessionId);
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
  const sessionId = sanitizeSessionId(req.body?.sessionId);
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
  const sessionId = sanitizeSessionId(req.params.sessionId);
  const session = readSession(tenantId, sessionId);
  if (!session) return res.json({ results: [], closures: [] });
  return res.json({ tenantId, sessionId, results: session.results, closures: session.closures });
});

// GET /api/attempt-status/:sessionId/:doc
app.get("/api/attempt-status/:sessionId/:doc", (req, res) => {
  const tenantId = getTenantIdFromRequest(req);
  const doc = normalizeDocument(req.params.doc);
  const sessionId = sanitizeSessionId(req.params.sessionId);
  const session = readSession(tenantId, sessionId);
  const entry = findAttemptByDoc(session, doc);
  return res.json({
    ok: true,
    tenantId,
    sessionId,
    blocked: Boolean(entry),
    entry: entry ? { doc: entry.doc, name: entry.name, closureCode: entry.closureCode, closureReason: entry.closureReason } : null
  });
});

// DELETE /api/results/:sessionId  — admin clears results (requires admin secret)
app.delete("/api/results/:sessionId", (req, res) => {
  const tenantId = getTenantIdFromRequest(req);
  if (!requireTenantWriteAccess(req, res, tenantId)) return;
  const sessionId = sanitizeSessionId(req.params.sessionId);
  const session = readSession(tenantId, sessionId);
  if (session) {
    session.results = [];
    session.closures = [];
    schedulePersist();
    broadcast(tenantId, sessionId, { type: "cleared" });
  }
  return res.json({ ok: true, tenantId, sessionId });
});

// POST /api/exam/:sessionId  — teacher publishes the active exam package
app.post("/api/exam/:sessionId", (req, res) => {
  if (!checkRateLimit(req, "exam_write")) {
    return res.status(429).json({ error: "Demasiadas solicitudes. Intenta en un minuto." });
  }
  const sessionId = sanitizeSessionId(req.params.sessionId);
  const examPackage = req.body?.package || req.body?.examPackage || req.body;
  const tenantId = getTenantIdFromRequest(req, examPackage?.tenantId);
  const academicMode = sanitizeAcademicMode(examPackage?.academicMode || examPackage?.settings?.academicMode || req.body?.academicMode || "");
  if (!requireTenantWriteAccess(req, res, tenantId, academicMode)) return;

  if (!sessionId || !examPackage?.schema || !Array.isArray(examPackage.questionBank) || !examPackage.questionBank.length) {
    return res.status(400).json({ error: "Paquete de examen inválido o vacío" });
  }
  if (examPackage.questionBank.length > MAX_EXAM_PACKAGE_QUESTIONS) {
    return res.status(400).json({ error: `Máximo ${MAX_EXAM_PACKAGE_QUESTIONS} preguntas por paquete` });
  }

  const safePackage = sanitizeExamPackageForStorage(examPackage, tenantId, sessionId);
  if (!safePackage.questionBank.length) {
    return res.status(400).json({ error: "El paquete no contiene preguntas validas despues de la sanitizacion" });
  }

  const session = getSession(tenantId, sessionId);
  session.examPackage = safePackage;
  schedulePersist();
  broadcast(tenantId, sessionId, { type: "exam-updated", updatedAt: session.examPackage.receivedAt, questionCount: session.examPackage.questionBank.length });
  return res.json({ ok: true, tenantId, sessionId, questionCount: session.examPackage.questionBank.length, updatedAt: session.examPackage.receivedAt });
});

// GET /api/exam/:sessionId  — student downloads the active exam package
app.get("/api/exam/:sessionId", (req, res) => {
  const tenantId = getTenantIdFromRequest(req);
  const sessionId = sanitizeSessionId(req.params.sessionId);
  const session = readSession(tenantId, sessionId);
  if (!session?.examPackage) return res.status(404).json({ error: "No hay examen publicado para esta sesión" });
  return res.json({ ok: true, tenantId, sessionId, package: sanitizeExamPackageForStudent(session.examPackage) });
});

// ─── YouTube Transcript Proxy ─────────────────────────────────────────────────
app.post("/api/ai/generate", requireAiAccess, async (req, res) => {
  if (!checkRateLimit(req, "default")) {
    return res.status(429).json({ error: "Demasiadas solicitudes." });
  }
  const provider = sanitizeText(req.body?.provider || "", { maxLength: 20 }).toLowerCase();
  const prompt = sanitizeText(req.body?.prompt || "", { maxLength: INPUT_LIMITS.prompt, multiline: true });
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
      const { parts, uploadedFiles } = await buildGeminiRequestParts(prompt, inlineFiles);
      let lastStatus = 502;
      let lastError = "Gemini no pudo completar la generacion";
      try {
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
      } finally {
        await Promise.allSettled((uploadedFiles || []).map(deleteGeminiFile));
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
  res.json({
    status: "ok",
    app: "EVALUAPRO-UTCH Server",
    storage: storageMode,
    tenants: tenants.size,
    sessions: Object.keys(sessions).length,
    teacherRegistries: Object.keys(teacherRegistries).length
  });
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
