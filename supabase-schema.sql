const express = require("express");
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const WebSocket = require("ws");
const cors = require("cors");
const { Pool } = require("pg");

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server, maxPayload: 64 * 1024 });

// ─── Security & Configuration ─────────────────────────────────────────────────
const IS_PRODUCTION = process.env.NODE_ENV === "production";
const DEFAULT_ALLOWED_ORIGINS = [
  "https://evaluapro-utch.netlify.app",
  ...(!IS_PRODUCTION ? [
    "http://localhost:4327", "http://localhost:4331", "http://localhost:4333",
    "http://127.0.0.1:4327", "http://127.0.0.1:4331", "http://127.0.0.1:4333"
  ] : [])
];
const DEV_OPEN_ACCESS = !IS_PRODUCTION && process.env.DEV_OPEN_ACCESS === "true";
const ALLOW_FILE_ORIGIN = !IS_PRODUCTION && process.env.ALLOW_FILE_ORIGIN === "true";
const ALLOWED_ORIGINS = [
  ...DEFAULT_ALLOWED_ORIGINS,
  ...(process.env.ALLOWED_ORIGINS || "").split(",")
]
  .map(normalizeCorsOrigin)
  .filter(Boolean)
  .filter((origin, index, list) => list.indexOf(origin) === index);

const ADMIN_SECRET = process.env.ADMIN_SECRET || "";
const TOKEN_HASH_SECRET = process.env.TOKEN_HASH_SECRET || process.env.ATTEMPT_CAPABILITY_SECRET || ADMIN_SECRET || (!IS_PRODUCTION ? "evapro-local-token-hash-secret-change-in-production" : "");
const DATA_FILE = process.env.EVAPRO_DATA_FILE || path.join(__dirname, "data", "evapro-store.json");
const DATABASE_URL = process.env.DATABASE_URL || process.env.SUPABASE_DATABASE_URL || "";
const TEST_FAILPOINT_SECRET = process.env.NODE_ENV === "test" ? String(process.env.TEST_FAILPOINT_SECRET || "") : "";
if (IS_PRODUCTION) {
  const missing = ["DATABASE_URL", "TOKEN_HASH_SECRET", "ADMIN_SECRET", "ALLOWED_ORIGINS"]
    .filter((name) => !String(process.env[name] || "").trim());
  if (missing.length) throw new Error(`Configuracion de produccion incompleta: ${missing.join(", ")}`);
}
const JSON_BODY_LIMIT = process.env.JSON_BODY_LIMIT || "2mb";
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
  const ip = req.ip || req.socket.remoteAddress || "unknown";
  const tenant = normalizeTenantId(req.headers["x-tenant-id"] || req.query?.tenantId || req.body?.tenantId || req.body?.entry?.tenantId);
  const doc = normalizeDocument(req.params?.doc || req.body?.entry?.doc).slice(-12);
  return `${action}::${ip}::${tenant}::${doc}`;
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
const rateCleanupTimer = setInterval(() => {
  const now = Date.now();
  for (const [key, record] of rateMap.entries()) {
    if (now > record.resetAt + RATE_WINDOW_MS) rateMap.delete(key);
  }
}, 5 * 60_000);
rateCleanupTimer.unref();

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
  allowedHeaders: ["Content-Type", "Accept", "Authorization", "x-tenant-id", "x-attempt-capability", "x-csrf-token"],
  credentials: true,
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
  if (req.path.startsWith("/api/")) {
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
    res.setHeader("Pragma", "no-cache");
  }
  next();
});

app.set("trust proxy", 1);
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
  if (req.authSession?.role === "admin") return next();
  if (!ADMIN_SECRET && DEV_OPEN_ACCESS) return next();
  if (!ADMIN_SECRET) return res.status(503).json({ error: "Servidor sin autenticación administrativa configurada" });
  return res.status(401).json({ error: "Inicia sesion como administrador" });
}

function isValidAdminSecret(value) {
  return Boolean(ADMIN_SECRET && value && String(value) === ADMIN_SECRET);
}

function isValidAdminRequest(req) {
  return req.authSession?.role === "admin";
}

function findTeacherByToken(token) {
  const clean = sanitizeToken(token || "", 64);
  if (!clean) return null;
  const tokenHash = hashToken(clean);
  for (const registry of Object.values(teacherRegistries)) {
    const teacher = registry?.teachers?.find((item) => item.tokenHash === tokenHash && item.active !== false);
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
  if (req.authSession?.role === "teacher" && normalizeTenantId(req.authSession.tenantId) === normalizeTenantId(tenantId)) return true;
  return false;
}

function requireTenantWriteAccess(req, res, tenantId, academicMode = "") {
  if (isValidTenantWriter(req, tenantId, academicMode)) return true;
  if (DEV_OPEN_ACCESS && !ADMIN_SECRET && !tenantHasRegisteredTeacher(tenantId)) return true;
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
  if (DEV_OPEN_ACCESS && !ADMIN_SECRET && !tenantHasRegisteredTeacher(tenantId)) {
    req.tenantId = tenantId;
    return next();
  }
  return res.status(401).json({ error: "No autorizado para generar con IA en este espacio de trabajo" });
}

// ─── In-memory store ──────────────────────────────────────────────────────────
const sessions = {};
const teacherRegistries = {};
const capabilities = {};
const authSessions = {};
const wsTickets = new Map();
const DEFAULT_TENANT_ID = "default";
let persistTimer = null;
let dbPool = null;
let storageMode = DATABASE_URL ? "postgres" : "json";
const storeReady = loadStore();

function parseCookies(req) {
  return Object.fromEntries(String(req.headers.cookie || "").split(";").map((part) => part.trim().split("=")).filter(([key]) => key).map(([key, value]) => [key, decodeURIComponent(value || "")]));
}

app.use(async (req, res, next) => {
  const cookies = parseCookies(req);
  const raw = cookies.evapro_session || "";
  const sessionHash = raw ? hashToken(raw) : "";
  let auth = sessionHash ? authSessions[sessionHash] : null;
  if (DATABASE_URL && sessionHash) {
    try {
      const row = (await getDatabasePool().query(`select session_hash, csrf_hash, role, tenant_id,
        extract(epoch from expires_at) * 1000 as expires_at, revoked_at, admin_id, subject_hash
        from evapro_auth_sessions where session_hash=$1 and expires_at>now() and revoked_at is null`, [sessionHash])).rows[0];
      auth = row ? { role: row.role, tenantId: row.tenant_id, csrfHash: row.csrf_hash,
        expiresAt: Number(row.expires_at), revokedAt: null, adminId: row.admin_id, subjectHash: row.subject_hash } : null;
      if (auth?.role === "teacher" && !(await teacherSubjectIsActive(auth))) auth = null;
    } catch (error) { return next(error); }
  }
  if (auth && !auth.revokedAt && auth.expiresAt > Date.now()) req.authSession = auth;
  if (req.authSession && !["GET", "HEAD", "OPTIONS"].includes(req.method)) {
    const csrf = String(req.headers["x-csrf-token"] || "");
    if (!csrf || hashToken(csrf) !== req.authSession.csrfHash) return res.status(403).json({ error: "CSRF inválido" });
  }
  next();
});

async function issueAuthSession(res, role, tenantId, subject = {}) {
  const raw = crypto.randomBytes(32).toString("base64url");
  const csrf = crypto.randomBytes(32).toString("base64url");
  const expiresAt = Date.now() + 8 * 60 * 60_000;
  const sessionHash = hashToken(raw);
  authSessions[sessionHash] = { role, tenantId: normalizeTenantId(tenantId), csrfHash: hashToken(csrf), expiresAt, revokedAt: null,
    adminId: normalizeTenantId(subject.adminId), subjectHash: subject.subjectHash || null };
  await persistAuthSession(sessionHash, authSessions[sessionHash]);
  const secure = IS_PRODUCTION ? "; Secure; SameSite=None" : "; SameSite=Lax";
  res.setHeader("Set-Cookie", `evapro_session=${raw}; Path=/; HttpOnly${secure}; Max-Age=28800`);
  return { csrfToken: csrf, expiresAt };
}

app.post("/api/auth/admin", async (req, res, next) => {
  if (!isValidAdminSecret(req.body?.secret)) return res.status(401).json({ error: "Credenciales inválidas" });
  try { return res.json({ ok: true, ...(await issueAuthSession(res, "admin", req.body?.tenantId)) }); } catch (error) { return next(error); }
});

app.get("/api/auth/me", (req, res) => {
  if (!req.authSession) return res.status(401).json({ authenticated: false });
  return res.json({ authenticated: true, role: req.authSession.role, tenantId: req.authSession.tenantId,
    adminId: req.authSession.adminId || undefined, expiresAt: req.authSession.expiresAt });
});

app.post("/api/auth/logout", async (req, res, next) => {
  const raw = parseCookies(req).evapro_session;
  if (raw && authSessions[hashToken(raw)]) authSessions[hashToken(raw)].revokedAt = Date.now();
  try { if (raw) await revokeAuthSession(hashToken(raw)); } catch (error) { return next(error); }
  res.setHeader("Set-Cookie", `evapro_session=; Path=/; HttpOnly; Max-Age=0${IS_PRODUCTION ? "; Secure; SameSite=None" : "; SameSite=Lax"}`);
  return res.json({ ok: true });
});

async function persistAuthSession(sessionHash, auth) {
  if (!DATABASE_URL) return persistJsonStore();
  await getDatabasePool().query(`insert into evapro_auth_sessions
    (session_hash,csrf_hash,role,tenant_id,expires_at,revoked_at,admin_id,subject_hash)
    values ($1,$2,$3,$4,to_timestamp($5/1000.0),null,$6,$7)
    on conflict (session_hash) do update set expires_at=excluded.expires_at, revoked_at=null,
      admin_id=excluded.admin_id, subject_hash=excluded.subject_hash`,
    [sessionHash, auth.csrfHash, auth.role, auth.tenantId, auth.expiresAt, auth.adminId || null, auth.subjectHash || null]);
}

async function teacherSubjectIsActive(auth) {
  if (!auth?.adminId || !auth?.subjectHash) return false;
  const row = (await getDatabasePool().query("select teachers from evapro_teacher_registries where admin_id=$1", [auth.adminId])).rows[0];
  return normalizeTeacherList(row?.teachers || []).some((teacher) => teacher.active !== false &&
    teacher.tokenHash === auth.subjectHash && normalizeTenantId(teacher.tenantId) === normalizeTenantId(auth.tenantId));
}

async function revokeAuthSession(sessionHash) {
  if (!DATABASE_URL) return persistJsonStore();
  await getDatabasePool().query("update evapro_auth_sessions set revoked_at=now() where session_hash=$1", [sessionHash]);
}

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
    const sslDisabled = /(?:[?&])sslmode=disable(?:&|$)/i.test(DATABASE_URL);
    dbPool = new Pool({
      connectionString: DATABASE_URL,
      ssl: sslDisabled ? false : { rejectUnauthorized: false },
      max: Number(process.env.DATABASE_POOL_MAX || 5),
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 15_000
    });
  }
  return dbPool;
}

async function runDatabaseMigrations() {
  const pool = getDatabasePool();
  if (!pool) return false;
  const client = await pool.connect();
  try {
    await client.query("select pg_advisory_lock($1)", [0x45564150]);
    await client.query(`create table if not exists evapro_schema_migrations
      (version integer primary key, name text not null, applied_at timestamptz not null default now())`);
    const applied = new Set((await client.query("select version from evapro_schema_migrations")).rows.map((row) => Number(row.version)));
    const files = fs.readdirSync(path.join(__dirname, "migrations")).filter((name) => /^\d{3}_.+\.sql$/.test(name)).sort();
    for (const name of files) {
      const version = Number(name.slice(0, 3));
      if (applied.has(version)) continue;
      await client.query("begin");
      try {
        await client.query(fs.readFileSync(path.join(__dirname, "migrations", name), "utf8"));
        await client.query("insert into evapro_schema_migrations(version,name) values ($1,$2)", [version, name]);
        await client.query("commit");
      } catch (error) { await client.query("rollback"); throw error; }
    }
  } finally {
    await client.query("select pg_advisory_unlock($1)", [0x45564150]).catch(() => {});
    client.release();
  }
  return true;
}

async function loadPostgresStore() {
  await runDatabaseMigrations();
  const pool = getDatabasePool();
  const [sessionRows, teacherRows, capabilityRows, authRows] = await Promise.all([
    pool.query("select tenant_id, session_id, results, closures, exam_package, created_at, last_activity from evapro_sessions"),
    pool.query("select admin_id, teachers, updated_at from evapro_teacher_registries"),
    pool.query("select token_hash, tenant_id, session_id, document_hash, exam_version, expires_at, revoked_at from evapro_capabilities where expires_at > now()"),
    pool.query("select session_hash, csrf_hash, role, tenant_id, expires_at, revoked_at, admin_id, subject_hash from evapro_auth_sessions where expires_at > now()")
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
  capabilityRows.rows.forEach((row) => {
    capabilities[row.token_hash] = { tid: row.tenant_id, sid: row.session_id, subHash: row.document_hash,
      ver: row.exam_version, exp: new Date(row.expires_at).getTime(), revokedAt: row.revoked_at ? new Date(row.revoked_at).getTime() : null };
  });
  authRows.rows.forEach((row) => {
    authSessions[row.session_hash] = { role: row.role, tenantId: row.tenant_id, csrfHash: row.csrf_hash,
      expiresAt: new Date(row.expires_at).getTime(), revokedAt: row.revoked_at ? new Date(row.revoked_at).getTime() : null,
      adminId: row.admin_id, subjectHash: row.subject_hash };
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
      if (IS_PRODUCTION) throw new Error(`Postgres obligatorio no disponible: ${error.message}`);
      storageMode = "json";
      console.error("No se pudo conectar a Postgres; solo desarrollo usa respaldo JSON:", error.message);
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
    Object.entries(data.capabilities || {}).forEach(([tokenHash, grant]) => {
      if (/^[a-f0-9]{64}$/.test(tokenHash) && Number(grant?.exp) > Date.now() && !grant?.revokedAt) capabilities[tokenHash] = grant;
    });
    Object.entries(data.authSessions || {}).forEach(([sessionHash, auth]) => {
      if (/^[a-f0-9]{64}$/.test(sessionHash) && Number(auth?.expiresAt) > Date.now() && !auth?.revokedAt) authSessions[sessionHash] = auth;
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
    teacherRegistries,
    capabilities,
    authSessions
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
  const pool = getDatabasePool();
  const client = await pool.connect();
  try {
    await client.query("begin");
    for (const session of Object.values(sessions)) {
      await client.query(
        `insert into evapro_sessions
          (tenant_id, session_id, results, closures, exam_package, created_at, last_activity)
         values ($1, $2, $3::jsonb, $4::jsonb, $5::jsonb, $6, $7)
         on conflict (tenant_id, session_id) do update set
           results = excluded.results, closures = excluded.closures,
           exam_package = excluded.exam_package, last_activity = excluded.last_activity`,
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
      for (const attempt of [...(session.results || []), ...(session.closures || [])]) {
        const documentHash = crypto.createHmac("sha256", TOKEN_HASH_SECRET).update(normalizeDocument(attempt.doc)).digest("hex");
        const terminalType = attempt.closureKey ? "closure" : "submit";
        await client.query(
          `insert into evapro_attempts (tenant_id, session_id, document_hash, exam_version, terminal_type, receipt_id, payload, received_at)
           values ($1,$2,$3,$4,$5,$6,$7::jsonb,$8) on conflict (tenant_id, session_id, document_hash) do nothing`,
          [session.tenantId, session.sessionId, documentHash, examVersion(session), terminalType, attempt.receiptId || crypto.randomUUID(), JSON.stringify(attempt), attempt.receivedAt || attempt.date || new Date().toISOString()]
        );
      }
    }

    await client.query("delete from evapro_capabilities where expires_at <= now()");
    for (const [tokenHash, grant] of Object.entries(capabilities)) {
      await client.query(`insert into evapro_capabilities
        (token_hash,tenant_id,session_id,document_hash,exam_version,expires_at,revoked_at)
        values ($1,$2,$3,$4,$5,to_timestamp($6 / 1000.0),to_timestamp($7 / 1000.0))
        on conflict (token_hash) do update set expires_at=excluded.expires_at, revoked_at=excluded.revoked_at`,
        [tokenHash, grant.tid, grant.sid, grant.subHash, grant.ver, grant.exp, grant.revokedAt]);
    }

    for (const registry of Object.values(teacherRegistries)) {
      await client.query(
        `insert into evapro_teacher_registries (admin_id, teachers, updated_at)
         values ($1, $2::jsonb, $3)
         on conflict (admin_id) do update set teachers = excluded.teachers, updated_at = excluded.updated_at`,
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
    const temporaryFile = `${DATA_FILE}.${process.pid}.tmp`;
    fs.writeFileSync(temporaryFile, JSON.stringify(serializeStore(), null, 2), { mode: 0o600 });
    fs.renameSync(temporaryFile, DATA_FILE);
  } catch (error) {
    console.error("No se pudo guardar EVAPRO_DATA_FILE:", error.message);
    throw error;
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
      console.error("No se pudo guardar en Supabase/Postgres:", error.message);
      throw error;
    }
  }
  persistJsonStore();
}

async function persistSessionAuthority(session, { clearAttempts = false } = {}) {
  if (!DATABASE_URL) return persistJsonStore();
  const client = await getDatabasePool().connect();
  try {
    await client.query("begin");
    await client.query(`insert into evapro_sessions (tenant_id,session_id,results,closures,exam_package,created_at,last_activity)
      values ($1,$2,$3::jsonb,$4::jsonb,$5::jsonb,$6,$7) on conflict (tenant_id,session_id) do update set
      results=excluded.results,closures=excluded.closures,exam_package=excluded.exam_package,last_activity=excluded.last_activity`,
      [session.tenantId, session.sessionId, JSON.stringify(session.results || []), JSON.stringify(session.closures || []),
        session.examPackage ? JSON.stringify(session.examPackage) : null, session.createdAt, Date.now()]);
    if (clearAttempts) await client.query("delete from evapro_attempts where tenant_id=$1 and session_id=$2", [session.tenantId, session.sessionId]);
    await client.query("commit");
  } catch (error) { await client.query("rollback").catch(() => {}); throw error; } finally { client.release(); }
}

async function persistTeacherRegistry(registry) {
  if (!DATABASE_URL) return persistJsonStore();
  await getDatabasePool().query(`insert into evapro_teacher_registries (admin_id,teachers,updated_at)
    values ($1,$2::jsonb,$3) on conflict (admin_id) do update set teachers=excluded.teachers,updated_at=excluded.updated_at`,
    [registry.adminId, JSON.stringify(registry.teachers), registry.updatedAt]);
}

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function examVersion(session) {
  const examPackage = session?.examPackage || null;
  const versionedPackage = examPackage && typeof examPackage === "object"
    ? Object.fromEntries(Object.entries(examPackage).filter(([key]) => key !== "receivedAt"))
    : examPackage;
  return crypto.createHash("sha256").update(stableJson(versionedPackage)).digest("hex").slice(0, 24);
}

function hashToken(token) {
  if (!TOKEN_HASH_SECRET) throw new Error("TOKEN_HASH_SECRET no configurado");
  return crypto.createHmac("sha256", TOKEN_HASH_SECRET).update(String(token)).digest("hex");
}

function timingSafeSecretMatch(candidate, expected) {
  const candidateHash = crypto.createHash("sha256").update(String(candidate || "")).digest();
  const expectedHash = crypto.createHash("sha256").update(String(expected || "")).digest();
  return Boolean(expected) && crypto.timingSafeEqual(candidateHash, expectedHash);
}

let failFinalizeAfterRevokeOnce = false;
if (process.env.NODE_ENV === "test") {
  app.post("/api/test/failpoint/finalize-after-revoke", (req, res) => {
    if (!timingSafeSecretMatch(req.headers["x-test-failpoint-secret"], TEST_FAILPOINT_SECRET)) {
      return res.status(401).json({ error: "No autorizado" });
    }
    failFinalizeAfterRevokeOnce = true;
    return res.json({ ok: true, armed: true });
  });
}

async function readCapability(req, { allowRevoked = false } = {}) {
  const bearer = String(req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  const token = String(req.headers["x-attempt-capability"] || bearer || "");
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) return null;
  const tokenHash = hashToken(token);
  let grant = capabilities[tokenHash];
  if (DATABASE_URL) {
    const result = await getDatabasePool().query(`select tenant_id,session_id,document_hash,exam_version,extract(epoch from expires_at)*1000 as exp,revoked_at
      from evapro_capabilities where token_hash=$1 and expires_at>now() ${allowRevoked ? "" : "and revoked_at is null"}`, [tokenHash]);
    const row = result.rows[0];
    grant = row ? { tid: row.tenant_id, sid: row.session_id, subHash: row.document_hash, ver: row.exam_version, exp: Number(row.exp), revokedAt: row.revoked_at ? new Date(row.revoked_at).getTime() : null } : null;
  }
  if (!grant || (!allowRevoked && grant.revokedAt) || Number(grant.exp) <= Date.now()) return null;
  grant.tokenHash = tokenHash;
  return grant;
}

async function requireAttemptCapability(req, res, options) {
  const claims = await readCapability(req, options);
  if (!claims) { res.status(401).json({ error: "Capacidad de intento inválida o vencida" }); return null; }
  let session = readSession(claims.tid, claims.sid);
  if (DATABASE_URL) {
    const row = (await getDatabasePool().query("select exam_package,created_at,last_activity from evapro_sessions where tenant_id=$1 and session_id=$2", [claims.tid, claims.sid])).rows[0];
    session = row ? createSessionRecord(claims.tid, claims.sid, { examPackage: row.exam_package, createdAt: row.created_at, lastActivity: row.last_activity }) : null;
  }
  if (!session?.examPackage || claims.ver !== examVersion(session)) {
    res.status(409).json({ error: "La versión del examen cambió; solicita un nuevo acceso" }); return null;
  }
  const roster = Array.isArray(session.examPackage.allowedAccess) ? session.examPackage.allowedAccess : [];
  const matched = roster.find((student) => {
    const candidate = normalizeDocument(student?.doc);
    const digest = crypto.createHmac("sha256", TOKEN_HASH_SECRET).update(candidate).digest("hex");
    return candidate && digest === claims.subHash;
  });
  if (!matched) { res.status(401).json({ error: "Capacidad sin identidad válida" }); return null; }
  claims.sub = normalizeDocument(matched.doc);
  return { claims, session };
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
  const allowed = new Set(["multiple_choice", "true_false", "matching", "fill_blank", "open_response"]);
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
  return ["multiple_choice", "true_false", "matching", "fill_blank", "open_response"].includes(clean) ? clean : "multiple_choice";
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
  if (!["multiple_choice", "true_false", "matching", "fill_blank", "open_response"].includes(type)) return null;
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
  if (!["multiple_choice", "true_false", "matching", "fill_blank", "open_response"].includes(type)) return null;
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
    // The roster is authorization data and must never be shipped to students.
    allowedAccess: [],
    questionBank: (examPackage.questionBank || []).map(sanitizeQuestionForStudent).filter((question) => question?.question)
  };
}

function findAttemptByDoc(session, doc) {
  const normalizedDoc = normalizeDocument(doc);
  if (!session || !normalizedDoc) return null;
  return [...session.results, ...session.closures]
    .find((entry) => normalizeDocument(entry?.doc) === normalizedDoc) || null;
}

function publicSubmissionReceipt(entry) {
  if (!entry) return null;
  return {
    doc: entry.doc,
    receivedAt: entry.receivedAt || entry.date,
    score: entry.score,
    total: entry.total,
    exerciseTotal: entry.exerciseTotal,
    pendingReview: entry.pendingReview,
    percent: entry.percent,
    grade: entry.grade,
    verifiedByServer: entry.verifiedByServer === true,
    receiptId: entry.receiptId || "",
    terminalType: entry.terminalType || "submit"
  };
}

function publicClosureReceipt(entry) {
  if (!entry) return null;
  return { receivedAt: entry.receivedAt || entry.date, receiptId: entry.receiptId || "", terminalType: "closure", closureKey: entry.closureKey, closureCode: entry.closureCode, closureReason: entry.closureReason, verifiedByServer: entry.verifiedByServer === true };
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
  const tokenHash = /^[a-f0-9]{64}$/.test(String(teacher?.tokenHash || "")) ? teacher.tokenHash : (token.length >= 10 ? hashToken(token) : "");
  const tenantId = normalizeTenantId(teacher?.tenantId || `doc-${doc || tokenHash.slice(0, 12)}`);
  if (!name || doc.length < 5 || !tokenHash) return null;
  return { name, doc, tokenHash, tenantId, academicModes: normalizeAcademicModes(teacher?.academicModes), active: teacher?.active !== false };
}

function normalizeTeacherList(value) {
  const seen = new Set();
  return (Array.isArray(value) ? value : [])
    .slice(0, 500)
    .map(normalizeTeacherRecord)
    .filter(Boolean)
    .filter((teacher) => {
      const key = teacher.tokenHash || teacher.doc;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
}

function publicTeacherRecord(teacher, adminId) {
  return { name: teacher.name, doc: teacher.doc, tenantId: teacher.tenantId, academicModes: normalizeAcademicModes(teacher.academicModes), adminId, active: teacher.active };
}

// Cleanup stale sessions every hour
const sessionCleanupTimer = setInterval(() => {
  const cutoff = Date.now() - SESSION_TTL_MS;
  for (const key of Object.keys(sessions)) {
    if ((sessions[key].lastActivity || 0) < cutoff) {
      sessions[key].adminClients.forEach((ws) => { try { ws.close(); } catch {} });
      delete sessions[key];
      schedulePersist();
    }
  }
}, 60 * 60_000);
sessionCleanupTimer.unref();

// ─── WebSocket ────────────────────────────────────────────────────────────────
wss.on("connection", async (ws, req) => {
  try {
    if (!isAllowedCorsOrigin(req.headers.origin)) { ws.close(1008, "Origin no permitido"); return; }
    await storeReady;
    const url = new URL(req.url, "http://localhost");
    const sessionId = sanitizeSessionId(url.searchParams.get("sessionId"));
    const tenantId = normalizeTenantId(url.searchParams.get("tenantId"));
    const role = url.searchParams.get("role");
    const ticket = String(url.searchParams.get("ticket") || "");

    if (!sessionId) { ws.close(1008, "sessionId requerido"); return; }

    const session = getSession(tenantId, sessionId);

    if (role === "admin") {
      const grant = wsTickets.get(ticket);
      wsTickets.delete(ticket);
      const allowed = Boolean(grant && grant.expiresAt > Date.now() && grant.tenantId === tenantId && grant.sessionId === sessionId);
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

app.post("/api/ws-ticket", (req, res) => {
  const tenantId = getTenantIdFromRequest(req);
  const sessionId = sanitizeSessionId(req.body?.sessionId);
  if (!sessionId) return res.status(400).json({ error: "sessionId requerido" });
  if (!requireTenantWriteAccess(req, res, tenantId)) return;
  const ticket = crypto.randomBytes(32).toString("base64url");
  wsTickets.set(ticket, { tenantId, sessionId, expiresAt: Date.now() + 30_000 });
  return res.json({ ticket, expiresIn: 30 });
});

// ─── REST API ─────────────────────────────────────────────────────────────────

// POST /api/teachers/:adminId  — admin publishes authorized teachers
app.post("/api/teachers/:adminId", requireAdminSecret, async (req, res, next) => {
  if (!checkRateLimit(req, "teachers_write")) {
    return res.status(429).json({ error: "Demasiadas solicitudes. Intenta en un minuto." });
  }
  const adminId = normalizeTenantId(req.params.adminId);
  if (!adminId) return res.status(400).json({ error: "adminId inválido" });

  const teachers = normalizeTeacherList(req.body?.teachers);
  const previous = teacherRegistries[adminId];
  teacherRegistries[adminId] = { adminId, teachers, updatedAt: new Date().toISOString() };
  try { await persistTeacherRegistry(teacherRegistries[adminId]); } catch (error) { if (previous) teacherRegistries[adminId] = previous; else delete teacherRegistries[adminId]; return next(error); }
  return res.json({ ok: true, adminId, teacherCount: teachers.length, updatedAt: teacherRegistries[adminId].updatedAt });
});

// GET /api/teacher-access/:adminId/:token  — validates teacher access
app.get("/api/teacher-access/:adminId/:token", (_req, res) => {
  return res.status(410).json({ ok: false, error: "Credenciales en URL retiradas" });
});

app.post("/api/teacher-access/:adminId", async (req, res, next) => {
  const adminId = normalizeTenantId(req.params.adminId);
  const token = sanitizeToken(req.body?.token || "", 64);
  let registry = teacherRegistries[adminId];
  if (DATABASE_URL) {
    try {
      const row = (await getDatabasePool().query("select teachers,updated_at from evapro_teacher_registries where admin_id=$1", [adminId])).rows[0];
      registry = row ? { adminId, teachers: normalizeTeacherList(row.teachers || []), updatedAt: row.updated_at } : null;
      if (registry) teacherRegistries[adminId] = registry;
    } catch (error) { return next(error); }
  }
  const tokenHash = token ? hashToken(token) : "";
  const found = registry?.teachers?.find((item) => item.tokenHash === tokenHash && item.active !== false);
  const teacher = found ? { ...found, adminId } : null;
  if (!teacher || normalizeTenantId(teacher.adminId) !== adminId) return res.status(403).json({ ok: false, error: "Docente no autorizado o enlace vencido" });
  try {
    const auth = await issueAuthSession(res, "teacher", teacher.tenantId, { adminId, subjectHash: teacher.tokenHash });
    return res.json({ ok: true, adminId, teacher: publicTeacherRecord(teacher, adminId), updatedAt: registry?.updatedAt, ...auth });
  } catch (error) { return next(error); }
});

// POST /api/result  — student submits result
app.post("/api/attempt/capability", async (req, res, next) => {
  if (!checkRateLimit(req, "result")) return res.status(429).json({ error: "Demasiadas solicitudes" });
  const tenantId = getTenantIdFromRequest(req);
  const sessionId = sanitizeSessionId(req.body?.sessionId);
  const doc = normalizeDocument(req.body?.doc);
  let session = readSession(tenantId, sessionId);
  if (DATABASE_URL) {
    try {
      const row = (await getDatabasePool().query("select exam_package,created_at,last_activity from evapro_sessions where tenant_id=$1 and session_id=$2", [tenantId, sessionId])).rows[0];
      if (row) session = createSessionRecord(tenantId, sessionId, { examPackage: row.exam_package, createdAt: row.created_at, lastActivity: row.last_activity });
    } catch (error) { return next(error); }
  }
  if (!session?.examPackage || doc.length < 5) return res.status(404).json({ error: "Examen o estudiante no disponible" });
  if (!isAuthorizedStudent(session, { doc })) return res.status(403).json({ error: "Estudiante no autorizado" });
  let prior = findAttemptByDoc(session, doc);
  const documentHash = crypto.createHmac("sha256", TOKEN_HASH_SECRET).update(doc).digest("hex");
  if (DATABASE_URL) prior = (await getDatabasePool().query("select 1 from evapro_attempts where tenant_id=$1 and session_id=$2 and document_hash=$3", [tenantId, sessionId, documentHash])).rowCount > 0;
  if (prior) return res.status(409).json({ error: "El intento ya finalizó" });
  const expiresAt = Date.now() + Math.min(SESSION_TTL_MS, 4 * 60 * 60_000);
  const capability = crypto.randomBytes(32).toString("base64url");
  const tokenHash = hashToken(capability);
  capabilities[tokenHash] = { tid: tenantId, sid: sessionId,
    subHash: documentHash,
    ver: examVersion(session), exp: expiresAt, revokedAt: null };
  try {
    if (DATABASE_URL) await getDatabasePool().query(`insert into evapro_capabilities (token_hash,tenant_id,session_id,document_hash,exam_version,expires_at)
      values ($1,$2,$3,$4,$5,to_timestamp($6/1000.0))`, [tokenHash, tenantId, sessionId, documentHash, examVersion(session), expiresAt]);
    else persistJsonStore();
  } catch (error) { delete capabilities[tokenHash]; return next(error); }
  return res.status(201).json({ ok: true, capability, expiresAt, examVersion: examVersion(session) });
});

app.get("/api/attempt/exam", async (req, res) => {
  const grant = await requireAttemptCapability(req, res);
  if (!grant) return;
  return res.json({ ok: true, examVersion: grant.claims.ver, package: sanitizeExamPackageForStudent(grant.session.examPackage) });
});

app.post("/api/attempt/status", async (req, res) => {
  const grant = await requireAttemptCapability(req, res, { allowRevoked: true });
  if (!grant) return;
  let entry = findAttemptByDoc(grant.session, grant.claims.sub);
  if (DATABASE_URL) {
    const result = await getDatabasePool().query("select payload from evapro_attempts where tenant_id=$1 and session_id=$2 and document_hash=$3", [grant.claims.tid, grant.claims.sid, grant.claims.subHash]);
    entry = result.rows[0]?.payload || null;
  }
  return res.json({ ok: true, blocked: Boolean(entry), terminalType: entry?.terminalType || (entry?.closureKey ? "closure" : entry ? "submit" : null), receipt: entry ? (entry.closureKey ? publicClosureReceipt(entry) : publicSubmissionReceipt(entry)) : null });
});

let terminalMutation = Promise.resolve();
function serializeTerminalMutation(work) {
  const run = terminalMutation.then(work, work);
  terminalMutation = run.catch(() => {});
  return run;
}

async function finalizePostgresAttempt(grant, stored, terminalType) {
  const client = await getDatabasePool().connect();
  try {
    await client.query("begin");
    const inserted = await client.query(`insert into evapro_attempts
      (tenant_id,session_id,document_hash,exam_version,terminal_type,receipt_id,payload,received_at)
      values ($1,$2,$3,$4,$5,$6,$7::jsonb,$8)
      on conflict (tenant_id,session_id,document_hash) do nothing returning payload`,
      [grant.claims.tid, grant.claims.sid, grant.claims.subHash, grant.claims.ver, terminalType,
        stored.receiptId, JSON.stringify(stored), stored.receivedAt]);
    const canonical = inserted.rows[0]?.payload || (await client.query(
      "select payload from evapro_attempts where tenant_id=$1 and session_id=$2 and document_hash=$3",
      [grant.claims.tid, grant.claims.sid, grant.claims.subHash])).rows[0]?.payload;
    await client.query("update evapro_capabilities set revoked_at=now() where token_hash=$1", [grant.claims.tokenHash]);
    if (failFinalizeAfterRevokeOnce) {
      failFinalizeAfterRevokeOnce = false;
      throw new Error("Test failpoint: finalize after insert and revoke");
    }
    await client.query("commit");
    return { stored: canonical, duplicate: inserted.rowCount === 0 };
  } catch (error) {
    await client.query("rollback").catch(() => {});
    throw error;
  } finally { client.release(); }
}

async function findAttemptForGrant(grant) {
  if (!DATABASE_URL) return findAttemptByDoc(grant.session, grant.claims.sub);
  const result = await getDatabasePool().query("select payload from evapro_attempts where tenant_id=$1 and session_id=$2 and document_hash=$3", [grant.claims.tid, grant.claims.sid, grant.claims.subHash]);
  return result.rows[0]?.payload || null;
}

app.post("/api/attempt/submit", async (req, res, next) => {
  try {
    const grant = await requireAttemptCapability(req, res, { allowRevoked: true }); if (!grant) return;
    const response = await serializeTerminalMutation(async () => {
      const prior = await findAttemptForGrant(grant);
      if (prior) return { duplicate: true, blocked: true, receipt: prior.closureKey ? publicClosureReceipt(prior) : publicSubmissionReceipt(prior) };
      if (grant.claims.revokedAt) { const error = new Error("La capacidad ya fue consumida"); error.status = 401; throw error; }
      const entry = sanitizeEntry({ ...(req.body?.entry || {}), doc: grant.claims.sub });
      if (!entry?.answers?.length) { const error = new Error("El resultado no contiene respuestas verificables"); error.status = 400; throw error; }
      const stored = verifyResultEntry(grant.session, { ...entry, tenantId: grant.claims.tid, sessionId: grant.claims.sid, terminalType: "submit", receiptId: crypto.randomUUID(), receivedAt: new Date().toISOString() });
      stored.terminalType = "submit"; stored.receiptId ||= crypto.randomUUID();
      if (DATABASE_URL) {
        const finalized = await finalizePostgresAttempt(grant, stored, "submit");
        return { duplicate: finalized.duplicate, blocked: finalized.duplicate, receipt: finalized.stored.closureKey ? publicClosureReceipt(finalized.stored) : publicSubmissionReceipt(finalized.stored) };
      }
      grant.session.results.push(stored);
      grant.claims.revokedAt = Date.now();
      try { await persistStore(); } catch (error) { grant.session.results.pop(); grant.claims.revokedAt = null; throw error; }
      broadcast(grant.claims.tid, grant.claims.sid, { type: "result", entry: stored });
      return { duplicate: false, receipt: publicSubmissionReceipt(stored) };
    });
    return res.json({ ok: true, ...response });
  } catch (error) { if (error.status) return res.status(error.status).json({ error: error.message }); next(error); }
});

app.post("/api/attempt/closure", async (req, res, next) => {
  try {
    const grant = await requireAttemptCapability(req, res, { allowRevoked: true }); if (!grant) return;
    const response = await serializeTerminalMutation(async () => {
      const prior = await findAttemptForGrant(grant);
      if (prior) return { duplicate: true, blocked: true, receipt: prior.closureKey ? publicClosureReceipt(prior) : publicSubmissionReceipt(prior) };
      if (grant.claims.revokedAt) { const error = new Error("La capacidad ya fue consumida"); error.status = 401; throw error; }
      const entry = sanitizeEntry({ ...(req.body?.entry || {}), doc: grant.claims.sub });
      if (!entry || entry.closureKey === "success") { const error = new Error("El cierre se reserva para anomalías"); error.status = 400; throw error; }
      const stored = { ...entry, tenantId: grant.claims.tid, sessionId: grant.claims.sid, terminalType: "closure", receiptId: crypto.randomUUID(), verifiedByServer: true, receivedAt: new Date().toISOString() };
      delete stored.score; delete stored.grade; delete stored.percent; delete stored.answers;
      if (DATABASE_URL) {
        const finalized = await finalizePostgresAttempt(grant, stored, "closure");
        return { duplicate: finalized.duplicate, blocked: finalized.duplicate, receipt: finalized.stored.closureKey ? publicClosureReceipt(finalized.stored) : publicSubmissionReceipt(finalized.stored) };
      }
      grant.session.closures.push(stored);
      grant.claims.revokedAt = Date.now();
      try { await persistStore(); } catch (error) { grant.session.closures.pop(); grant.claims.revokedAt = null; throw error; }
      broadcast(grant.claims.tid, grant.claims.sid, { type: "closure", entry: stored });
      return { duplicate: false, receipt: publicClosureReceipt(stored) };
    });
    return res.json({ ok: true, ...response });
  } catch (error) { if (error.status) return res.status(error.status).json({ error: error.message }); next(error); }
});

app.post("/api/result", (_req, res) => {
  return res.status(410).json({ error: "Endpoint retirado; use /api/attempt/submit con capacidad" });
});

// POST /api/closure  — student submits closure reason
app.post("/api/closure", (_req, res) => res.status(410).json({ error: "Endpoint retirado; use /api/attempt/closure con capacidad" }));
// GET /api/results/:sessionId  — admin polls results (fallback if WS unavailable)
app.get("/api/results/:sessionId", async (req, res, next) => {
  const tenantId = getTenantIdFromRequest(req);
  if (!requireTenantWriteAccess(req, res, tenantId)) return;
  const sessionId = sanitizeSessionId(req.params.sessionId);
  if (DATABASE_URL) {
    try {
      const result = await getDatabasePool().query("select terminal_type,payload from evapro_attempts where tenant_id=$1 and session_id=$2 order by received_at", [tenantId, sessionId]);
      return res.json({ tenantId, sessionId, results: result.rows.filter((row) => row.terminal_type === "submit").map((row) => row.payload), closures: result.rows.filter((row) => row.terminal_type === "closure").map((row) => row.payload) });
    } catch (error) { return next(error); }
  }
  const session = readSession(tenantId, sessionId);
  if (!session) return res.json({ results: [], closures: [] });
  return res.json({ tenantId, sessionId, results: session.results, closures: session.closures });
});

// GET /api/attempt-status/:sessionId/:doc
app.get("/api/attempt-status/:sessionId/:doc", (_req, res) => res.status(410).json({ error: "Endpoint retirado; use POST /api/attempt/status" }));
// DELETE /api/results/:sessionId  — admin clears results (requires admin secret)
app.delete("/api/results/:sessionId", async (req, res, next) => {
  const tenantId = getTenantIdFromRequest(req);
  if (!requireTenantWriteAccess(req, res, tenantId)) return;
  const sessionId = sanitizeSessionId(req.params.sessionId);
  const session = readSession(tenantId, sessionId);
  if (session) {
    const previousResults = session.results;
    const previousClosures = session.closures;
    session.results = [];
    session.closures = [];
    try { await persistSessionAuthority(session, { clearAttempts: true }); } catch (error) { session.results = previousResults; session.closures = previousClosures; return next(error); }
    broadcast(tenantId, sessionId, { type: "cleared" });
  }
  return res.json({ ok: true, tenantId, sessionId });
});

// POST /api/exam/:sessionId  — teacher publishes the active exam package
app.post("/api/exam/:sessionId", async (req, res, next) => {
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
  const previousPackage = session.examPackage;
  session.examPackage = safePackage;
  try { await persistSessionAuthority(session); } catch (error) { session.examPackage = previousPackage; return next(error); }
  broadcast(tenantId, sessionId, { type: "exam-updated", updatedAt: session.examPackage.receivedAt, questionCount: session.examPackage.questionBank.length });
  return res.json({ ok: true, tenantId, sessionId, questionCount: session.examPackage.questionBank.length, updatedAt: session.examPackage.receivedAt });
});

// GET /api/exam/:sessionId  — student downloads the active exam package
app.get("/api/exam/:sessionId", (_req, res) => res.status(410).json({ error: "Endpoint retirado; use /api/attempt/exam con capacidad" }));
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

app.get("/readyz", async (_req, res) => {
  try {
    await storeReady;
    if (DATABASE_URL) await getDatabasePool().query("select 1");
    return res.json({ status: "ready", storage: storageMode });
  } catch (_error) {
    return res.status(503).json({ status: "not-ready" });
  }
});

// ─── Global error handler ─────────────────────────────────────────────────────
app.use((err, req, res, _next) => {
  console.error("Unhandled error:", err.message);
  if (err.message?.includes("CORS")) return res.status(403).json({ error: "CORS: origen no permitido" });
  res.status(500).json({ error: "Error interno del servidor" });
});

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
server.requestTimeout = 30_000;
server.headersTimeout = 35_000;
server.keepAliveTimeout = 5_000;

async function start() {
  if (IS_PRODUCTION && !ADMIN_SECRET) {
    throw new Error("ADMIN_SECRET es obligatorio en producción");
  }
  await storeReady;
  return server.listen(PORT, () => {
    console.log(`EVALUAPRO server running on port ${server.address().port}`);
    if (DEV_OPEN_ACCESS) console.warn("DEV_OPEN_ACCESS activo: úselo únicamente en desarrollo local.");
  });
}

if (require.main === module) start().catch((error) => { console.error(error); process.exitCode = 1; });

module.exports = { app, server, start };
