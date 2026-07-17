const test = require("node:test");
const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const crypto = require("node:crypto");
const path = require("node:path");
const { Pool } = require("pg");

const required = process.env.REQUIRE_POSTGRES_TESTS === "true";
const databaseUrl = process.env.TEST_DATABASE_URL || process.env.DATABASE_URL || "";
if (required && !databaseUrl) throw new Error("REQUIRE_POSTGRES_TESTS=true exige TEST_DATABASE_URL o DATABASE_URL");

const adminSecret = "postgres-integration-admin-secret";
const tokenHashSecret = "postgres-integration-token-hash-secret";
const failpointSecret = "postgres-integration-failpoint-secret";
const children = new Set();

function boot(nodeEnv, extraEnv = {}) {
  const child = spawn(process.execPath, ["server.js"], {
    cwd: path.join(__dirname, ".."),
    env: {
      ...process.env,
      NODE_ENV: nodeEnv,
      DATABASE_URL: databaseUrl,
      PORT: "0",
      ADMIN_SECRET: adminSecret,
      TOKEN_HASH_SECRET: tokenHashSecret,
      ALLOWED_ORIGINS: "http://127.0.0.1",
      ...extraEnv
    },
    stdio: ["ignore", "pipe", "pipe"]
  });
  children.add(child);
  let stderr = "";
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  const started = new Promise((resolve, reject) => {
    let stdout = "";
    const timeout = setTimeout(() => reject(new Error(`Servidor no inicio. stderr: ${stderr}`)), 15_000);
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
      const match = stdout.match(/running on port (\d+)/);
      if (match) {
        clearTimeout(timeout);
        resolve({ child, port: Number(match[1]), baseUrl: `http://127.0.0.1:${match[1]}` });
      }
    });
    child.once("exit", (code) => {
      clearTimeout(timeout);
      reject(new Error(`Servidor termino antes de readiness (${code}). stderr: ${stderr}`));
    });
  });
  return started;
}

async function ready(instance) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      const response = await fetch(`${instance.baseUrl}/readyz`);
      if (response.ok) return instance;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`Proceso ${instance.port} no alcanzo readiness`);
}

async function stopAll() {
  await Promise.all([...children].map((child) => new Promise((resolve) => {
    if (child.exitCode !== null) return resolve();
    child.once("exit", resolve);
    child.kill("SIGTERM");
    setTimeout(() => { if (child.exitCode === null) child.kill("SIGKILL"); }, 3_000).unref();
  })));
  children.clear();
}

async function request(baseUrl, route, options = {}) {
  const response = await fetch(baseUrl + route, options);
  const text = await response.text();
  let body = null;
  try { body = text ? JSON.parse(text) : null; } catch { body = text; }
  return { response, body };
}

async function adminLogin(baseUrl, tenantId) {
  const result = await request(baseUrl, "/api/auth/admin", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ secret: adminSecret, tenantId })
  });
  assert.equal(result.response.status, 200, JSON.stringify(result.body));
  return { cookie: result.response.headers.get("set-cookie").split(";")[0], csrf: result.body.csrfToken };
}

function exam(tenantId, doc) {
  return {
    schema: "evaluapro-utch.studentlink.v3",
    tenantId,
    allowedAccess: [{ name: "Postgres Student", doc }],
    settings: { questionTotal: 1 },
    questionBank: [{ type: "multiple_choice", question: "Two plus two?", options: ["3", "4", "5"], correct: 1, rationale: "Arithmetic" }]
  };
}

async function publish(baseUrl, auth, tenantId, sessionId, doc) {
  const result = await request(baseUrl, `/api/exam/${sessionId}`, {
    method: "POST",
    headers: { cookie: auth.cookie, "x-csrf-token": auth.csrf, "content-type": "application/json" },
    body: JSON.stringify({ tenantId, package: exam(tenantId, doc) })
  });
  assert.equal(result.response.status, 200, JSON.stringify(result.body));
}

async function capability(baseUrl, tenantId, sessionId, doc) {
  const result = await request(baseUrl, "/api/attempt/capability", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ tenantId, sessionId, doc })
  });
  assert.equal(result.response.status, 201, JSON.stringify(result.body));
  assert.match(result.body.capability, /^[A-Za-z0-9_-]{43}$/);
  return result.body.capability;
}

function submit(baseUrl, token) {
  return request(baseUrl, "/api/attempt/submit", {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify({ entry: { name: "Postgres Student", answers: [{ type: "multiple_choice", question: "Two plus two?", selected: 1 }] } })
  });
}

function closure(baseUrl, token) {
  return request(baseUrl, "/api/attempt/closure", {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify({ entry: { name: "Postgres Student", closureKey: "internal", closureCode: "PG-01", closureReason: "controlled race" } })
  });
}

test("Postgres: atomicidad HTTP entre procesos, rollback recuperable y failpoint ausente en produccion", { skip: !databaseUrl, timeout: 45_000 }, async () => {
  const suffix = crypto.randomBytes(6).toString("hex");
  const tenantId = `pg-${suffix}`;
  const raceSession = `race-${suffix}`;
  const rollbackSession = `rollback-${suffix}`;
  const raceDoc = `81${crypto.randomInt(10_000_000, 99_999_999)}`;
  const rollbackDoc = `82${crypto.randomInt(10_000_000, 99_999_999)}`;
  const sslDisabled = /(?:[?&])sslmode=disable(?:&|$)/i.test(databaseUrl);
  const pool = new Pool({ connectionString: databaseUrl, ssl: sslDisabled ? false : { rejectUnauthorized: false } });
  try {
    const [a, b] = await Promise.all([
      boot("test", { TEST_FAILPOINT_SECRET: failpointSecret }).then(ready),
      boot("test").then(ready)
    ]);
    const auth = await adminLogin(a.baseUrl, tenantId);

    await publish(a.baseUrl, auth, tenantId, raceSession, raceDoc);
    const raceCapability = await capability(b.baseUrl, tenantId, raceSession, raceDoc);
    const [submitA, closureB] = await Promise.all([submit(a.baseUrl, raceCapability), closure(b.baseUrl, raceCapability)]);
    assert.equal(submitA.response.status, 200, JSON.stringify(submitA.body));
    assert.equal(closureB.response.status, 200, JSON.stringify(closureB.body));
    assert.equal([submitA.body.duplicate, closureB.body.duplicate].filter(Boolean).length, 1);
    assert.deepEqual(submitA.body.receipt, closureB.body.receipt);
    const raceRows = await pool.query("select terminal_type,receipt_id,payload from evapro_attempts where tenant_id=$1 and session_id=$2", [tenantId, raceSession]);
    assert.equal(raceRows.rowCount, 1);
    assert.deepEqual(raceRows.rows[0].payload.receiptId, submitA.body.receipt.receiptId);

    await publish(a.baseUrl, auth, tenantId, rollbackSession, rollbackDoc);
    const rollbackCapability = await capability(b.baseUrl, tenantId, rollbackSession, rollbackDoc);
    const armed = await request(a.baseUrl, "/api/test/failpoint/finalize-after-revoke", {
      method: "POST",
      headers: { "x-test-failpoint-secret": failpointSecret }
    });
    assert.equal(armed.response.status, 200, JSON.stringify(armed.body));
    const failed = await submit(a.baseUrl, rollbackCapability);
    assert.equal(failed.response.status, 500, JSON.stringify(failed.body));
    assert.equal(Number((await pool.query("select count(*) from evapro_attempts where tenant_id=$1 and session_id=$2", [tenantId, rollbackSession])).rows[0].count), 0);
    const capabilityState = await pool.query("select revoked_at from evapro_capabilities where tenant_id=$1 and session_id=$2", [tenantId, rollbackSession]);
    assert.equal(capabilityState.rowCount, 1);
    assert.equal(capabilityState.rows[0].revoked_at, null);
    const retried = await submit(b.baseUrl, rollbackCapability);
    assert.equal(retried.response.status, 200, JSON.stringify(retried.body));
    assert.equal(retried.body.duplicate, false);
    assert.equal(Number((await pool.query("select count(*) from evapro_attempts where tenant_id=$1 and session_id=$2", [tenantId, rollbackSession])).rows[0].count), 1);

    const production = await boot("production").then(ready);
    const hidden = await request(production.baseUrl, "/api/test/failpoint/finalize-after-revoke", {
      method: "POST",
      headers: { "x-test-failpoint-secret": failpointSecret }
    });
    assert.equal(hidden.response.status, 404);

    const rls = await pool.query("select relrowsecurity from pg_class where relname in ('evapro_sessions','evapro_teacher_registries','evapro_attempts','evapro_capabilities','evapro_auth_sessions')");
    assert.equal(rls.rows.length, 5);
    assert.ok(rls.rows.every((row) => row.relrowsecurity));
  } finally {
    await stopAll();
    await pool.query("delete from evapro_attempts where tenant_id=$1", [tenantId]).catch(() => {});
    await pool.query("delete from evapro_capabilities where tenant_id=$1", [tenantId]).catch(() => {});
    await pool.query("delete from evapro_sessions where tenant_id=$1", [tenantId]).catch(() => {});
    await pool.query("delete from evapro_auth_sessions where tenant_id=$1", [tenantId]).catch(() => {});
    await pool.end().catch(() => {});
  }
});
