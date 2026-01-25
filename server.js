import express from "express";
import helmet from "helmet";
import session from "express-session";
import pg from "pg";
import connectPgSimple from "connect-pg-simple";
import bcrypt from "bcryptjs";
import { WebSocketServer } from "ws";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const {
  DATABASE_URL,
  SESSION_SECRET,
  NODE_ENV,
  PORT,
  ADMIN_BOOTSTRAP_TOKEN,
} = process.env;

if (!DATABASE_URL) throw new Error("Missing env DATABASE_URL");
if (!SESSION_SECRET) throw new Error("Missing env SESSION_SECRET");

const isProd = NODE_ENV === "production";
const app = express();
app.set("trust proxy", 1);

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "64kb" }));
app.use(express.urlencoded({ extended: false }));

function stripQuery(urlString) {
  try {
    const u = new URL(urlString);
    u.search = "";
    return u.toString();
  } catch {
    return urlString;
  }
}

function useSsl(urlString) {
  const s = String(urlString || "").toLowerCase();
  return s.includes("supabase.com") || s.includes("pooler") || isProd;
}

const pool = new pg.Pool({
  connectionString: stripQuery(DATABASE_URL),
  ssl: useSsl(DATABASE_URL) ? { rejectUnauthorized: false } : undefined,
});

const PgStore = connectPgSimple(session);

const sessionMiddleware = session({
  store: new PgStore({
    pool,
    tableName: "user_sessions",
    createTableIfMissing: true,
  }),
  name: "chatly.sid",
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: isProd,
    maxAge: 1000 * 60 * 60 * 24 * 14,
  },
});

app.use(sessionMiddleware);

app.use(express.static(__dirname, { extensions: ["html"] }));

function now() {
  return new Date();
}

function minutesFromNow(m) {
  const d = new Date();
  d.setMinutes(d.getMinutes() + m);
  return d;
}

function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function normalizeUsername(u) {
  return String(u || "").trim();
}

function validUsername(u) {
  return /^[A-Za-z0-9._-]{3,24}$/.test(u);
}

function validPassword(p) {
  return typeof p === "string" && p.length >= 6 && p.length <= 128;
}

async function q(text, params = []) {
  return pool.query(text, params);
}

async function initDb() {
  await q(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      pass_hash TEXT NOT NULL,
      bio TEXT DEFAULT '',
      avatar_url TEXT DEFAULT '',
      role TEXT NOT NULL DEFAULT 'user',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      banned_until TIMESTAMPTZ,
      timeout_until TIMESTAMPTZ,
      needs_password_change BOOLEAN NOT NULL DEFAULT FALSE,
      session_version INTEGER NOT NULL DEFAULT 0
    );
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS rooms (
      id BIGSERIAL PRIMARY KEY,
      slug TEXT UNIQUE NOT NULL,
      title TEXT NOT NULL,
      is_private BOOLEAN NOT NULL DEFAULT FALSE,
      pass_hash TEXT,
      created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS messages (
      id BIGSERIAL PRIMARY KEY,
      room_id BIGINT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
      author_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
      body TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      is_admin BOOLEAN NOT NULL DEFAULT FALSE
    );
  `);

  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS banned_until TIMESTAMPTZ;`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS timeout_until TIMESTAMPTZ;`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS needs_password_change BOOLEAN NOT NULL DEFAULT FALSE;`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS session_version INTEGER NOT NULL DEFAULT 0;`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS bio TEXT DEFAULT '';`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url TEXT DEFAULT '';`);
  await q(`ALTER TABLE rooms ADD COLUMN IF NOT EXISTS is_private BOOLEAN NOT NULL DEFAULT FALSE;`);
  await q(`ALTER TABLE rooms ADD COLUMN IF NOT EXISTS pass_hash TEXT;`);
  await q(`ALTER TABLE messages ADD COLUMN IF NOT EXISTS is_admin BOOLEAN NOT NULL DEFAULT FALSE;`);

  const roomCount = await q(`SELECT COUNT(*)::int AS c FROM rooms;`);
  if (roomCount.rows[0].c === 0) {
    await q(
      `INSERT INTO rooms (slug, title, is_private) VALUES ($1,$2,$3), ($4,$5,$6);`,
      ["lobby", "Lobby", false, "fun", "Fun", false]
    );
  }
}

async function getUserById(id) {
  const r = await q(
    `SELECT id, username, bio, avatar_url, role, banned_until, timeout_until, needs_password_change, session_version
     FROM users WHERE id=$1;`,
    [id]
  );
  return r.rows[0] || null;
}

async function getUserByUsername(username) {
  const r = await q(`SELECT * FROM users WHERE username=$1;`, [username]);
  return r.rows[0] || null;
}

async function getRoomBySlug(slug) {
  const r = await q(`SELECT * FROM rooms WHERE slug=$1;`, [slug]);
  return r.rows[0] || null;
}

function requireAuth(req, res, next) {
  if (!req.session?.userId) return res.status(401).json({ ok: false, error: "not_authenticated" });
  next();
}

async function requireFreshSession(req, res, next) {
  const u = await getUserById(req.session.userId);
  if (!u) return res.status(401).json({ ok: false, error: "not_authenticated" });

  if ((req.session.sessionVersion ?? 0) !== u.session_version) {
    req.session.destroy(() => {});
    return res.status(401).json({ ok: false, error: "session_invalidated" });
  }

  if (u.banned_until && new Date(u.banned_until) > now()) return res.status(403).json({ ok: false, error: "banned" });

  if (
    u.needs_password_change &&
    req.path !== "/api/change-password" &&
    req.path !== "/api/logout" &&
    req.path !== "/api/me"
  ) {
    return res.status(403).json({ ok: false, error: "password_change_required" });
  }

  req.user = u;
  next();
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== "admin") return res.status(403).json({ ok: false, error: "not_admin" });
  next();
}

async function enforcePunishments(userId) {
  const u = await getUserById(userId);
  if (!u) return { ok: false, error: "not_found" };
  if (u.banned_until && new Date(u.banned_until) > now()) return { ok: false, error: "banned" };
  if (u.timeout_until && new Date(u.timeout_until) > now()) return { ok: false, error: "timeout" };
  return { ok: true };
}

app.get("/api/health", async (_req, res) => {
  try {
    await q("SELECT 1;");
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false });
  }
});

app.post("/api/register", async (req, res) => {
  const username = normalizeUsername(req.body.username);
  const password = req.body.password;

  if (!validUsername(username)) return res.status(400).json({ ok: false, error: "bad_username" });
  if (!validPassword(password)) return res.status(400).json({ ok: false, error: "bad_password" });

  const bio = typeof req.body.bio === "string" ? req.body.bio.slice(0, 160) : "";
  const avatarUrl = typeof req.body.avatarUrl === "string" ? req.body.avatarUrl.slice(0, 300) : "";

  const existing = await getUserByUsername(username);
  if (existing) return res.status(409).json({ ok: false, error: "username_taken" });

  const pass_hash = await bcrypt.hash(password, 12);

  const r = await q(
    `INSERT INTO users (username, pass_hash, bio, avatar_url)
     VALUES ($1,$2,$3,$4)
     RETURNING id, username, role, session_version;`,
    [username, pass_hash, bio, avatarUrl]
  );

  req.session.userId = r.rows[0].id;
  req.session.sessionVersion = r.rows[0].session_version;
  req.session.roomSlug = "lobby";

  res.json({ ok: true, user: { id: r.rows[0].id, username, role: r.rows[0].role } });
});

app.post("/api/login", async (req, res) => {
  const username = normalizeUsername(req.body.username);
  const password = req.body.password;

  const u = await getUserByUsername(username);
  if (!u) return res.status(401).json({ ok: false, error: "bad_login" });

  if (u.banned_until && new Date(u.banned_until) > now()) return res.status(403).json({ ok: false, error: "banned" });

  const ok = await bcrypt.compare(String(password || ""), u.pass_hash);
  if (!ok) return res.status(401).json({ ok: false, error: "bad_login" });

  req.session.userId = u.id;
  req.session.sessionVersion = u.session_version;
  req.session.roomSlug = req.session.roomSlug || "lobby";

  res.json({
    ok: true,
    user: { id: u.id, username: u.username, role: u.role, needsPasswordChange: !!u.needs_password_change },
  });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("chatly.sid");
    res.json({ ok: true });
  });
});

app.get("/api/me", requireAuth, requireFreshSession, async (req, res) => {
  const u = req.user;
  res.json({
    ok: true,
    user: {
      id: u.id,
      username: u.username,
      bio: u.bio || "",
      avatarUrl: u.avatar_url || "",
      role: u.role,
      room: req.session.roomSlug || "lobby",
      bannedUntil: u.banned_until,
      timeoutUntil: u.timeout_until,
      needsPasswordChange: !!u.needs_password_change,
    },
  });
});

app.post("/api/change-password", requireAuth, requireFreshSession, async (req, res) => {
  const oldPassword = String(req.body.oldPassword || "");
  const newPassword = req.body.newPassword;

  if (!validPassword(newPassword)) return res.status(400).json({ ok: false, error: "bad_password" });

  const u = await getUserByUsername(req.user.username);
  const ok = await bcrypt.compare(oldPassword, u.pass_hash);
  if (!ok) return res.status(401).json({ ok: false, error: "bad_old_password" });

  const pass_hash = await bcrypt.hash(newPassword, 12);

  const r = await q(
    `UPDATE users
     SET pass_hash=$1, needs_password_change=FALSE, session_version=session_version+1
     WHERE id=$2
     RETURNING session_version;`,
    [pass_hash, req.user.id]
  );

  req.session.sessionVersion = r.rows[0].session_version;
  res.json({ ok: true });
});

app.get("/api/rooms", requireAuth, requireFreshSession, async (_req, res) => {
  const r = await q(`SELECT slug, title, is_private FROM rooms ORDER BY created_at ASC;`);
  res.json({ ok: true, rooms: r.rows });
});

app.post("/api/rooms/join", requireAuth, requireFreshSession, async (req, res) => {
  const slug = String(req.body.slug || "").trim().toLowerCase();
  const password = req.body.password;

  const room = await getRoomBySlug(slug);
  if (!room) return res.status(404).json({ ok: false, error: "room_not_found" });

  if (room.is_private) {
    if (!room.pass_hash) return res.status(500).json({ ok: false, error: "room_misconfigured" });
    const ok = await bcrypt.compare(String(password || ""), room.pass_hash);
    if (!ok) return res.status(403).json({ ok: false, error: "bad_room_password" });
  }

  req.session.roomSlug = room.slug;
  res.json({ ok: true, room: { slug: room.slug, title: room.title } });
});

app.get("/api/messages", requireAuth, requireFreshSession, async (req, res) => {
  const slug = String(req.query.room || req.session.roomSlug || "lobby").trim().toLowerCase();
  const limit = Math.max(1, Math.min(100, parseInt(req.query.limit || "50", 10)));

  const room = await getRoomBySlug(slug);
  if (!room) return res.status(404).json({ ok: false, error: "room_not_found" });

  const r = await q(
    `
    SELECT
      m.id, m.body, m.created_at, m.is_admin,
      u.username AS author_username,
      u.avatar_url AS author_avatar
    FROM messages m
    LEFT JOIN users u ON u.id = m.author_id
    WHERE m.room_id=$1
    ORDER BY m.id DESC
    LIMIT $2;
    `,
    [room.id, limit]
  );

  res.json({ ok: true, messages: r.rows.reverse() });
});

app.post("/api/messages", requireAuth, requireFreshSession, async (req, res) => {
  const roomSlug = String(req.body.room || req.session.roomSlug || "lobby").trim().toLowerCase();
  const rawBody = String(req.body.body || "");
  const body = rawBody.trim().slice(0, 2000);

  if (!body) return res.status(400).json({ ok: false, error: "empty" });

  const room = await getRoomBySlug(roomSlug);
  if (!room) return res.status(404).json({ ok: false, error: "room_not_found" });

  const punish = await enforcePunishments(req.user.id);
  if (!punish.ok) return res.status(403).json(punish);

  const safeBody = escapeHtml(body);

  const r = await q(
    `INSERT INTO messages (room_id, author_id, body, is_admin)
     VALUES ($1,$2,$3,$4)
     RETURNING id, created_at, is_admin;`,
    [room.id, req.user.id, safeBody, req.user.role === "admin"]
  );

  const payload = {
    type: "message",
    message: {
      id: r.rows[0].id,
      room: room.slug,
      body: safeBody,
      created_at: r.rows[0].created_at,
      is_admin: r.rows[0].is_admin,
      author_username: req.user.username,
      author_avatar: req.user.avatar_url || "",
    },
  };

  broadcastToRoom(room.slug, payload);
  res.json({ ok: true, id: r.rows[0].id });
});

app.post("/api/admin/bootstrap", async (req, res) => {
  const token = String(req.body.token || "");
  if (!ADMIN_BOOTSTRAP_TOKEN || token !== ADMIN_BOOTSTRAP_TOKEN) return res.status(403).json({ ok: false, error: "bad_token" });

  const admins = await q(`SELECT COUNT(*)::int AS c FROM users WHERE role='admin';`);
  if (admins.rows[0].c > 0) return res.status(409).json({ ok: false, error: "admin_exists" });

  const username = normalizeUsername(req.body.username);
  const password = req.body.password;

  if (!validUsername(username)) return res.status(400).json({ ok: false, error: "bad_username" });
  if (!validPassword(password)) return res.status(400).json({ ok: false, error: "bad_password" });

  const pass_hash = await bcrypt.hash(password, 12);

  const r = await q(
    `INSERT INTO users (username, pass_hash, role, needs_password_change)
     VALUES ($1,$2,'admin',TRUE)
     RETURNING id, session_version;`,
    [username, pass_hash]
  );

  res.json({ ok: true, adminId: r.rows[0].id, needsPasswordChange: true });
});

app.get("/api/admin/me", requireAuth, requireFreshSession, requireAdmin, async (_req, res) => {
  res.json({ ok: true });
});

app.post("/api/admin/ban", requireAuth, requireFreshSession, requireAdmin, async (req, res) => {
  const username = normalizeUsername(req.body.username);
  const minutes = Math.max(1, Math.min(60 * 24 * 30, parseInt(req.body.minutes || "60", 10)));

  const u = await getUserByUsername(username);
  if (!u) return res.status(404).json({ ok: false, error: "not_found" });
  if (u.role === "admin") return res.status(400).json({ ok: false, error: "cannot_ban_admin" });

  await q(`UPDATE users SET banned_until=$1, session_version=session_version+1 WHERE id=$2;`, [minutesFromNow(minutes), u.id]);
  res.json({ ok: true });
});

app.post("/api/admin/timeout", requireAuth, requireFreshSession, requireAdmin, async (req, res) => {
  const username = normalizeUsername(req.body.username);
  const minutes = Math.max(1, Math.min(60 * 24 * 7, parseInt(req.body.minutes || "10", 10)));

  const u = await getUserByUsername(username);
  if (!u) return res.status(404).json({ ok: false, error: "not_found" });
  if (u.role === "admin") return res.status(400).json({ ok: false, error: "cannot_timeout_admin" });

  await q(`UPDATE users SET timeout_until=$1 WHERE id=$2;`, [minutesFromNow(minutes), u.id]);
  res.json({ ok: true });
});

app.post("/api/admin/force-password-reset", requireAuth, requireFreshSession, requireAdmin, async (req, res) => {
  const username = normalizeUsername(req.body.username);
  const u = await getUserByUsername(username);
  if (!u) return res.status(404).json({ ok: false, error: "not_found" });
  if (u.role === "admin") return res.status(400).json({ ok: false, error: "cannot_reset_admin" });

  await q(`UPDATE users SET needs_password_change=TRUE, session_version=session_version+1 WHERE id=$1;`, [u.id]);
  res.json({ ok: true });
});

const socketsByUserId = new Map();

function broadcastToRoom(roomSlug, payload) {
  const msg = JSON.stringify(payload);
  for (const ws of socketsByUserId.values()) {
    if (ws.readyState !== 1) continue;
    if (ws.roomSlug !== roomSlug) continue;
    ws.send(msg);
  }
}

const server = app.listen(parseInt(PORT || "10000", 10), () => {
  console.log(`Chatly listening on :${PORT || 10000}`);
});

initDb()
  .then(() => console.log("DB ready"))
  .catch((e) => {
    console.error("DB init error:", e);
    process.exit(1);
  });

const wss = new WebSocketServer({ noServer: true });

function runSession(req) {
  return new Promise((resolve) => {
    const res = { getHeader() {}, setHeader() {}, writeHead() {}, end() {} };
    sessionMiddleware(req, res, resolve);
  });
}

server.on("upgrade", async (req, socket, head) => {
  try {
    await runSession(req);
    if (!req.session?.userId) {
      socket.destroy();
      return;
    }

    wss.handleUpgrade(req, socket, head, (ws) => {
      ws.userId = req.session.userId;
      ws.roomSlug = req.session.roomSlug || "lobby";
      socketsByUserId.set(ws.userId, ws);

      ws.on("message", async (buf) => {
        let data;
        try {
          data = JSON.parse(buf.toString("utf8"));
        } catch {
          return;
        }

        if (data?.type === "join" && typeof data.slug === "string") {
          const slug = data.slug.trim().toLowerCase();
          const room = await getRoomBySlug(slug);
          if (!room) return;
          ws.roomSlug = room.slug;
          if (req.session) req.session.roomSlug = room.slug;
          ws.send(JSON.stringify({ type: "joined", slug: room.slug }));
        }
      });

      ws.on("close", () => {
        socketsByUserId.delete(ws.userId);
      });

      ws.send(JSON.stringify({ type: "hello", room: ws.roomSlug }));
    });
  } catch {
    socket.destroy();
  }
});
