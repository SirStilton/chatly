import express from "express";
import session from "express-session";
import bcrypt from "bcryptjs";
import path from "path";
import http from "http";
import { WebSocketServer } from "ws";
import { fileURLToPath } from "url";
import pg from "pg";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import sanitizeHtml from "sanitize-html";
import connectPgSimple from "connect-pg-simple";

const { Pool } = pg;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  console.error("Missing DATABASE_URL env var");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

function safeRoom(input) {
  const room = String(input || "lobby").trim().toLowerCase();
  const cleaned = room.replace(/[^a-z0-9_-]/g, "").slice(0, 32);
  return cleaned || "lobby";
}

function hashPw(pw) {
  return bcrypt.hashSync(pw, 10);
}
function verifyPw(pw, hash) {
  try { return bcrypt.compareSync(String(pw), String(hash)); } catch { return false; }
}

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      pass_hash TEXT NOT NULL,
      bio TEXT DEFAULT '',
      avatar TEXT DEFAULT '',
      role TEXT DEFAULT 'user',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      needs_password_change BOOLEAN DEFAULT FALSE,
      admin_panel_hash TEXT DEFAULT NULL,
      admin_panel_needs_setup BOOLEAN DEFAULT FALSE
    );

    CREATE TABLE IF NOT EXISTS messages (
      id BIGSERIAL PRIMARY KEY,
      room TEXT NOT NULL DEFAULT 'lobby',
      content TEXT NOT NULL,
      author_id BIGINT NOT NULL REFERENCES users(id),
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_messages_room_id ON messages(room, id);

    CREATE TABLE IF NOT EXISTS punishments (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id),
      type TEXT NOT NULL,
      reason TEXT DEFAULT '',
      until_ts BIGINT DEFAULT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      created_by BIGINT NOT NULL REFERENCES users(id),
      active BOOLEAN DEFAULT TRUE
    );

    CREATE INDEX IF NOT EXISTS idx_punish_user_active ON punishments(user_id, active, type);
  `);

  const admin = await pool.query(`SELECT id FROM users WHERE username=$1`, ["admin"]);
  if (admin.rowCount === 0) {
    await pool.query(
      `INSERT INTO users (username, pass_hash, bio, role, needs_password_change, admin_panel_hash, admin_panel_needs_setup)
       VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      ["admin", hashPw("admin123"), "Master Administrator", "admin", true, hashPw("admin12"), true]
    );
    console.log("Created default admin: admin / admin123 (CHANGE THIS!)");
  }
}

app.set("trust proxy", 1);

app.use(helmet({
  contentSecurityPolicy: false
}));

app.use(express.json({ limit: "200kb" }));

app.use(rateLimit({
  windowMs: 60_000,
  limit: 240,
  standardHeaders: true,
  legacyHeaders: false
}));

const PgSession = connectPgSimple(session);

const sessionParser = session({
  store: new PgSession({
    pool,
    tableName: "user_sessions",
    createTableIfMissing: true
  }),
  secret: process.env.SESSION_SECRET || "change-this-secret-please-12345",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: !!process.env.COOKIE_SECURE
  }
});

app.use(sessionParser);

app.use(express.static(path.join(__dirname, "public")));

function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "not_logged_in" });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "not_logged_in" });
  if (req.session.user.role !== "admin") return res.status(403).json({ error: "not_admin" });
  next();
}
function requireAdminPanel(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "not_logged_in" });
  if (req.session.user.role !== "admin") return res.status(403).json({ error: "not_admin" });
  if (!req.session.adminPanelUnlocked) return res.status(403).json({ error: "admin_panel_locked" });
  next();
}

async function getUserByUsername(username) {
  const r = await pool.query(
    `SELECT id, username, role, pass_hash, needs_password_change, admin_panel_hash, admin_panel_needs_setup, bio, avatar
     FROM users WHERE username=$1`,
    [username]
  );
  return r.rows[0] || null;
}
function publicUser(u) {
  return { id: Number(u.id), username: u.username, role: u.role };
}

async function cleanupPunishmentsForUser(userId) {
  const t = nowSec();
  await pool.query(
    `UPDATE punishments
     SET active=FALSE
     WHERE user_id=$1 AND active=TRUE AND until_ts IS NOT NULL AND until_ts <= $2`,
    [userId, t]
  );
}

async function getActivePunishment(userId, type) {
  await cleanupPunishmentsForUser(userId);
  const t = nowSec();
  const r = await pool.query(
    `SELECT id, type, reason, until_ts
     FROM punishments
     WHERE user_id=$1 AND type=$2 AND active=TRUE AND (until_ts IS NULL OR until_ts > $3)
     ORDER BY id DESC
     LIMIT 1`,
    [userId, type, t]
  );
  return r.rows[0] || null;
}

async function getPunishmentFlags(userId) {
  const ban = await getActivePunishment(userId, "ban");
  const mute = await getActivePunishment(userId, "mute");
  return { banned: !!ban, muted: !!mute, ban, mute };
}

async function banCheck(req, res, next) {
  if (!req.session.user) return next();
  const flags = await getPunishmentFlags(req.session.user.id);
  if (flags.banned) return res.status(403).json({ error: "banned" });
  next();
}

app.post("/api/register", async (req, res) => {
  try {
    const { username, password, bio = "", avatar = "" } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: "missing_fields" });

    const cleanUser = String(username).trim().slice(0, 24);
    if (cleanUser.length < 3) return res.status(400).json({ error: "username_short" });
    if (!/^[a-zA-Z0-9_.-]+$/.test(cleanUser)) return res.status(400).json({ error: "username_invalid" });
    if (String(password).length < 4) return res.status(400).json({ error: "password_short" });

    const r = await pool.query(
      `INSERT INTO users (username, pass_hash, bio, avatar, role)
       VALUES ($1,$2,$3,$4,'user')
       RETURNING id`,
      [cleanUser, hashPw(password), String(bio).slice(0, 200), String(avatar).slice(0, 300)]
    );

    req.session.user = { id: Number(r.rows[0].id), username: cleanUser, role: "user" };
    req.session.adminPanelUnlocked = false;
    res.json({ ok: true, user: req.session.user });
  } catch (e) {
    if (String(e).includes("duplicate key")) return res.status(409).json({ error: "username_taken" });
    res.status(500).json({ error: "server_error" });
  }
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "missing_fields" });

  const u = await getUserByUsername(String(username).trim());
  if (!u) return res.status(401).json({ error: "bad_login" });
  if (!verifyPw(password, u.pass_hash)) return res.status(401).json({ error: "bad_login" });

  const punish = await getPunishmentFlags(Number(u.id));
  if (punish.banned) return res.status(403).json({ error: "banned" });

  req.session.user = publicUser(u);
  req.session.adminPanelUnlocked = false;
  res.json({
    ok: true,
    user: req.session.user,
    flags: {
      needsPasswordChange: !!u.needs_password_change,
      adminPanelNeedsSetup: u.role === "admin" ? !!u.admin_panel_needs_setup : false,
      muted: punish.muted,
      mute: punish.mute || null
    }
  });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get("/api/me", async (req, res) => {
  if (!req.session.user) return res.json({ user: null });
  const u = await getUserByUsername(req.session.user.username);
  if (!u) return res.json({ user: null });

  const punish = await getPunishmentFlags(Number(u.id));

  res.json({
    user: req.session.user,
    flags: {
      needsPasswordChange: !!u.needs_password_change,
      adminPanelNeedsSetup: u.role === "admin" ? !!u.admin_panel_needs_setup : false,
      adminPanelUnlocked: !!req.session.adminPanelUnlocked,
      muted: punish.muted,
      mute: punish.mute || null
    }
  });
});

app.get("/api/profile/:username", async (req, res) => {
  const r = await pool.query(
    `SELECT username, bio, avatar, role, created_at FROM users WHERE username=$1`,
    [req.params.username]
  );
  if (r.rowCount === 0) return res.status(404).json({ error: "not_found" });
  res.json({ profile: r.rows[0] });
});

app.post("/api/profile", requireAuth, banCheck, async (req, res) => {
  const { bio = "", avatar = "" } = req.body || {};
  await pool.query(
    `UPDATE users SET bio=$1, avatar=$2 WHERE id=$3`,
    [String(bio).slice(0, 200), String(avatar).slice(0, 300), req.session.user.id]
  );
  res.json({ ok: true });
});

app.post("/api/change-password", requireAuth, banCheck, async (req, res) => {
  const { oldPassword, newPassword } = req.body || {};
  if (!oldPassword || !newPassword) return res.status(400).json({ error: "missing_fields" });
  if (String(newPassword).length < 4) return res.status(400).json({ error: "password_short" });

  const r = await pool.query(`SELECT pass_hash FROM users WHERE id=$1`, [req.session.user.id]);
  if (r.rowCount === 0) return res.status(401).json({ error: "bad_login" });
  if (!verifyPw(oldPassword, r.rows[0].pass_hash)) return res.status(401).json({ error: "bad_login" });

  await pool.query(
    `UPDATE users SET pass_hash=$1, needs_password_change=FALSE WHERE id=$2`,
    [hashPw(newPassword), req.session.user.id]
  );
  res.json({ ok: true });
});

app.post("/api/admin/setup", requireAdmin, async (req, res) => {
  const { currentLoginPassword, newLoginPassword, newAdminPanelPassword } = req.body || {};
  if (!currentLoginPassword || !newLoginPassword || !newAdminPanelPassword) return res.status(400).json({ error: "missing_fields" });
  if (String(newLoginPassword).length < 6) return res.status(400).json({ error: "password_short" });
  if (String(newAdminPanelPassword).length < 6) return res.status(400).json({ error: "password_short" });

  const r = await pool.query(
    `SELECT pass_hash, needs_password_change, admin_panel_needs_setup FROM users WHERE id=$1`,
    [req.session.user.id]
  );
  if (r.rowCount === 0) return res.status(500).json({ error: "server_error" });

  const u = r.rows[0];
  if (!u.needs_password_change && !u.admin_panel_needs_setup) return res.status(403).json({ error: "setup_not_required" });
  if (!verifyPw(currentLoginPassword, u.pass_hash)) return res.status(401).json({ error: "bad_login" });

  await pool.query(
    `UPDATE users
     SET pass_hash=$1, needs_password_change=FALSE, admin_panel_hash=$2, admin_panel_needs_setup=FALSE
     WHERE id=$3`,
    [hashPw(newLoginPassword), hashPw(newAdminPanelPassword), req.session.user.id]
  );

  req.session.adminPanelUnlocked = false;
  res.json({ ok: true });
});

app.post("/api/admin/panel/unlock", requireAdmin, async (req, res) => {
  const { adminPanelPassword } = req.body || {};
  if (!adminPanelPassword) return res.status(400).json({ error: "missing_fields" });

  const r = await pool.query(
    `SELECT admin_panel_hash, admin_panel_needs_setup FROM users WHERE id=$1`,
    [req.session.user.id]
  );
  if (r.rowCount === 0) return res.status(500).json({ error: "server_error" });

  const u = r.rows[0];
  if (u.admin_panel_needs_setup) return res.status(403).json({ error: "admin_panel_needs_setup" });
  if (!u.admin_panel_hash || !verifyPw(adminPanelPassword, u.admin_panel_hash)) return res.status(401).json({ error: "admin_panel_bad_password" });

  req.session.adminPanelUnlocked = true;
  res.json({ ok: true });
});

app.post("/api/admin/panel/lock", requireAdmin, (req, res) => {
  req.session.adminPanelUnlocked = false;
  res.json({ ok: true });
});

app.post("/api/admin/change-user-password", requireAdminPanel, async (req, res) => {
  const { username, newPassword } = req.body || {};
  if (!username || !newPassword) return res.status(400).json({ error: "missing_fields" });
  if (String(newPassword).length < 4) return res.status(400).json({ error: "password_short" });

  const target = await pool.query(`SELECT id, role FROM users WHERE username=$1`, [String(username).trim()]);
  if (target.rowCount === 0) return res.status(404).json({ error: "not_found" });
  if (target.rows[0].role === "admin") return res.status(403).json({ error: "cannot_change_admin" });

  await pool.query(
    `UPDATE users SET pass_hash=$1, needs_password_change=TRUE WHERE id=$2`,
    [hashPw(newPassword), Number(target.rows[0].id)]
  );

  res.json({ ok: true });
});

app.get("/api/messages", requireAuth, banCheck, async (req, res) => {
  const room = safeRoom(req.query.room);
  const limit = Math.min(Number(req.query.limit || 80), 200);

  const r = await pool.query(
    `SELECT m.id, m.room, m.content, m.created_at,
            u.username AS author, u.avatar AS avatar, u.role AS role
     FROM messages m
     JOIN users u ON u.id = m.author_id
     WHERE m.room=$1
     ORDER BY m.id DESC
     LIMIT $2`,
    [room, limit]
  );

  res.json({ messages: r.rows.reverse(), room });
});

const server = http.createServer(app);
const wss = new WebSocketServer({ noServer: true });

function broadcastToRoom(room, payload) {
  const msg = JSON.stringify(payload);
  for (const client of wss.clients) {
    if (client.readyState === 1 && client.room === room) client.send(msg);
  }
}
function sendToUser(username, payload) {
  const msg = JSON.stringify(payload);
  for (const client of wss.clients) {
    if (client.readyState === 1 && client.user?.username === username) client.send(msg);
  }
}
function kickUser(username, reason = "kicked") {
  for (const client of wss.clients) {
    if (client.readyState === 1 && client.user?.username === username) {
      try { client.send(JSON.stringify({ type: "system", event: "kick", reason })); } catch {}
      try { client.close(); } catch {}
    }
  }
}

server.on("upgrade", async (req, socket, head) => {
  sessionParser(req, {}, async () => {
    if (!req.session?.user) {
      socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
      socket.destroy();
      return;
    }
    const punish = await getPunishmentFlags(req.session.user.id);
    if (punish.banned) {
      socket.write("HTTP/1.1 403 Forbidden\r\n\r\n");
      socket.destroy();
      return;
    }

    wss.handleUpgrade(req, socket, head, (ws) => {
      ws.user = req.session.user;
      ws.room = "lobby";
      wss.emit("connection", ws);
    });
  });
});

function parseDurationSec(input) {
  const v = String(input || "perm");
  if (v === "perm") return null;
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) return null;
  return Math.floor(n);
}

app.post("/api/admin/punish", requireAdminPanel, async (req, res) => {
  const { username, action, durationSec, reason = "" } = req.body || {};
  if (!username || !action) return res.status(400).json({ error: "missing_fields" });

  const target = await pool.query(`SELECT id, role FROM users WHERE username=$1`, [String(username).trim()]);
  if (target.rowCount === 0) return res.status(404).json({ error: "not_found" });
  if (target.rows[0].role === "admin") return res.status(403).json({ error: "cannot_punish_admin" });

  const userId = Number(target.rows[0].id);
  const dur = parseDurationSec(durationSec);
  const until_ts = dur === null ? null : nowSec() + dur;

  if (action === "ban" || action === "mute") {
    await pool.query(
      `UPDATE punishments SET active=FALSE WHERE user_id=$1 AND type=$2 AND active=TRUE`,
      [userId, action]
    );
    await pool.query(
      `INSERT INTO punishments (user_id, type, reason, until_ts, created_by, active)
       VALUES ($1,$2,$3,$4,$5,TRUE)`,
      [userId, action, String(reason).slice(0, 200), until_ts, req.session.user.id]
    );

    if (action === "ban") kickUser(String(username).trim(), "banned");
    if (action === "mute") sendToUser(String(username).trim(), { type: "system", event: "muted_set", until_ts, reason: String(reason).slice(0, 200) });

    return res.json({ ok: true });
  }

  if (action === "unban") {
    await pool.query(`UPDATE punishments SET active=FALSE WHERE user_id=$1 AND type='ban' AND active=TRUE`, [userId]);
    return res.json({ ok: true });
  }

  if (action === "unmute") {
    await pool.query(`UPDATE punishments SET active=FALSE WHERE user_id=$1 AND type='mute' AND active=TRUE`, [userId]);
    sendToUser(String(username).trim(), { type: "system", event: "unmuted" });
    return res.json({ ok: true });
  }

  if (action === "kick") {
    kickUser(String(username).trim(), String(reason).slice(0, 200) || "kicked");
    return res.json({ ok: true });
  }

  return res.status(400).json({ error: "bad_action" });
});

app.post("/api/admin/force-room", requireAdminPanel, async (req, res) => {
  const { username, room } = req.body || {};
  if (!username || !room) return res.status(400).json({ error: "missing_fields" });

  const target = await pool.query(`SELECT id, role FROM users WHERE username=$1`, [String(username).trim()]);
  if (target.rowCount === 0) return res.status(404).json({ error: "not_found" });
  if (target.rows[0].role === "admin") return res.status(403).json({ error: "cannot_force_admin" });

  const r = safeRoom(room);
  sendToUser(String(username).trim(), { type: "system", event: "force_room", room: r });
  for (const client of wss.clients) {
    if (client.readyState === 1 && client.user?.username === String(username).trim()) {
      client.room = r;
      try { client.send(JSON.stringify({ type: "joined", room: r })); } catch {}
    }
  }
  res.json({ ok: true, room: r });
});

function cleanAdminHtml(input) {
  const raw = String(input || "").slice(0, 2000);
  return sanitizeHtml(raw, {
    allowedTags: ["b", "i", "u", "em", "strong", "br", "a", "code"],
    allowedAttributes: {
      a: ["href", "target", "rel"]
    },
    transformTags: {
      a: sanitizeHtml.simpleTransform("a", { target: "_blank", rel: "noopener noreferrer" })
    },
    allowedSchemes: ["http", "https", "mailto"]
  });
}

app.post("/api/admin/announce", requireAdminPanel, async (req, res) => {
  const { room = "lobby", mode = "text", content = "" } = req.body || {};
  const r = safeRoom(room);

  let payload = { type: "system", event: "admin_announce", room: r, mode: "text", content: "" };

  if (mode === "html") {
    payload.mode = "html";
    payload.content = cleanAdminHtml(content);
  } else {
    payload.content = String(content || "").slice(0, 800);
  }

  broadcastToRoom(r, payload);
  res.json({ ok: true });
});

wss.on("connection", (ws) => {
  ws.send(JSON.stringify({ type: "hello", user: ws.user, room: ws.room }));

  ws.on("message", async (raw) => {
    let data;
    try { data = JSON.parse(String(raw)); } catch { return; }

    if (data.type === "join") {
      ws.room = safeRoom(data.room);
      ws.send(JSON.stringify({ type: "joined", room: ws.room }));
      return;
    }

    if (data.type === "chat") {
      const text = String(data.text || "").trim();
      if (!text || text.length > 500) return;

      const punish = await getPunishmentFlags(ws.user.id);
      if (punish.banned) {
        try { ws.send(JSON.stringify({ type: "system", event: "banned" })); } catch {}
        try { ws.close(); } catch {}
        return;
      }
      if (punish.muted) {
        ws.send(JSON.stringify({ type: "system", event: "muted", until_ts: punish.mute?.until_ts ?? null, reason: punish.mute?.reason ?? "" }));
        return;
      }

      const ins = await pool.query(
        `INSERT INTO messages (room, content, author_id) VALUES ($1,$2,$3) RETURNING id, created_at`,
        [ws.room, text, ws.user.id]
      );

      const msgId = Number(ins.rows[0].id);
      const r = await pool.query(
        `SELECT m.id, m.room, m.content, m.created_at,
                u.username AS author, u.avatar AS avatar, u.role AS role
         FROM messages m
         JOIN users u ON u.id = m.author_id
         WHERE m.id=$1`,
        [msgId]
      );

      broadcastToRoom(ws.room, { type: "message", message: r.rows[0] });
    }
  });
});

const PORT = process.env.PORT || 3000;

initDb()
  .then(() => {
    server.listen(PORT, "0.0.0.0", () => console.log(`Server running: http://localhost:${PORT}`));
  })
  .catch((e) => {
    console.error("DB init failed:", e);
    process.exit(1);
  });
