import express from "express";
import session from "express-session";
import pg from "pg";
import bcrypt from "bcryptjs";
import http from "http";
import path from "path";
import helmet from "helmet";
import { WebSocketServer } from "ws";
import connectPgSimple from "connect-pg-simple";
import { fileURLToPath } from "url";

const { Pool } = pg;
const PgSession = connectPgSimple(session);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const isProd = process.env.NODE_ENV === "production";
const PORT = Number(process.env.PORT || 3000);

if (!process.env.DATABASE_URL) {
  console.error("Missing DATABASE_URL");
  process.exit(1);
}
if (!process.env.SESSION_SECRET) {
  console.error("Missing SESSION_SECRET (set it in Render Environment)");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: isProd ? { rejectUnauthorized: false } : false
});

const app = express();
app.set("trust proxy", 1);

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "256kb" }));
app.use(express.urlencoded({ extended: false }));

function cryptoRandom(n = 32) {
  const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let out = "";
  for (let i = 0; i < n; i++) out += chars[Math.floor(Math.random() * chars.length)];
  return out;
}

function esc(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function sanitizeHtml(input) {
  let s = String(input ?? "");
  s = s.replace(/<\s*(script|style)[^>]*>[\s\S]*?<\s*\/\s*\1\s*>/gi, "");
  s = s.replace(/on\w+\s*=\s*(".*?"|'.*?'|[^\s>]+)/gi, "");
  s = s.replace(/javascript:/gi, "");

  const allowed = new Set(["b", "i", "u", "br", "a", "code"]);
  s = s.replace(/<\/?([a-z0-9]+)(\s[^>]*)?>/gi, (m, tag, attrs) => {
    const t = String(tag || "").toLowerCase();
    const isClose = m.trim().startsWith("</");
    if (!allowed.has(t)) return esc(m);

    if (t === "br") return "<br>";

    if (t === "a") {
      if (isClose) return "</a>";
      const a = String(attrs || "");
      const hrefMatch = a.match(/href\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))/i);
      let href = hrefMatch ? (hrefMatch[2] || hrefMatch[3] || hrefMatch[4] || "") : "";
      href = href.trim();
      if (!href) return "<a>";
      if (/^javascript:/i.test(href)) href = "";
      if (!/^https?:\/\//i.test(href) && !href.startsWith("/")) href = "";
      return href
        ? `<a href="${esc(href)}" target="_blank" rel="noopener noreferrer">`
        : "<a>";
    }

    return isClose ? `</${t}>` : `<${t}>`;
  });

  return s;
}

function hashPw(pw) {
  return bcrypt.hashSync(String(pw), 10);
}
function verifyPw(pw, hash) {
  try {
    return bcrypt.compareSync(String(pw), String(hash));
  } catch {
    return false;
  }
}

function cleanUsername(u) {
  const s = String(u || "").trim();
  if (s.length < 3) return null;
  if (s.length > 24) return null;
  if (!/^[a-zA-Z0-9_]+$/.test(s)) return null;
  return s;
}

function safeRoom(input) {
  const room = String(input || "lobby")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_-]/g, "")
    .slice(0, 32);
  return room || "lobby";
}

async function q(sql, params = []) {
  return pool.query(sql, params);
}

function saveSession(req) {
  return new Promise((resolve, reject) => {
    req.session.save((err) => (err ? reject(err) : resolve()));
  });
}
function regenerateSession(req) {
  return new Promise((resolve, reject) => {
    req.session.regenerate((err) => (err ? reject(err) : resolve()));
  });
}

/* ===== Sessions ===== */
const sessionParser = session({
  name: "chatly.sid",
  store: new PgSession({
    pool,
    tableName: "user_sessions",
    createTableIfMissing: true
  }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: isProd,
    maxAge: 1000 * 60 * 60 * 24 * 14
  }
});

app.use(sessionParser);

/* ===== Static ===== */
app.use(express.static(path.join(__dirname, "public")));

/* ===== Auth guards ===== */
function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "not_logged_in" });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "not_logged_in" });
  if (req.session.user.role !== "admin") return res.status(403).json({ error: "not_admin" });
  next();
}
function requireAdminUnlocked(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "not_logged_in" });
  if (req.session.user.role !== "admin") return res.status(403).json({ error: "not_admin" });
  if (!req.session.adminPanelUnlocked) return res.status(403).json({ error: "admin_panel_locked" });
  next();
}

/* ===== Presence maps ===== */
const online = new Map(); // userId -> { userId, username, role, avatar, status, lastSeen }
const userSockets = new Map(); // userId -> Set(ws)
const roomSockets = new Map(); // room -> Set(ws)
const rateWindow = new Map(); // userId -> timestamps

function touchOnline(row) {
  const id = String(row.id);
  online.set(id, {
    userId: Number(row.id),
    username: row.username,
    role: row.role,
    avatar: row.avatar || "",
    status: row.status || "online",
    lastSeen: Date.now()
  });
}

function safeSend(ws, obj) {
  try {
    if (ws.readyState === 1) ws.send(JSON.stringify(obj));
  } catch {}
}

function addUserSocket(userId, ws) {
  const k = String(userId);
  if (!userSockets.has(k)) userSockets.set(k, new Set());
  userSockets.get(k).add(ws);
}
function removeUserSocket(userId, ws) {
  const k = String(userId);
  const set = userSockets.get(k);
  if (!set) return;
  set.delete(ws);
  if (set.size === 0) userSockets.delete(k);
}

function joinRoom(ws, room) {
  const r = safeRoom(room);
  leaveRoom(ws);
  ws.room = r;
  if (!roomSockets.has(r)) roomSockets.set(r, new Set());
  roomSockets.get(r).add(ws);
  safeSend(ws, { type: "joined", room: r });
}
function leaveRoom(ws) {
  const r = ws.room;
  if (!r) return;
  const set = roomSockets.get(r);
  if (!set) return;
  set.delete(ws);
  if (set.size === 0) roomSockets.delete(r);
}
function broadcastRoom(room, obj, exceptWs = null) {
  const r = safeRoom(room);
  const set = roomSockets.get(r);
  if (!set) return;
  for (const ws of set) {
    if (exceptWs && ws === exceptWs) continue;
    safeSend(ws, obj);
  }
}
function sendToUser(userId, obj) {
  const set = userSockets.get(String(userId));
  if (!set) return;
  for (const ws of set) safeSend(ws, obj);
}

/* ===== Automod helpers ===== */
function escapeRegex(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
function hitRateLimit(userId, maxPer10s) {
  const k = String(userId);
  const now = Date.now();
  if (!rateWindow.has(k)) rateWindow.set(k, []);
  const arr = rateWindow.get(k);
  while (arr.length && now - arr[0] > 10000) arr.shift();
  arr.push(now);
  return arr.length > maxPer10s;
}
function applyBadWords(mode, blacklist, text) {
  if (mode === "off") return { ok: true, text };
  const list = (blacklist || []).map((w) => String(w).trim()).filter(Boolean);
  if (!list.length) return { ok: true, text };
  let out = String(text);
  for (const w of list) {
    const re = new RegExp(`\\b${escapeRegex(w)}\\b`, "gi");
    if (mode === "strict" && re.test(out)) return { ok: false, text: "" };
    if (mode === "soft") out = out.replace(re, "•".repeat(Math.min(12, w.length || 3)));
  }
  return { ok: true, text: out };
}

/* ===== DB helpers ===== */
async function getUserByUsername(username) {
  const r = await q(`SELECT * FROM users WHERE username=$1`, [username]);
  return r.rowCount ? r.rows[0] : null;
}
async function ensureRoom(name) {
  const n = safeRoom(name);
  await q(
    `INSERT INTO rooms(name, category, rules) VALUES ($1,'General','')
     ON CONFLICT(name) DO NOTHING`,
    [n]
  );
  return n;
}
async function getAutomod(room) {
  const r = await q(`SELECT * FROM automod_settings WHERE room=$1`, [safeRoom(room)]);
  if (!r.rowCount) return { rate_max: 8, bad_words_mode: "off", blacklist: [] };
  return r.rows[0];
}
function parseDurationSec(input) {
  const v = String(input || "perm").trim().toLowerCase();
  if (v === "perm") return null;
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) return null;
  return Math.min(60 * 60 * 24 * 30, Math.floor(n));
}
async function punishFlags(userId) {
  const r = await q(`SELECT banned_until, muted_until FROM users WHERE id=$1`, [userId]);
  if (!r.rowCount) return { banned: false, muted: false, bannedUntil: null, mutedUntil: null };
  const b = r.rows[0].banned_until ? new Date(r.rows[0].banned_until) : null;
  const m = r.rows[0].muted_until ? new Date(r.rows[0].muted_until) : null;
  const now = new Date();
  return {
    banned: !!(b && b > now),
    muted: !!(m && m > now),
    bannedUntil: b,
    mutedUntil: m
  };
}

/* ===== Bots ===== */
async function getBotsForRoom(room) {
  const r = await q(
    `SELECT name, commands, enabled FROM bots WHERE room=$1 AND enabled=TRUE`,
    [safeRoom(room)]
  );
  return r.rows || [];
}
async function tryBotCommand(room, text) {
  if (!text || !text.startsWith("!")) return null;
  const bots = await getBotsForRoom(room);
  const cmd = text.trim().split(/\s+/)[0].toLowerCase();
  for (const b of bots) {
    const commands = b.commands || {};
    const val = commands[cmd] || commands[cmd.toUpperCase()] || null;
    if (!val) continue;
    const reply = typeof val === "string" ? val : (val.reply || "");
    if (!reply) continue;
    return { botName: b.name, reply: String(reply).slice(0, 800) };
  }
  return null;
}

/* ===== MIGRATIONS (create + alter) ===== */
async function migrate() {
  await q(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      pass_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user'
    );
  `);

  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS bio TEXT NOT NULL DEFAULT '';`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar TEXT NOT NULL DEFAULT '';`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'online';`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS banned_until TIMESTAMPTZ NULL;`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS muted_until TIMESTAMPTZ NULL;`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS needs_password_change BOOLEAN NOT NULL DEFAULT FALSE;`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS admin_panel_hash TEXT NULL;`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS admin_panel_needs_setup BOOLEAN NOT NULL DEFAULT FALSE;`);

  await q(`
    CREATE TABLE IF NOT EXISTS rooms (
      name TEXT PRIMARY KEY,
      category TEXT NOT NULL DEFAULT 'General',
      rules TEXT NOT NULL DEFAULT '',
      password_hash TEXT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS messages (
      id BIGSERIAL PRIMARY KEY,
      room TEXT NOT NULL REFERENCES rooms(name) ON DELETE CASCADE,
      author_id BIGINT NULL REFERENCES users(id) ON DELETE SET NULL,
      author_name TEXT NOT NULL,
      author_role TEXT NOT NULL DEFAULT 'user',
      avatar TEXT NOT NULL DEFAULT '',
      content TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      deleted BOOLEAN NOT NULL DEFAULT FALSE
    );
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS moderation_logs (
      id BIGSERIAL PRIMARY KEY,
      admin_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      action TEXT NOT NULL,
      target_id BIGINT NULL REFERENCES users(id) ON DELETE SET NULL,
      target_name TEXT NOT NULL DEFAULT '',
      room TEXT NOT NULL DEFAULT '',
      reason TEXT NOT NULL DEFAULT '',
      meta JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS friends (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      other_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      status TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(user_id, other_id)
    );
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS dm_threads (
      id BIGSERIAL PRIMARY KEY,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS dm_members (
      thread_id BIGINT NOT NULL REFERENCES dm_threads(id) ON DELETE CASCADE,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      PRIMARY KEY(thread_id, user_id)
    );
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS dm_messages (
      id BIGSERIAL PRIMARY KEY,
      thread_id BIGINT NOT NULL REFERENCES dm_threads(id) ON DELETE CASCADE,
      author_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      content TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS bots (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      room TEXT NOT NULL REFERENCES rooms(name) ON DELETE CASCADE,
      enabled BOOLEAN NOT NULL DEFAULT TRUE,
      commands JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_by BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(name, room)
    );
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS automod_settings (
      room TEXT PRIMARY KEY REFERENCES rooms(name) ON DELETE CASCADE,
      rate_max INT NOT NULL DEFAULT 8,
      bad_words_mode TEXT NOT NULL DEFAULT 'off',
      blacklist TEXT[] NOT NULL DEFAULT '{}'::text[],
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS message_reactions (
      id BIGSERIAL PRIMARY KEY,
      message_id BIGINT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      emoji TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(message_id, user_id, emoji)
    );
  `);

  await q(`INSERT INTO rooms(name, category, rules) VALUES ('lobby','General','') ON CONFLICT(name) DO NOTHING;`);
  await q(`INSERT INTO rooms(name, category, rules) VALUES ('general','General','') ON CONFLICT(name) DO NOTHING;`);
  await q(`INSERT INTO rooms(name, category, rules) VALUES ('help','Support','') ON CONFLICT(name) DO NOTHING;`);

  const adminUser = process.env.ADMIN_USERNAME || "admin";
  const adminExists = await q(`SELECT id FROM users WHERE username=$1`, [adminUser]);
  if (adminExists.rowCount === 0) {
    const bootstrap = process.env.ADMIN_BOOTSTRAP_PASSWORD || cryptoRandom(18);
    await q(
      `INSERT INTO users (username, pass_hash, bio, role, needs_password_change, admin_panel_hash, admin_panel_needs_setup)
       VALUES ($1,$2,$3,'admin',TRUE,$4,TRUE)`,
      [adminUser, hashPw(bootstrap), "Master Administrator", hashPw("admin12")]
    );
    console.log(`Created admin: ${adminUser} / ${bootstrap}`);
    console.log(`Admin must run setup immediately.`);
  }
}

/* ===== API ===== */
app.get("/health", (req, res) => res.status(200).send("ok"));

app.get("/api/me", async (req, res) => {
  if (!req.session.user) return res.json({ user: null, flags: null });

  const u = await q(`SELECT * FROM users WHERE id=$1`, [req.session.user.id]);
  if (!u.rowCount) {
    req.session.destroy(() => {});
    return res.json({ user: null, flags: null });
  }
  const row = u.rows[0];

  req.session.user = { id: Number(row.id), username: row.username, role: row.role };
  const flags = {
    adminPanelUnlocked: !!req.session.adminPanelUnlocked,
    needsPasswordChange: !!row.needs_password_change,
    adminPanelNeedsSetup: !!row.admin_panel_needs_setup
  };
  return res.json({ user: req.session.user, flags });
});

app.post("/api/register", async (req, res) => {
  const body = req.body || {};
  const username = body.username;
  const password = body.password;
  const bio = body.bio ?? "";
  const avatar = body.avatar ?? "";

  const clean = cleanUsername(username);
  if (!clean) return res.status(400).json({ error: "username_invalid" });
  if (!password || String(password).length < 4) return res.status(400).json({ error: "password_short" });

  try {
    const r = await q(
      `INSERT INTO users (username, pass_hash, bio, avatar, role)
       VALUES ($1,$2,$3,$4,'user') RETURNING id, role`,
      [clean, hashPw(password), String(bio).slice(0, 220), String(avatar).slice(0, 320)]
    );

    await regenerateSession(req);
    req.session.user = { id: Number(r.rows[0].id), username: clean, role: r.rows[0].role };
    req.session.adminPanelUnlocked = false;
    await saveSession(req);

    res.json({ ok: true, user: req.session.user });
  } catch (e) {
    if (String(e).includes("duplicate key")) return res.status(409).json({ error: "username_taken" });
    res.status(500).json({ error: "server_error" });
  }
});

app.post("/api/login", async (req, res) => {
  const body = req.body || {};
  const username = body.username;
  const password = body.password;

  if (!username || !password) return res.status(400).json({ error: "missing_fields" });

  const u = await getUserByUsername(String(username).trim());
  if (!u) return res.status(401).json({ error: "bad_login" });
  if (!verifyPw(password, u.pass_hash)) return res.status(401).json({ error: "bad_login" });

  const p = await punishFlags(Number(u.id));
  if (p.banned) return res.status(403).json({ error: "banned" });

  await regenerateSession(req);
  req.session.user = { id: Number(u.id), username: u.username, role: u.role };
  req.session.adminPanelUnlocked = false;
  await saveSession(req);

  const flags = {
    adminPanelUnlocked: false,
    needsPasswordChange: !!u.needs_password_change,
    adminPanelNeedsSetup: !!u.admin_panel_needs_setup
  };

  touchOnline(u);
  res.json({ ok: true, user: req.session.user, flags });
});

app.post("/api/logout", requireAuth, async (req, res) => {
  req.session.destroy(() => {});
  res.json({ ok: true });
});

app.get("/api/profile/:username", async (req, res) => {
  const raw = String(req.params.username || "").trim();
  const clean = cleanUsername(raw) || raw;
  const u = await getUserByUsername(clean);
  if (!u) return res.status(404).json({ error: "not_found" });

  res.json({
    ok: true,
    profile: {
      id: Number(u.id),
      username: u.username,
      role: u.role,
      bio: u.bio || "",
      avatar: u.avatar || "",
      status: u.status || "online",
      created_at: u.created_at
    }
  });
});

app.post("/api/profile", requireAuth, async (req, res) => {
  const { bio = "", avatar = "" } = req.body || {};
  await q(`UPDATE users SET bio=$1, avatar=$2 WHERE id=$3`, [
    String(bio).slice(0, 220),
    String(avatar).slice(0, 320),
    req.session.user.id
  ]);
  res.json({ ok: true });
});

app.post("/api/change-password", requireAuth, async (req, res) => {
  const { oldPassword, newPassword } = req.body || {};
  if (!oldPassword || !newPassword) return res.status(400).json({ error: "missing_fields" });
  if (String(newPassword).length < 4) return res.status(400).json({ error: "password_short" });

  const r = await q(`SELECT pass_hash FROM users WHERE id=$1`, [req.session.user.id]);
  if (!r.rowCount) return res.status(500).json({ error: "server_error" });
  if (!verifyPw(oldPassword, r.rows[0].pass_hash)) return res.status(401).json({ error: "bad_login" });

  await q(`UPDATE users SET pass_hash=$1, needs_password_change=FALSE WHERE id=$2`, [
    hashPw(newPassword),
    req.session.user.id
  ]);

  res.json({ ok: true });
});

/* Messages */
app.get("/api/messages", requireAuth, async (req, res) => {
  const room = safeRoom(req.query.room || "lobby");
  const limit = Math.max(1, Math.min(200, Number(req.query.limit || 120)));

  await ensureRoom(room);

  const r = await q(
    `SELECT id, room, author_name, author_role, avatar, content, created_at
     FROM messages
     WHERE room=$1 AND deleted=FALSE
     ORDER BY id DESC
     LIMIT $2`,
    [room, limit]
  );

  const messages = (r.rows || []).reverse().map((m) => ({
    id: Number(m.id),
    room: m.room,
    author: m.author_name,
    role: m.author_role,
    avatar: m.avatar,
    content: m.content,
    created_at: new Date(m.created_at).toLocaleString()
  }));

  res.json({ ok: true, room, messages });
});

app.delete("/api/messages/:id", requireAuth, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isFinite(id) || id <= 0) return res.status(400).json({ error: "bad_id" });

  const m = await q(`SELECT author_id, room FROM messages WHERE id=$1`, [id]);
  if (!m.rowCount) return res.status(404).json({ error: "not_found" });

  const authorId = m.rows[0].author_id ? Number(m.rows[0].author_id) : null;
  const isAdminUnlocked = req.session.user.role === "admin" && !!req.session.adminPanelUnlocked;

  if (!isAdminUnlocked && authorId !== Number(req.session.user.id)) {
    return res.status(403).json({ error: "forbidden" });
  }

  await q(`UPDATE messages SET deleted=TRUE WHERE id=$1`, [id]);
  broadcastRoom(m.rows[0].room, { type: "system", event: "message_deleted", messageId: id });
  res.json({ ok: true });
});

/* Presence / Online */
app.get("/api/online", requireAuth, async (req, res) => {
  const list = Array.from(online.values())
    .filter((x) => Date.now() - x.lastSeen < 1000 * 60 * 5)
    .sort((a, b) => a.username.localeCompare(b.username))
    .slice(0, 200);
  res.json({ ok: true, online: list });
});

app.post("/api/status", requireAuth, async (req, res) => {
  const { status } = req.body || {};
  const allowed = new Set(["online", "away", "dnd", "offline"]);
  const s = allowed.has(String(status)) ? String(status) : "online";
  await q(`UPDATE users SET status=$1 WHERE id=$2`, [s, req.session.user.id]);

  const u = await q(`SELECT id, username, role, avatar, status FROM users WHERE id=$1`, [req.session.user.id]);
  if (u.rowCount) touchOnline(u.rows[0]);

  res.json({ ok: true, status: s });
});

/* Friends */
app.get("/api/friends/list", requireAuth, async (req, res) => {
  const id = Number(req.session.user.id);
  const r = await q(
    `SELECT f.status, u.username, u.avatar, u.role
     FROM friends f
     JOIN users u ON u.id=f.other_id
     WHERE f.user_id=$1
     ORDER BY u.username`,
    [id]
  );
  res.json({ ok: true, items: r.rows || [] });
});

app.post("/api/friends/request", requireAuth, async (req, res) => {
  const { username } = req.body || {};
  const clean = cleanUsername(username);
  if (!clean) return res.status(400).json({ error: "username_invalid" });

  const meId = Number(req.session.user.id);
  const other = await getUserByUsername(clean);
  if (!other) return res.status(404).json({ error: "not_found" });

  const otherId = Number(other.id);
  if (otherId === meId) return res.status(400).json({ error: "bad_request" });

  await q(
    `INSERT INTO friends(user_id, other_id, status)
     VALUES ($1,$2,'pending')
     ON CONFLICT(user_id, other_id) DO UPDATE SET status='pending'`,
    [meId, otherId]
  );
  await q(
    `INSERT INTO friends(user_id, other_id, status)
     VALUES ($1,$2,'incoming')
     ON CONFLICT(user_id, other_id) DO UPDATE SET status='incoming'`,
    [otherId, meId]
  );

  res.json({ ok: true });
});

app.post("/api/friends/accept", requireAuth, async (req, res) => {
  const { username } = req.body || {};
  const clean = cleanUsername(username);
  if (!clean) return res.status(400).json({ error: "username_invalid" });

  const meId = Number(req.session.user.id);
  const other = await getUserByUsername(clean);
  if (!other) return res.status(404).json({ error: "not_found" });

  const otherId = Number(other.id);

  await q(`UPDATE friends SET status='accepted' WHERE user_id=$1 AND other_id=$2`, [meId, otherId]);
  await q(`UPDATE friends SET status='accepted' WHERE user_id=$1 AND other_id=$2`, [otherId, meId]);

  res.json({ ok: true });
});

app.post("/api/friends/block", requireAuth, async (req, res) => {
  const { username } = req.body || {};
  const clean = cleanUsername(username);
  if (!clean) return res.status(400).json({ error: "username_invalid" });

  const meId = Number(req.session.user.id);
  const other = await getUserByUsername(clean);
  if (!other) return res.status(404).json({ error: "not_found" });

  const otherId = Number(other.id);

  await q(
    `INSERT INTO friends(user_id, other_id, status)
     VALUES ($1,$2,'blocked')
     ON CONFLICT(user_id, other_id) DO UPDATE SET status='blocked'`,
    [meId, otherId]
  );

  res.json({ ok: true });
});

/* DMs */
async function findOrCreateDmThread(aId, bId) {
  const r = await q(
    `SELECT m1.thread_id
     FROM dm_members m1
     JOIN dm_members m2 ON m1.thread_id=m2.thread_id
     WHERE m1.user_id=$1 AND m2.user_id=$2
     LIMIT 1`,
    [aId, bId]
  );
  if (r.rowCount) return Number(r.rows[0].thread_id);

  const t = await q(`INSERT INTO dm_threads DEFAULT VALUES RETURNING id`);
  const tid = Number(t.rows[0].id);
  await q(`INSERT INTO dm_members(thread_id, user_id) VALUES ($1,$2),($1,$3)`, [tid, aId, bId]);
  return tid;
}

app.post("/api/dm/start", requireAuth, async (req, res) => {
  const { username } = req.body || {};
  const clean = cleanUsername(username);
  if (!clean) return res.status(400).json({ error: "username_invalid" });

  const meId = Number(req.session.user.id);
  const other = await getUserByUsername(clean);
  if (!other) return res.status(404).json({ error: "not_found" });

  const threadId = await findOrCreateDmThread(meId, Number(other.id));
  res.json({ ok: true, threadId });
});

app.get("/api/dm/list", requireAuth, async (req, res) => {
  const meId = Number(req.session.user.id);
  const r = await q(
    `SELECT t.id AS thread_id, u.username, u.avatar, u.role
     FROM dm_threads t
     JOIN dm_members m1 ON m1.thread_id=t.id AND m1.user_id=$1
     JOIN dm_members m2 ON m2.thread_id=t.id AND m2.user_id<>$1
     JOIN users u ON u.id=m2.user_id
     ORDER BY t.id DESC
     LIMIT 80`,
    [meId]
  );
  res.json({ ok: true, items: r.rows || [] });
});

app.get("/api/dm/:threadId/messages", requireAuth, async (req, res) => {
  const meId = Number(req.session.user.id);
  const threadId = Number(req.params.threadId);
  if (!Number.isFinite(threadId) || threadId <= 0) return res.status(400).json({ error: "bad_id" });

  const member = await q(`SELECT 1 FROM dm_members WHERE thread_id=$1 AND user_id=$2`, [threadId, meId]);
  if (!member.rowCount) return res.status(403).json({ error: "forbidden" });

  const r = await q(
    `SELECT m.id, m.content, m.created_at, u.username AS author, u.avatar
     FROM dm_messages m
     JOIN users u ON u.id=m.author_id
     WHERE m.thread_id=$1
     ORDER BY m.id DESC
     LIMIT 200`,
    [threadId]
  );

  const messages = (r.rows || []).reverse().map((x) => ({
    id: Number(x.id),
    author: x.author,
    avatar: x.avatar || "",
    content: x.content,
    created_at: new Date(x.created_at).toLocaleString()
  }));

  res.json({ ok: true, threadId, messages });
});

app.post("/api/dm/:threadId/send", requireAuth, async (req, res) => {
  const meId = Number(req.session.user.id);
  const threadId = Number(req.params.threadId);
  const { content } = req.body || {};
  const text = String(content || "").trim();
  if (!text) return res.status(400).json({ error: "missing_fields" });

  const member = await q(`SELECT 1 FROM dm_members WHERE thread_id=$1 AND user_id=$2`, [threadId, meId]);
  if (!member.rowCount) return res.status(403).json({ error: "forbidden" });

  const ins = await q(
    `INSERT INTO dm_messages(thread_id, author_id, content) VALUES ($1,$2,$3) RETURNING id, created_at`,
    [threadId, meId, text.slice(0, 900)]
  );

  const other = await q(
    `SELECT user_id FROM dm_members WHERE thread_id=$1 AND user_id<>$2 LIMIT 1`,
    [threadId, meId]
  );
  if (other.rowCount) {
    sendToUser(Number(other.rows[0].user_id), {
      type: "dm",
      threadId,
      message: {
        id: Number(ins.rows[0].id),
        author: req.session.user.username,
        content: text.slice(0, 900),
        created_at: new Date(ins.rows[0].created_at).toLocaleString()
      }
    });
  }

  res.json({ ok: true });
});

/* Admin */
app.post("/api/admin/setup", requireAdmin, async (req, res) => {
  const { currentLoginPassword, newLoginPassword, newAdminPanelPassword } = req.body || {};
  if (!currentLoginPassword || !newLoginPassword || !newAdminPanelPassword) {
    return res.status(400).json({ error: "missing_fields" });
  }
  if (String(newLoginPassword).length < 6) return res.status(400).json({ error: "password_short" });
  if (String(newAdminPanelPassword).length < 6) return res.status(400).json({ error: "password_short" });

  const r = await q(
    `SELECT pass_hash, needs_password_change, admin_panel_needs_setup FROM users WHERE id=$1`,
    [req.session.user.id]
  );
  if (!r.rowCount) return res.status(500).json({ error: "server_error" });

  const u = r.rows[0];
  if (!u.needs_password_change && !u.admin_panel_needs_setup) {
    return res.status(403).json({ error: "setup_not_required" });
  }
  if (!verifyPw(currentLoginPassword, u.pass_hash)) return res.status(401).json({ error: "bad_login" });

  await q(
    `UPDATE users
     SET pass_hash=$1, needs_password_change=FALSE, admin_panel_hash=$2, admin_panel_needs_setup=FALSE
     WHERE id=$3`,
    [hashPw(newLoginPassword), hashPw(newAdminPanelPassword), req.session.user.id]
  );

  req.session.adminPanelUnlocked = false;
  await saveSession(req);

  res.json({ ok: true });
});

app.post("/api/admin/panel/unlock", requireAdmin, async (req, res) => {
  const { adminPanelPassword } = req.body || {};
  if (!adminPanelPassword) return res.status(400).json({ error: "missing_fields" });

  const r = await q(`SELECT admin_panel_hash, admin_panel_needs_setup FROM users WHERE id=$1`, [req.session.user.id]);
  if (!r.rowCount) return res.status(500).json({ error: "server_error" });
  if (r.rows[0].admin_panel_needs_setup) return res.status(403).json({ error: "admin_panel_needs_setup" });

  if (!verifyPw(adminPanelPassword, r.rows[0].admin_panel_hash)) {
    return res.status(401).json({ error: "admin_panel_bad_password" });
  }

  req.session.adminPanelUnlocked = true;
  await saveSession(req);

  res.json({ ok: true });
});

app.post("/api/admin/panel/lock", requireAdmin, async (req, res) => {
  req.session.adminPanelUnlocked = false;
  await saveSession(req);
  res.json({ ok: true });
});

app.post("/api/admin/announce", requireAdminUnlocked, async (req, res) => {
  const { room, mode, content } = req.body || {};
  const r = safeRoom(room || "lobby");
  const m = mode === "html" ? "html" : "text";
  const c = m === "html" ? sanitizeHtml(content || "") : String(content || "");

  broadcastRoom(r, { type: "system", event: "admin_announce", room: r, mode: m, content: c });

  await q(
    `INSERT INTO moderation_logs(admin_id, action, room, reason, meta)
     VALUES ($1,'announce',$2,'', $3::jsonb)`,
    [req.session.user.id, r, JSON.stringify({ mode: m })]
  );

  res.json({ ok: true });
});

app.post("/api/admin/punish", requireAdminUnlocked, async (req, res) => {
  const { username, action, durationSec, reason = "" } = req.body || {};
  const clean = cleanUsername(username);
  if (!clean) return res.status(400).json({ error: "username_invalid" });

  const target = await getUserByUsername(clean);
  if (!target) return res.status(404).json({ error: "not_found" });
  if (target.role === "admin") return res.status(403).json({ error: "cannot_punish_admin" });

  const act = String(action || "");
  const dur = parseDurationSec(durationSec);
  const now = new Date();
  const until = dur ? new Date(now.getTime() + dur * 1000) : null;

  if (!["ban", "unban", "mute", "unmute", "kick"].includes(act)) {
    return res.status(400).json({ error: "bad_action" });
  }

  if (act === "ban") {
    await q(`UPDATE users SET banned_until=$1 WHERE id=$2`, [
      until || new Date(now.getTime() + 1000 * 60 * 60 * 24 * 365),
      target.id
    ]);
  }
  if (act === "unban") await q(`UPDATE users SET banned_until=NULL WHERE id=$1`, [target.id]);
  if (act === "mute") {
    await q(`UPDATE users SET muted_until=$1 WHERE id=$2`, [
      until || new Date(now.getTime() + 1000 * 60 * 60 * 24 * 365),
      target.id
    ]);
  }
  if (act === "unmute") await q(`UPDATE users SET muted_until=NULL WHERE id=$1`, [target.id]);

  await q(
    `INSERT INTO moderation_logs(admin_id, action, target_id, target_name, reason, meta)
     VALUES ($1,$2,$3,$4,$5,$6::jsonb)`,
    [
      req.session.user.id,
      act,
      target.id,
      target.username,
      String(reason).slice(0, 220),
      JSON.stringify({ durationSec: dur ?? "perm" })
    ]
  );

  if (act === "kick") sendToUser(Number(target.id), { type: "system", event: "kick" });
  if (act === "ban") sendToUser(Number(target.id), { type: "system", event: "banned" });
  if (act === "mute") sendToUser(Number(target.id), { type: "system", event: "muted_set", until_ts: until ? Math.floor(until.getTime() / 1000) : null });
  if (act === "unmute") sendToUser(Number(target.id), { type: "system", event: "unmuted" });

  res.json({ ok: true });
});

app.post("/api/admin/force-room", requireAdminUnlocked, async (req, res) => {
  const { username, room } = req.body || {};
  const clean = cleanUsername(username);
  if (!clean) return res.status(400).json({ error: "username_invalid" });

  const target = await getUserByUsername(clean);
  if (!target) return res.status(404).json({ error: "not_found" });
  if (target.role === "admin") return res.status(403).json({ error: "cannot_force_admin" });

  const r = await ensureRoom(room || "lobby");

  await q(
    `INSERT INTO moderation_logs(admin_id, action, target_id, target_name, room, meta)
     VALUES ($1,'force_room',$2,$3,$4,$5::jsonb)`,
    [req.session.user.id, target.id, target.username, r, JSON.stringify({})]
  );

  sendToUser(Number(target.id), { type: "system", event: "force_room", room: r });
  res.json({ ok: true, room: r });
});

app.post("/api/admin/change-user-password", requireAdminUnlocked, async (req, res) => {
  const { username, newPassword } = req.body || {};
  const clean = cleanUsername(username);
  if (!clean) return res.status(400).json({ error: "username_invalid" });
  if (!newPassword || String(newPassword).length < 6) return res.status(400).json({ error: "password_short" });

  const target = await getUserByUsername(clean);
  if (!target) return res.status(404).json({ error: "not_found" });
  if (target.role === "admin") return res.status(403).json({ error: "cannot_change_admin" });

  await q(`UPDATE users SET pass_hash=$1, needs_password_change=TRUE WHERE id=$2`, [hashPw(newPassword), target.id]);

  await q(
    `INSERT INTO moderation_logs(admin_id, action, target_id, target_name, reason)
     VALUES ($1,'set_password',$2,$3,'')`,
    [req.session.user.id, target.id, target.username]
  );

  res.json({ ok: true });
});

app.get("/api/admin/users", requireAdminUnlocked, async (req, res) => {
  const r = await q(
    `SELECT id, username, role, avatar, status, created_at, banned_until, muted_until
     FROM users
     ORDER BY username
     LIMIT 500`
  );
  res.json({ ok: true, users: r.rows || [] });
});

app.get("/api/admin/logs", requireAdminUnlocked, async (req, res) => {
  const r = await q(
    `SELECT l.id, l.action, l.target_name, l.room, l.reason, l.meta, l.created_at, u.username AS admin
     FROM moderation_logs l
     JOIN users u ON u.id=l.admin_id
     ORDER BY l.id DESC
     LIMIT 400`
  );
  res.json({ ok: true, logs: r.rows || [] });
});

app.get("/api/admin/rooms", requireAdminUnlocked, async (req, res) => {
  const r = await q(`SELECT name, category, rules, (password_hash IS NOT NULL) AS locked, created_at FROM rooms ORDER BY name`);
  res.json({ ok: true, rooms: r.rows || [] });
});

app.post("/api/admin/rooms", requireAdminUnlocked, async (req, res) => {
  const { name, category = "General", rules = "", password = "" } = req.body || {};
  const room = safeRoom(name);
  if (!room) return res.status(400).json({ error: "bad_room" });

  const pwHash = String(password || "").trim() ? hashPw(password) : null;

  await q(
    `INSERT INTO rooms(name, category, rules, password_hash)
     VALUES ($1,$2,$3,$4)
     ON CONFLICT(name) DO UPDATE
     SET category=EXCLUDED.category, rules=EXCLUDED.rules, password_hash=EXCLUDED.password_hash`,
    [room, String(category).slice(0, 40), String(rules).slice(0, 260), pwHash]
  );

  await q(
    `INSERT INTO moderation_logs(admin_id, action, room, meta)
     VALUES ($1,'save_room',$2,$3::jsonb)`,
    [req.session.user.id, room, JSON.stringify({ locked: !!pwHash })]
  );

  res.json({ ok: true, room });
});

app.get("/api/admin/bots", requireAdminUnlocked, async (req, res) => {
  const r = await q(`SELECT id, name, room, enabled, commands, created_at FROM bots ORDER BY room, name`);
  res.json({ ok: true, bots: r.rows || [] });
});

app.post("/api/admin/bots", requireAdminUnlocked, async (req, res) => {
  const { name, room, enabled = true, commands } = req.body || {};
  const botName = String(name || "").trim().slice(0, 32);
  const r = safeRoom(room || "lobby");
  if (!botName) return res.status(400).json({ error: "missing_fields" });

  await ensureRoom(r);

  let cmdObj = {};
  if (typeof commands === "object" && commands) {
    cmdObj = commands;
  }

  await q(
    `INSERT INTO bots(name, room, enabled, commands, created_by)
     VALUES ($1,$2,$3,$4::jsonb,$5)
     ON CONFLICT(name, room) DO UPDATE
     SET enabled=EXCLUDED.enabled, commands=EXCLUDED.commands`,
    [botName, r, !!enabled, JSON.stringify(cmdObj), req.session.user.id]
  );

  await q(
    `INSERT INTO moderation_logs(admin_id, action, room, reason, meta)
     VALUES ($1,'save_bot',$2,$3,$4::jsonb)`,
    [req.session.user.id, r, botName, JSON.stringify({ commands: Object.keys(cmdObj).length })]
  );

  res.json({ ok: true });
});

app.get("/api/admin/automod", requireAdminUnlocked, async (req, res) => {
  const r = safeRoom(req.query.room || "lobby");
  const cfg = await getAutomod(r);
  res.json({ ok: true, room: r, cfg });
});

app.post("/api/admin/automod", requireAdminUnlocked, async (req, res) => {
  const { room, rateMax = 8, badWordsMode = "off", blacklist = [] } = req.body || {};
  const r = safeRoom(room || "lobby");
  await ensureRoom(r);

  const rm = Math.max(2, Math.min(40, Number(rateMax || 8)));
  const mode = new Set(["off", "soft", "strict"]).has(String(badWordsMode)) ? String(badWordsMode) : "off";
  const list = Array.isArray(blacklist)
    ? blacklist.map((x) => String(x).trim()).filter(Boolean).slice(0, 200)
    : [];

  await q(
    `INSERT INTO automod_settings(room, rate_max, bad_words_mode, blacklist)
     VALUES ($1,$2,$3,$4)
     ON CONFLICT(room) DO UPDATE SET rate_max=EXCLUDED.rate_max, bad_words_mode=EXCLUDED.bad_words_mode, blacklist=EXCLUDED.blacklist`,
    [r, rm, mode, list]
  );

  await q(
    `INSERT INTO moderation_logs(admin_id, action, room, meta)
     VALUES ($1,'save_automod',$2,$3::jsonb)`,
    [req.session.user.id, r, JSON.stringify({ rateMax: rm, mode, listCount: list.length })]
  );

  res.json({ ok: true });
});

/* ===== WS ===== */
const server = http.createServer(app);
const wss = new WebSocketServer({ noServer: true });

server.on("upgrade", (req, socket, head) => {
  sessionParser(req, {}, () => {
    if (!req.session?.user) {
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

wss.on("connection", async (ws) => {
  const user = ws.user;

  const uRow = await q(`SELECT id, username, role, avatar, status FROM users WHERE id=$1`, [user.id]);
  if (!uRow.rowCount) {
    try { ws.close(); } catch {}
    return;
  }
  const u = uRow.rows[0];
  touchOnline(u);
  addUserSocket(user.id, ws);

  await ensureRoom("lobby");
  joinRoom(ws, "lobby");

  ws.on("message", async (raw) => {
    let data;
    try { data = JSON.parse(String(raw || "")); } catch { return; }

    const type = String(data.type || "");
    const meId = Number(user.id);

    const fresh = await q(`SELECT id, username, role, avatar, status FROM users WHERE id=$1`, [meId]);
    if (!fresh.rowCount) return;

    touchOnline(fresh.rows[0]);

    const pf = await punishFlags(meId);
    if (pf.banned) {
      safeSend(ws, { type: "system", event: "banned" });
      try { ws.close(); } catch {}
      return;
    }

    if (type === "join") {
      const room = safeRoom(data.room || "lobby");
      await ensureRoom(room);
      joinRoom(ws, room);
      return;
    }

    if (type === "typing") {
      const room = safeRoom(data.room || ws.room || "lobby");
      broadcastRoom(room, { type: "typing", room, user: user.username, on: !!data.on }, ws);
      return;
    }

    if (type === "chat") {
      const room = safeRoom(ws.room || "lobby");
      const text = String(data.text || "").trim();
      if (!text) return;

      if (pf.muted) {
        const until = pf.mutedUntil ? Math.floor(pf.mutedUntil.getTime() / 1000) : null;
        safeSend(ws, { type: "system", event: "muted", until_ts: until });
        return;
      }

      const cfg = await getAutomod(room);
      if (hitRateLimit(meId, Number(cfg.rate_max || 8))) return;

      const bw = applyBadWords(String(cfg.bad_words_mode || "off"), cfg.blacklist || [], text);
      if (!bw.ok) return;

      const finalText = bw.text.slice(0, 900);

      const bot = await tryBotCommand(room, finalText);
      if (bot) {
        const botMsg = {
          room,
          author: bot.botName,
          role: "bot",
          avatar: "",
          content: bot.reply,
          created_at: new Date().toLocaleString()
        };
        broadcastRoom(room, { type: "message", message: botMsg });

        await q(
          `INSERT INTO messages(room, author_id, author_name, author_role, avatar, content)
           VALUES ($1,NULL,$2,'bot','',$3)`,
          [room, bot.botName, bot.reply]
        );
        return;
      }

      const ins = await q(
        `INSERT INTO messages(room, author_id, author_name, author_role, avatar, content)
         VALUES ($1,$2,$3,$4,$5,$6)
         RETURNING id, created_at`,
        [room, meId, user.username, user.role, fresh.rows[0].avatar || "", finalText]
      );

      const msg = {
        id: Number(ins.rows[0].id),
        room,
        author: user.username,
        role: user.role,
        avatar: fresh.rows[0].avatar || "",
        content: finalText,
        created_at: new Date(ins.rows[0].created_at).toLocaleString()
      };

      broadcastRoom(room, { type: "message", message: msg });
      return;
    }
  });

  ws.on("close", () => {
    removeUserSocket(user.id, ws);
    leaveRoom(ws);
  });
});

/* ===== START ===== */
await migrate();

server.listen(PORT, () => {
  console.log(`Chatly listening on :${PORT}`);
});
