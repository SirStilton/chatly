import express from "express";
import session from "express-session";
import bcrypt from "bcryptjs";
import Database from "better-sqlite3";
import path from "path";
import http from "http";
import { WebSocketServer } from "ws";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const db = new Database(path.join(__dirname, "data.db"));

db.exec(`
  PRAGMA journal_mode = WAL;

  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    pass_hash TEXT NOT NULL,
    bio TEXT DEFAULT '',
    avatar TEXT DEFAULT '',
    role TEXT DEFAULT 'user',
    created_at TEXT DEFAULT (datetime('now')),
    needs_password_change INTEGER DEFAULT 0,
    admin_panel_hash TEXT DEFAULT NULL,
    admin_panel_needs_setup INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room TEXT NOT NULL DEFAULT 'lobby',
    content TEXT NOT NULL,
    author_id INTEGER NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(author_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS punishments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    type TEXT NOT NULL,              -- 'ban' | 'mute'
    reason TEXT DEFAULT '',
    until_ts INTEGER DEFAULT NULL,   -- unix seconds, NULL = permanent
    created_at TEXT DEFAULT (datetime('now')),
    created_by INTEGER NOT NULL,
    active INTEGER DEFAULT 1,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(created_by) REFERENCES users(id)
  );
`);

function hashPw(pw) {
  return bcrypt.hashSync(pw, 10);
}
function verifyPw(pw, hash) {
  try { return bcrypt.compareSync(String(pw), String(hash)); } catch { return false; }
}
function nowSec() {
  return Math.floor(Date.now() / 1000);
}
function safeRoom(input) {
  const room = String(input || "lobby").trim().toLowerCase();
  const cleaned = room.replace(/[^a-z0-9_-]/g, "").slice(0, 32);
  return cleaned || "lobby";
}

function ensureColumn(table, col, typeSql) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all().map(r => r.name);
  if (!cols.includes(col)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${col} ${typeSql}`);
}
ensureColumn("users", "needs_password_change", "INTEGER DEFAULT 0");
ensureColumn("users", "admin_panel_hash", "TEXT DEFAULT NULL");
ensureColumn("users", "admin_panel_needs_setup", "INTEGER DEFAULT 0");

const adminRow = db.prepare("SELECT id FROM users WHERE username=?").get("admin");
if (!adminRow) {
  db.prepare(
    "INSERT INTO users (username, pass_hash, bio, avatar, role, needs_password_change, admin_panel_hash, admin_panel_needs_setup) VALUES (?,?,?,?,?,?,?,?)"
  ).run("admin", hashPw("admin123"), "Master Administrator", "", "admin", 1, hashPw("admin12"), 1);
  console.log("Created default admin: admin / admin123 (CHANGE THIS!)");
}

app.use(express.json({ limit: "200kb" }));

const sessionParser = session({
  secret: "change-this-secret-please-12345",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax"
    // secure: true
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

function getUserByUsername(username) {
  return db.prepare(
    "SELECT id, username, role, pass_hash, needs_password_change, admin_panel_hash, admin_panel_needs_setup, bio, avatar FROM users WHERE username=?"
  ).get(username);
}
function publicUser(u) {
  return { id: u.id, username: u.username, role: u.role };
}

function cleanupPunishmentsForUser(user_id) {
  const t = nowSec();
  db.prepare(`
    UPDATE punishments
    SET active=0
    WHERE user_id=?
      AND active=1
      AND until_ts IS NOT NULL
      AND until_ts <= ?
  `).run(user_id, t);
}

function getActivePunishment(user_id, type) {
  cleanupPunishmentsForUser(user_id);
  const t = nowSec();
  return db.prepare(`
    SELECT id, type, reason, until_ts
    FROM punishments
    WHERE user_id=?
      AND type=?
      AND active=1
      AND (until_ts IS NULL OR until_ts > ?)
    ORDER BY id DESC
    LIMIT 1
  `).get(user_id, type, t);
}

function getPunishmentFlags(user_id) {
  const ban = getActivePunishment(user_id, "ban");
  const mute = getActivePunishment(user_id, "mute");
  return {
    banned: !!ban,
    muted: !!mute,
    ban,
    mute
  };
}

function banCheckMiddleware(req, res, next) {
  if (!req.session.user) return next();
  const flags = getPunishmentFlags(req.session.user.id);
  if (flags.banned) return res.status(403).json({ error: "banned" });
  next();
}

app.post("/api/register", (req, res) => {
  const { username, password, bio = "", avatar = "" } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "missing_fields" });

  const cleanUser = String(username).trim().slice(0, 24);
  if (cleanUser.length < 3) return res.status(400).json({ error: "username_short" });
  if (!/^[a-zA-Z0-9_.-]+$/.test(cleanUser)) return res.status(400).json({ error: "username_invalid" });
  if (String(password).length < 4) return res.status(400).json({ error: "password_short" });

  try {
    const info = db.prepare(
      "INSERT INTO users (username, pass_hash, bio, avatar, role) VALUES (?,?,?,?, 'user')"
    ).run(cleanUser, hashPw(password), String(bio).slice(0, 200), String(avatar).slice(0, 300));

    req.session.user = { id: info.lastInsertRowid, username: cleanUser, role: "user" };
    req.session.adminPanelUnlocked = false;
    res.json({ ok: true, user: req.session.user });
  } catch (e) {
    if (String(e).includes("UNIQUE")) return res.status(409).json({ error: "username_taken" });
    res.status(500).json({ error: "server_error" });
  }
});

app.post("/api/login", (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "missing_fields" });

  const u = getUserByUsername(String(username).trim());
  if (!u) return res.status(401).json({ error: "bad_login" });
  if (!verifyPw(password, u.pass_hash)) return res.status(401).json({ error: "bad_login" });

  const punish = getPunishmentFlags(u.id);
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

app.get("/api/me", (req, res) => {
  if (!req.session.user) return res.json({ user: null });
  const u = getUserByUsername(req.session.user.username);
  if (!u) return res.json({ user: null });

  const punish = getPunishmentFlags(u.id);

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

app.get("/api/profile/:username", (req, res) => {
  const u = db.prepare(
    "SELECT username, bio, avatar, role, created_at FROM users WHERE username=?"
  ).get(req.params.username);
  if (!u) return res.status(404).json({ error: "not_found" });
  res.json({ profile: u });
});

app.post("/api/profile", requireAuth, banCheckMiddleware, (req, res) => {
  const { bio = "", avatar = "" } = req.body || {};
  db.prepare("UPDATE users SET bio=?, avatar=? WHERE id=?").run(
    String(bio).slice(0, 200),
    String(avatar).slice(0, 300),
    req.session.user.id
  );
  res.json({ ok: true });
});

app.post("/api/change-password", requireAuth, banCheckMiddleware, (req, res) => {
  const { oldPassword, newPassword } = req.body || {};
  if (!oldPassword || !newPassword) return res.status(400).json({ error: "missing_fields" });
  if (String(newPassword).length < 4) return res.status(400).json({ error: "password_short" });

  const u = db.prepare("SELECT id, pass_hash FROM users WHERE id=?").get(req.session.user.id);
  if (!u || !verifyPw(oldPassword, u.pass_hash)) return res.status(401).json({ error: "bad_login" });

  db.prepare("UPDATE users SET pass_hash=?, needs_password_change=0 WHERE id=?")
    .run(hashPw(newPassword), req.session.user.id);

  res.json({ ok: true });
});

app.post("/api/admin/setup", requireAdmin, (req, res) => {
  const { currentLoginPassword, newLoginPassword, newAdminPanelPassword } = req.body || {};
  if (!currentLoginPassword || !newLoginPassword || !newAdminPanelPassword) {
    return res.status(400).json({ error: "missing_fields" });
  }
  if (String(newLoginPassword).length < 6) return res.status(400).json({ error: "password_short" });
  if (String(newAdminPanelPassword).length < 6) return res.status(400).json({ error: "password_short" });

  const u = db.prepare(
    "SELECT id, pass_hash, needs_password_change, admin_panel_needs_setup FROM users WHERE id=?"
  ).get(req.session.user.id);

  if (!u) return res.status(500).json({ error: "server_error" });

  if (!u.needs_password_change && !u.admin_panel_needs_setup) {
    return res.status(403).json({ error: "setup_not_required" });
  }
  if (!verifyPw(currentLoginPassword, u.pass_hash)) return res.status(401).json({ error: "bad_login" });

  db.prepare(
    "UPDATE users SET pass_hash=?, needs_password_change=0, admin_panel_hash=?, admin_panel_needs_setup=0 WHERE id=?"
  ).run(hashPw(newLoginPassword), hashPw(newAdminPanelPassword), req.session.user.id);

  req.session.adminPanelUnlocked = false;
  res.json({ ok: true });
});

app.post("/api/admin/panel/unlock", requireAdmin, (req, res) => {
  const { adminPanelPassword } = req.body || {};
  if (!adminPanelPassword) return res.status(400).json({ error: "missing_fields" });

  const u = db.prepare("SELECT admin_panel_hash, admin_panel_needs_setup FROM users WHERE id=?").get(req.session.user.id);
  if (!u) return res.status(500).json({ error: "server_error" });
  if (u.admin_panel_needs_setup) return res.status(403).json({ error: "admin_panel_needs_setup" });

  if (!u.admin_panel_hash || !verifyPw(adminPanelPassword, u.admin_panel_hash)) {
    return res.status(401).json({ error: "admin_panel_bad_password" });
  }

  req.session.adminPanelUnlocked = true;
  res.json({ ok: true });
});

app.post("/api/admin/panel/lock", requireAdmin, (req, res) => {
  req.session.adminPanelUnlocked = false;
  res.json({ ok: true });
});

app.post("/api/admin/change-user-password", requireAdminPanel, (req, res) => {
  const { username, newPassword } = req.body || {};
  if (!username || !newPassword) return res.status(400).json({ error: "missing_fields" });
  if (String(newPassword).length < 4) return res.status(400).json({ error: "password_short" });

  const target = db.prepare("SELECT id, role FROM users WHERE username=?").get(String(username).trim());
  if (!target) return res.status(404).json({ error: "not_found" });
  if (target.role === "admin") return res.status(403).json({ error: "cannot_change_admin" });

  db.prepare("UPDATE users SET pass_hash=?, needs_password_change=1 WHERE id=?").run(hashPw(newPassword), target.id);
  res.json({ ok: true });
});

app.get("/api/messages", requireAuth, banCheckMiddleware, (req, res) => {
  const room = safeRoom(req.query.room);
  const limit = Math.min(Number(req.query.limit || 80), 200);

  const rows = db.prepare(`
    SELECT m.id, m.room, m.content, m.created_at,
           u.username AS author, u.avatar AS avatar, u.role AS role
    FROM messages m
    JOIN users u ON u.id = m.author_id
    WHERE m.room=?
    ORDER BY m.id DESC
    LIMIT ?
  `).all(room, limit).reverse();

  res.json({ messages: rows, room });
});

const server = http.createServer(app);
const wss = new WebSocketServer({ noServer: true });

server.on("upgrade", (req, socket, head) => {
  sessionParser(req, {}, () => {
    if (!req.session?.user) {
      socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
      socket.destroy();
      return;
    }
    const punish = getPunishmentFlags(req.session.user.id);
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

wss.on("connection", (ws) => {
  ws.send(JSON.stringify({ type: "hello", user: ws.user, room: ws.room }));

  ws.on("message", (raw) => {
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

      const punish = getPunishmentFlags(ws.user.id);
      if (punish.banned) {
        try { ws.send(JSON.stringify({ type: "system", event: "banned" })); } catch {}
        try { ws.close(); } catch {}
        return;
      }
      if (punish.muted) {
        ws.send(JSON.stringify({
          type: "system",
          event: "muted",
          until_ts: punish.mute?.until_ts ?? null,
          reason: punish.mute?.reason ?? ""
        }));
        return;
      }

      const info = db.prepare("INSERT INTO messages (room, content, author_id) VALUES (?,?,?)")
        .run(ws.room, text, ws.user.id);

      const msg = db.prepare(`
        SELECT m.id, m.room, m.content, m.created_at,
               u.username AS author, u.avatar AS avatar, u.role AS role
        FROM messages m
        JOIN users u ON u.id = m.author_id
        WHERE m.id=?
      `).get(info.lastInsertRowid);

      broadcastToRoom(ws.room, { type: "message", message: msg });
    }
  });
});

function parseDurationSec(input) {
  const v = String(input || "perm");
  if (v === "perm") return null;
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) return null;
  return Math.floor(n);
}

app.post("/api/admin/punish", requireAdminPanel, (req, res) => {
  const { username, action, durationSec, reason = "" } = req.body || {};
  if (!username || !action) return res.status(400).json({ error: "missing_fields" });

  const target = db.prepare("SELECT id, role FROM users WHERE username=?").get(String(username).trim());
  if (!target) return res.status(404).json({ error: "not_found" });
  if (target.role === "admin") return res.status(403).json({ error: "cannot_punish_admin" });

  const dur = parseDurationSec(durationSec);
  const until_ts = dur === null ? null : nowSec() + dur;

  if (action === "ban") {
    db.prepare(`
      UPDATE punishments
      SET active=0
      WHERE user_id=? AND type='ban' AND active=1
    `).run(target.id);

    db.prepare(`
      INSERT INTO punishments (user_id, type, reason, until_ts, created_by, active)
      VALUES (?, 'ban', ?, ?, ?, 1)
    `).run(target.id, String(reason).slice(0, 200), until_ts, req.session.user.id);

    kickUser(String(username).trim(), "banned");
    return res.json({ ok: true });
  }

  if (action === "mute") {
    db.prepare(`
      UPDATE punishments
      SET active=0
      WHERE user_id=? AND type='mute' AND active=1
    `).run(target.id);

    db.prepare(`
      INSERT INTO punishments (user_id, type, reason, until_ts, created_by, active)
      VALUES (?, 'mute', ?, ?, ?, 1)
    `).run(target.id, String(reason).slice(0, 200), until_ts, req.session.user.id);

    sendToUser(String(username).trim(), { type: "system", event: "muted_set", until_ts, reason: String(reason).slice(0, 200) });
    return res.json({ ok: true });
  }

  if (action === "unban") {
    db.prepare(`
      UPDATE punishments
      SET active=0
      WHERE user_id=? AND type='ban' AND active=1
    `).run(target.id);
    return res.json({ ok: true });
  }

  if (action === "unmute") {
    db.prepare(`
      UPDATE punishments
      SET active=0
      WHERE user_id=? AND type='mute' AND active=1
    `).run(target.id);
    sendToUser(String(username).trim(), { type: "system", event: "unmuted" });
    return res.json({ ok: true });
  }

  if (action === "kick") {
    kickUser(String(username).trim(), String(reason).slice(0, 200) || "kicked");
    return res.json({ ok: true });
  }

  return res.status(400).json({ error: "bad_action" });
});

app.post("/api/admin/force-room", requireAdminPanel, (req, res) => {
  const { username, room } = req.body || {};
  if (!username || !room) return res.status(400).json({ error: "missing_fields" });

  const target = db.prepare("SELECT id, role FROM users WHERE username=?").get(String(username).trim());
  if (!target) return res.status(404).json({ error: "not_found" });
  if (target.role === "admin") return res.status(403).json({ error: "cannot_force_admin" });

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

const PORT = process.env.PORT || 3000;
server.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running: http://localhost:${PORT}`);
});
