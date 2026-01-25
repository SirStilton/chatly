import express from "express";
import helmet from "helmet";
import http from "http";
import { Server as SocketIOServer } from "socket.io";
import pgPkg from "pg";
import bcrypt from "bcryptjs";
import path from "path";
import { fileURLToPath } from "url";

const { Pool } = pgPkg;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Render sets PORT automatically; never hardcode it in env
const PORT = Number(process.env.PORT || 3000);
const DATABASE_URL = process.env.DATABASE_URL;
const SESSION_SECRET = process.env.SESSION_SECRET;
const TRUST_PROXY = String(process.env.TRUST_PROXY || "0") === "1";

if (!DATABASE_URL) throw new Error("Missing env DATABASE_URL");
if (!SESSION_SECRET) throw new Error("Missing env SESSION_SECRET");

// --- DB (Supabase pooler often needs ssl with rejectUnauthorized false)
function stripQuery(urlString) {
  try {
    const u = new URL(urlString);
    u.search = "";
    return u.toString();
  } catch {
    return urlString;
  }
}
const isSupabase = /supabase\.com|pooler/i.test(DATABASE_URL);

const pool = new Pool({
  connectionString: stripQuery(DATABASE_URL),
  ssl: isSupabase ? { rejectUnauthorized: false } : undefined,
  max: 10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000
});

async function q(text, params = []) {
  return pool.query(text, params);
}

// --- App rules (your choices)
const USERNAME_RE = /^[a-z0-9]+$/i;
const USERNAME_MAX = 10;
const MSG_MAX = 100;

// Basic parsers
function now() {
  return new Date();
}
function safeText(s, max) {
  return String(s ?? "").trim().slice(0, max);
}
function safeSlug(s) {
  const x = String(s || "").trim().toLowerCase();
  const cleaned = x.replace(/[^a-z0-9_-]/g, "").slice(0, 32);
  return cleaned || "lobby";
}
function normUsername(u) {
  return safeText(u, 100).toLowerCase();
}
function validUsername(u) {
  if (!u) return false;
  if (u.length < 3 || u.length > USERNAME_MAX) return false;
  return USERNAME_RE.test(u);
}
function validPassword(p) {
  return typeof p === "string" && p.length >= 8 && p.length <= 128;
}
function parseCookies(cookieHeader = "") {
  const out = {};
  cookieHeader.split(";").forEach((part) => {
    const idx = part.indexOf("=");
    if (idx === -1) return;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  });
  return out;
}
function cookieStr(name, value, opts = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  if (opts.maxAge != null) parts.push(`Max-Age=${Math.floor(opts.maxAge)}`);
  if (opts.path) parts.push(`Path=${opts.path}`);
  if (opts.httpOnly) parts.push("HttpOnly");
  if (opts.secure) parts.push("Secure");
  if (opts.sameSite) parts.push(`SameSite=${opts.sameSite}`);
  return parts.join("; ");
}

// --- In-memory rate limits (simple but effective)
const msgWindow = new Map();       // userId -> timestamps[]
const switchWindow = new Map();    // userId -> timestamps[]

function allowAction(map, userId, limit, windowMs) {
  const t = Date.now();
  const arr = map.get(userId) || [];
  const keep = arr.filter((x) => t - x < windowMs);
  if (keep.length >= limit) {
    map.set(userId, keep);
    return false;
  }
  keep.push(t);
  map.set(userId, keep);
  return true;
}

// --- Sessions stored in DB (user_sessions)
const SESSION_COOKIE = "sid";
const SESSION_DAYS = 14;

async function createSessionForUser(userId) {
  const r = await q(`SELECT id, session_version FROM users WHERE id=$1 LIMIT 1`, [userId]);
  const u = r.rows[0];
  if (!u) throw new Error("user_not_found");

  const expires = new Date(Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000);
  const ins = await q(
    `INSERT INTO user_sessions (user_id, session_version, expires_at)
     VALUES ($1, $2, $3)
     RETURNING id;`,
    [userId, Number(u.session_version), expires]
  );
  return { sid: ins.rows[0].id, expires };
}

async function getSessionUser(sid) {
  if (!sid) return null;
  const r = await q(
    `SELECT s.id as sid, s.expires_at, s.session_version as sver,
            u.id, u.username, u.role, u.bio, u.avatar_url, u.status,
            u.banned_until, u.muted_until, u.timeout_until,
            u.session_version as uver
     FROM user_sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.id = $1
     LIMIT 1;`,
    [sid]
  );
  if (!r.rows[0]) return null;

  const row = r.rows[0];
  if (row.expires_at && new Date(row.expires_at) <= now()) return null;
  if (Number(row.sver) !== Number(row.uver)) return null;

  return {
    sid: row.sid,
    user: {
      id: row.id,
      username: row.username,
      role: row.role,
      bio: row.bio,
      avatar_url: row.avatar_url,
      status: row.status,
      banned_until: row.banned_until,
      muted_until: row.muted_until,
      timeout_until: row.timeout_until,
      session_version: Number(row.uver)
    }
  };
}

async function destroySession(sid) {
  if (!sid) return;
  await q(`DELETE FROM user_sessions WHERE id=$1`, [sid]);
}

function isActiveBan(user) {
  return user?.banned_until && new Date(user.banned_until) > now();
}
function isActiveMute(user) {
  return user?.muted_until && new Date(user.muted_until) > now();
}
function isActiveTimeout(user) {
  return user?.timeout_until && new Date(user.timeout_until) > now();
}

// --- Rooms cache + defaults
const roomCache = new Map(); // slug -> room row

async function getRoomBySlug(slug) {
  const key = safeSlug(slug);
  if (roomCache.has(key)) return roomCache.get(key);

  const r = await q(
    `SELECT id, slug, title, description, visibility, kind, created_by, join_code, is_locked, admin_only
     FROM rooms
     WHERE slug=$1
     LIMIT 1;`,
    [key]
  );
  const room = r.rows[0] || null;
  if (room) roomCache.set(key, room);
  return room;
}

async function ensureDefaultRooms() {
  await q(
    `INSERT INTO rooms (slug, title, description, visibility, kind, is_locked, admin_only)
     VALUES
     ('lobby','Lobby','Allgemeiner Chat','public','room',false,false),
     ('support','Support','Hilfe & Fragen','public','room',false,false),
     ('casual','Casual','Locker reden','public','room',false,false),
     ('school','School','Schule & AGs','public','room',false,false),
     ('fun','Fun','Memes & Spaß','public','room',false,false),
     ('admin-hq','Admin HQ','Nur Admins','public','room',false,true)
     ON CONFLICT (slug) DO NOTHING;`
  );
  roomCache.clear();
}

async function ensureMember(roomId, userId, role = "member") {
  await q(
    `INSERT INTO room_members (room_id, user_id, role)
     VALUES ($1,$2,$3)
     ON CONFLICT (room_id, user_id) DO NOTHING;`,
    [roomId, userId, role]
  );
}

async function modLog({ byAdmin, action, targetUser = null, targetRoom = null, details = null }) {
  await q(
    `INSERT INTO moderation_logs (by_admin, action, target_user, target_room, details)
     VALUES ($1,$2,$3,$4,$5);`,
    [byAdmin, action, targetUser, targetRoom, details]
  );
}

// --- Express
const app = express();
if (TRUST_PROXY) app.set("trust proxy", 1);

app.use(helmet());
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname, "public"), { extensions: ["html"] }));
app.get("/", (_req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

async function authMiddleware(req, _res, next) {
  try {
    const cookies = parseCookies(req.headers.cookie || "");
    const sid = cookies[SESSION_COOKIE];
    if (!sid) {
      req.user = null;
      req.sid = null;
      return next();
    }
    const sess = await getSessionUser(sid);
    req.user = sess?.user || null;
    req.sid = sess?.sid || sid;
    next();
  } catch (e) {
    console.error("authMiddleware error", e);
    req.user = null;
    req.sid = null;
    next();
  }
}

app.use(authMiddleware);

function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ ok: false, error: "not_logged_in" });
  if (isActiveBan(req.user)) return res.status(403).json({ ok: false, error: "banned", until: req.user.banned_until });
  next();
}

function requireAdmin(req, res, next) {
  if (!req.user) return res.status(401).json({ ok: false, error: "not_logged_in" });
  if (req.user.role !== "admin") return res.status(403).json({ ok: false, error: "not_admin" });
  next();
}

// --- API: Auth
app.get("/api/me", (req, res) => res.json({ ok: true, user: req.user || null }));

app.post("/api/register", async (req, res) => {
  try {
    const usernameRaw = String(req.body.username || "");
    const username = normUsername(usernameRaw);
    const password = String(req.body.password || "");

    if (!validUsername(username)) return res.status(400).json({ ok: false, error: "bad_username" });
    if (!validPassword(password)) return res.status(400).json({ ok: false, error: "bad_password" });

    const pass_hash = await bcrypt.hash(password, 12);

    const r = await q(
      `INSERT INTO users (username, pass_hash, role, status, session_version, admin_panel_needs_setup)
       VALUES ($1,$2,'user','active',0,true)
       RETURNING id, username, role, bio, avatar_url, status, banned_until, muted_until, timeout_until, session_version;`,
      [username, pass_hash]
    );

    const user = r.rows[0];
    const sess = await createSessionForUser(user.id);

    res.setHeader(
      "Set-Cookie",
      cookieStr(SESSION_COOKIE, sess.sid, {
        httpOnly: true,
        secure: true,
        sameSite: "Lax",
        path: "/",
        maxAge: SESSION_DAYS * 24 * 60 * 60
      })
    );

    res.json({ ok: true, user });
  } catch (e) {
    if (e?.code === "23505") return res.status(409).json({ ok: false, error: "username_taken" });
    console.error("register error", e);
    res.status(500).json({ ok: false, error: "server_error" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const username = normUsername(req.body.username);
    const password = String(req.body.password || "");

    const r = await q(
      `SELECT id, username, pass_hash, role, bio, avatar_url, status,
              banned_until, muted_until, timeout_until, session_version
       FROM users
       WHERE username=$1
       LIMIT 1;`,
      [username]
    );

    const u = r.rows[0];
    if (!u) return res.status(401).json({ ok: false, error: "invalid_login" });

    const ok = await bcrypt.compare(password, u.pass_hash);
    if (!ok) return res.status(401).json({ ok: false, error: "invalid_login" });

    const user = {
      id: u.id,
      username: u.username,
      role: u.role,
      bio: u.bio,
      avatar_url: u.avatar_url,
      status: u.status,
      banned_until: u.banned_until,
      muted_until: u.muted_until,
      timeout_until: u.timeout_until,
      session_version: Number(u.session_version)
    };

    if (isActiveBan(user)) return res.status(403).json({ ok: false, error: "banned", until: user.banned_until });

    const sess = await createSessionForUser(user.id);

    res.setHeader(
      "Set-Cookie",
      cookieStr(SESSION_COOKIE, sess.sid, {
        httpOnly: true,
        secure: true,
        sameSite: "Lax",
        path: "/",
        maxAge: SESSION_DAYS * 24 * 60 * 60
      })
    );

    res.json({ ok: true, user });
  } catch (e) {
    console.error("login error", e);
    res.status(500).json({ ok: false, error: "server_error" });
  }
});

app.post("/api/logout", requireAuth, async (req, res) => {
  try {
    await destroySession(req.sid);
    res.setHeader(
      "Set-Cookie",
      cookieStr(SESSION_COOKIE, "", {
        httpOnly: true,
        secure: true,
        sameSite: "Lax",
        path: "/",
        maxAge: 0
      })
    );
    res.json({ ok: true });
  } catch (e) {
    console.error("logout error", e);
    res.status(500).json({ ok: false, error: "server_error" });
  }
});

// --- API: Rooms & messages
app.get("/api/rooms", requireAuth, async (req, res) => {
  try {
    const r = req.user.role === "admin"
      ? await q(`SELECT id, slug, title, description, visibility, kind, is_locked, admin_only FROM rooms ORDER BY slug ASC;`)
      : await q(`SELECT id, slug, title, description, visibility, kind, is_locked, admin_only FROM rooms WHERE admin_only=false ORDER BY slug ASC;`);
    res.json({ ok: true, rooms: r.rows });
  } catch (e) {
    console.error("rooms error", e);
    res.status(500).json({ ok: false, error: "server_error" });
  }
});

app.post("/api/rooms/:slug/join", requireAuth, async (req, res) => {
  try {
    const slug = safeSlug(req.params.slug);
    const room = await getRoomBySlug(slug);
    if (!room) return res.status(404).json({ ok: false, error: "room_not_found" });

    if (room.admin_only && req.user.role !== "admin") return res.status(403).json({ ok: false, error: "admin_room" });

    if (room.visibility === "private") {
      const code = safeText(req.body.join_code, 64);
      if (!room.join_code || code !== room.join_code) return res.status(403).json({ ok: false, error: "bad_join_code" });
    }

    await ensureMember(room.id, req.user.id, req.user.role === "admin" ? "admin" : "member");
    res.json({ ok: true, room: { slug: room.slug, title: room.title } });
  } catch (e) {
    console.error("join room error", e);
    res.status(500).json({ ok: false, error: "server_error" });
  }
});

app.get("/api/rooms/:slug/messages", requireAuth, async (req, res) => {
  try {
    const slug = safeSlug(req.params.slug);
    const room = await getRoomBySlug(slug);
    if (!room) return res.status(404).json({ ok: false, error: "room_not_found" });
    if (room.admin_only && req.user.role !== "admin") return res.status(403).json({ ok: false, error: "admin_room" });

    const limit = Math.min(200, Math.max(1, Number(req.query.limit || 50)));

    const r = await q(
      `SELECT m.id, m.created_at, m.type, m.content, m.is_deleted,
              u.username AS author, u.role AS author_role
       FROM messages m
       LEFT JOIN users u ON u.id = m.author_id
       WHERE m.room_id = $1
       ORDER BY m.id DESC
       LIMIT $2;`,
      [room.id, limit]
    );

    res.json({ ok: true, messages: r.rows.reverse() });
  } catch (e) {
    console.error("fetch messages error", e);
    res.status(500).json({ ok: false, error: "server_error" });
  }
});

app.delete("/api/messages/:id", requireAuth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ ok: false, error: "bad_id" });

    const r = await q(`SELECT id, room_id, author_id, is_deleted FROM messages WHERE id=$1 LIMIT 1;`, [id]);
    const msg = r.rows[0];
    if (!msg) return res.status(404).json({ ok: false, error: "not_found" });
    if (msg.is_deleted) return res.json({ ok: true });

    const isOwner = msg.author_id && Number(msg.author_id) === Number(req.user.id);
    const isAdmin = req.user.role === "admin";
    if (!isOwner && !isAdmin) return res.status(403).json({ ok: false, error: "forbidden" });

    await q(
      `UPDATE messages
       SET is_deleted=true, content='[deleted]', deleted_by=$1, deleted_at=now()
       WHERE id=$2;`,
      [req.user.id, id]
    );

    res.json({ ok: true });
  } catch (e) {
    console.error("delete message error", e);
    res.status(500).json({ ok: false, error: "server_error" });
  }
});

// --- ADMIN API (Panel uses these)
app.get("/api/admin/users", requireAuth, requireAdmin, async (_req, res) => {
  try {
    const r = await q(
      `SELECT id, username, role, status, bio, avatar_url,
              banned_until, muted_until, timeout_until, created_at
       FROM users
       ORDER BY id ASC
       LIMIT 300;`
    );
    res.json({ ok: true, users: r.rows });
  } catch (e) {
    console.error("admin users error", e);
    res.status(500).json({ ok: false, error: "server_error" });
  }
});

app.get("/api/admin/logs", requireAuth, requireAdmin, async (req, res) => {
  try {
    const limit = Math.min(300, Math.max(1, Number(req.query.limit || 120)));
    const r = await q(
      `SELECT l.id, l.created_at, l.action, l.details,
              a.username AS by_admin_name,
              tu.username AS target_user_name,
              tr.slug AS target_room_slug
       FROM moderation_logs l
       LEFT JOIN users a ON a.id = l.by_admin
       LEFT JOIN users tu ON tu.id = l.target_user
       LEFT JOIN rooms tr ON tr.id = l.target_room
       ORDER BY l.id DESC
       LIMIT $1;`,
      [limit]
    );
    res.json({ ok: true, logs: r.rows });
  } catch (e) {
    console.error("admin logs error", e);
    res.status(500).json({ ok: false, error: "server_error" });
  }
});

// Ban/Mute/Timeout (already used by your UI later)
app.post("/api/admin/punish", requireAuth, requireAdmin, async (req, res) => {
  try {
    const username = normUsername(req.body.username);
    const kind = String(req.body.kind || "").toLowerCase(); // ban|mute|timeout
    const minutes = Math.max(1, Math.min(60 * 24 * 30, Number(req.body.minutes || 10)));
    const reason = safeText(req.body.reason, 200);

    if (!validUsername(username)) return res.status(400).json({ ok: false, error: "bad_username" });
    if (!["ban", "mute", "timeout"].includes(kind)) return res.status(400).json({ ok: false, error: "bad_kind" });

    const ur = await q(`SELECT id, role FROM users WHERE username=$1 LIMIT 1;`, [username]);
    const target = ur.rows[0];
    if (!target) return res.status(404).json({ ok: false, error: "user_not_found" });
    if (target.role === "admin") return res.status(400).json({ ok: false, error: "cannot_punish_admin" });

    const untilAt = new Date(Date.now() + minutes * 60 * 1000);

    if (kind === "ban") await q(`UPDATE users SET banned_until=$1 WHERE id=$2;`, [untilAt, target.id]);
    if (kind === "mute") await q(`UPDATE users SET muted_until=$1 WHERE id=$2;`, [untilAt, target.id]);
    if (kind === "timeout") await q(`UPDATE users SET timeout_until=$1 WHERE id=$2;`, [untilAt, target.id]);

    await q(
      `INSERT INTO punishments (user_id, by_admin, kind, until_at, reason)
       VALUES ($1,$2,$3,$4,$5);`,
      [target.id, req.user.id, kind, untilAt, reason || null]
    );

    await modLog({
      byAdmin: req.user.id,
      action: `USER_${kind.toUpperCase()}`,
      targetUser: target.id,
      details: { minutes, reason }
    });

    // Notify target live (optional)
    notifyUser(target.id, "punished", { kind, until_at: untilAt, reason });

    res.json({ ok: true, until_at: untilAt });
  } catch (e) {
    console.error("admin punish error", e);
    res.status(500).json({ ok: false, error: "server_error" });
  }
});

// System message in a room
app.post("/api/admin/system", requireAuth, requireAdmin, async (req, res) => {
  try {
    const slug = safeSlug(req.body.room || "lobby");
    const text = safeText(req.body.text, 200);
    if (!text) return res.status(400).json({ ok: false, error: "empty" });

    const room = await getRoomBySlug(slug);
    if (!room) return res.status(404).json({ ok: false, error: "room_not_found" });
    if (room.admin_only && req.user.role !== "admin") return res.status(403).json({ ok: false, error: "admin_room" });

    const ins = await q(
      `INSERT INTO messages (room_id, author_id, type, content)
       VALUES ($1, NULL, 'system', $2)
       RETURNING id, created_at;`,
      [room.id, text]
    );

    const msg = {
      id: ins.rows[0].id,
      created_at: ins.rows[0].created_at,
      type: "system",
      content: text,
      author: null,
      author_role: null,
      is_deleted: false
    };

    io.to(room.slug).emit("message", msg);

    await modLog({ byAdmin: req.user.id, action: "SYSTEM_MESSAGE", targetRoom: room.id, details: { text } });

    res.json({ ok: true });
  } catch (e) {
    console.error("admin system error", e);
    res.status(500).json({ ok: false, error: "server_error" });
  }
});

// Force-move a user into another room (client must handle "force_move" event)
app.post("/api/admin/force-move", requireAuth, requireAdmin, async (req, res) => {
  try {
    const username = normUsername(req.body.username);
    const slug = safeSlug(req.body.room);
    const join_code = safeText(req.body.join_code, 64);

    if (!validUsername(username)) return res.status(400).json({ ok: false, error: "bad_username" });

    const ur = await q(`SELECT id, role FROM users WHERE username=$1 LIMIT 1;`, [username]);
    const target = ur.rows[0];
    if (!target) return res.status(404).json({ ok: false, error: "user_not_found" });

    const room = await getRoomBySlug(slug);
    if (!room) return res.status(404).json({ ok: false, error: "room_not_found" });
    if (room.admin_only && target.role !== "admin") return res.status(400).json({ ok: false, error: "target_not_admin" });

    if (room.visibility === "private") {
      if (!room.join_code || join_code !== room.join_code) return res.status(403).json({ ok: false, error: "bad_join_code" });
    }

    notifyUser(target.id, "force_move", { room: room.slug, join_code: room.visibility === "private" ? join_code : null });

    await modLog({
      byAdmin: req.user.id,
      action: "FORCE_MOVE",
      targetUser: target.id,
      targetRoom: room.id,
      details: { room: room.slug }
    });

    res.json({ ok: true });
  } catch (e) {
    console.error("admin force-move error", e);
    res.status(500).json({ ok: false, error: "server_error" });
  }
});

// Bots (minimal: create/list/toggle)
app.get("/api/admin/bots", requireAuth, requireAdmin, async (_req, res) => {
  try {
    const r = await q(
      `SELECT b.id, b.created_at, b.name, b.room_id, b.enabled, b.config,
              r.slug AS room_slug
       FROM bots b
       LEFT JOIN rooms r ON r.id = b.room_id
       ORDER BY b.id DESC
       LIMIT 300;`
    );
    res.json({ ok: true, bots: r.rows });
  } catch (e) {
    console.error("admin bots list error", e);
    res.status(500).json({ ok: false, error: "server_error" });
  }
});

app.post("/api/admin/bots/create", requireAuth, requireAdmin, async (req, res) => {
  try {
    const name = safeText(req.body.name, 30);
    const roomSlug = safeSlug(req.body.room || "lobby");
    const config = req.body.config && typeof req.body.config === "object" ? req.body.config : {};

    if (!name) return res.status(400).json({ ok: false, error: "bad_name" });

    const room = await getRoomBySlug(roomSlug);
    if (!room) return res.status(404).json({ ok: false, error: "room_not_found" });
    if (room.admin_only && req.user.role !== "admin") return res.status(403).json({ ok: false, error: "admin_room" });

    const ins = await q(
      `INSERT INTO bots (name, room_id, enabled, config)
       VALUES ($1,$2,true,$3)
       RETURNING id;`,
      [name, room.id, config]
    );

    await modLog({ byAdmin: req.user.id, action: "BOT_CREATE", targetRoom: room.id, details: { name } });
    res.json({ ok: true, id: ins.rows[0].id });
  } catch (e) {
    console.error("admin bots create error", e);
    res.status(500).json({ ok: false, error: "server_error" });
  }
});

app.post("/api/admin/bots/toggle", requireAuth, requireAdmin, async (req, res) => {
  try {
    const id = Number(req.body.id);
    const enabled = Boolean(req.body.enabled);
    if (!Number.isFinite(id)) return res.status(400).json({ ok: false, error: "bad_id" });

    await q(`UPDATE bots SET enabled=$1 WHERE id=$2`, [enabled, id]);
    await modLog({ byAdmin: req.user.id, action: "BOT_TOGGLE", details: { id, enabled } });

    res.json({ ok: true });
  } catch (e) {
    console.error("admin bots toggle error", e);
    res.status(500).json({ ok: false, error: "server_error" });
  }
});

// --- Socket.IO
const server = http.createServer(app);
const io = new SocketIOServer(server, {
  cors: { origin: true, credentials: true }
});

const userSockets = new Map(); // userId -> Set(socket)
function trackSocket(userId, socket) {
  const set = userSockets.get(userId) || new Set();
  set.add(socket);
  userSockets.set(userId, set);
  socket.on("disconnect", () => {
    const s = userSockets.get(userId);
    if (!s) return;
    s.delete(socket);
    if (s.size === 0) userSockets.delete(userId);
  });
}
function notifyUser(userId, event, payload) {
  const set = userSockets.get(Number(userId));
  if (!set) return;
  for (const s of set) {
    try {
      s.emit(event, payload);
    } catch {}
  }
}

io.use(async (socket, next) => {
  try {
    const cookies = parseCookies(socket.request.headers.cookie || "");
    const sid = cookies[SESSION_COOKIE];
    if (!sid) return next(new Error("not_logged_in"));

    const sess = await getSessionUser(sid);
    if (!sess) return next(new Error("not_logged_in"));

    if (isActiveBan(sess.user)) return next(new Error("banned"));

    socket.user = sess.user;
    socket.sid = sid;
    trackSocket(sess.user.id, socket);
    next();
  } catch {
    next(new Error("auth_error"));
  }
});

io.on("connection", (socket) => {
  socket.join("lobby");
  socket.emit("hello", { ok: true, user: socket.user, room: "lobby" });

  socket.on("join", async (payload, cb) => {
    try {
      const slug = safeSlug(payload?.slug || payload?.room || "lobby");

      if (!allowAction(switchWindow, socket.user.id, 8, 10_000)) {
        return cb?.({ ok: false, error: "rate_limited" });
      }

      const room = await getRoomBySlug(slug);
      if (!room) return cb?.({ ok: false, error: "room_not_found" });

      if (room.admin_only && socket.user.role !== "admin") {
        return cb?.({ ok: false, error: "admin_room" });
      }

      if (room.visibility === "private") {
        const code = safeText(payload?.join_code, 64);
        if (!room.join_code || code !== room.join_code) {
          return cb?.({ ok: false, error: "bad_join_code" });
        }
      }

      for (const r of socket.rooms) {
        if (r !== socket.id) socket.leave(r);
      }

      socket.join(slug);

      await ensureMember(room.id, socket.user.id, socket.user.role === "admin" ? "admin" : "member");

      cb?.({ ok: true, room: { slug: room.slug, title: room.title } });
    } catch {
      cb?.({ ok: false, error: "server_error" });
    }
  });

  socket.on("send", async (payload, cb) => {
    try {
      if (isActiveTimeout(socket.user)) return cb?.({ ok: false, error: "timeout" });
      if (isActiveMute(socket.user)) return cb?.({ ok: false, error: "muted" });

      // rate limit: 5 messages / 3s
      if (!allowAction(msgWindow, socket.user.id, 5, 3000)) return cb?.({ ok: false, error: "rate_limited" });

      const slug = safeSlug(payload?.room || "lobby");
      const text = safeText(payload?.text, MSG_MAX);
      const wantHtml = Boolean(payload?.is_html);

      if (!text) return cb?.({ ok: false, error: "empty" });

      const room = await getRoomBySlug(slug);
      if (!room) return cb?.({ ok: false, error: "room_not_found" });

      if (room.admin_only && socket.user.role !== "admin") return cb?.({ ok: false, error: "admin_room" });

      // private rooms: must be a member (joined through /join)
      if (room.visibility === "private") {
        const mr = await q(
          `SELECT 1 FROM room_members WHERE room_id=$1 AND user_id=$2 LIMIT 1;`,
          [room.id, socket.user.id]
        );
        if (mr.rowCount === 0) return cb?.({ ok: false, error: "not_in_room" });
      }

      // auto-join on first message
      await ensureMember(room.id, socket.user.id, socket.user.role === "admin" ? "admin" : "member");

      const type = socket.user.role === "admin" && wantHtml ? "admin_html" : "text";

      const ins = await q(
        `INSERT INTO messages (room_id, author_id, type, content)
         VALUES ($1, $2, $3, $4)
         RETURNING id, created_at;`,
        [room.id, socket.user.id, type, text]
      );

      const msg = {
        id: ins.rows[0].id,
        created_at: ins.rows[0].created_at,
        type,
        content: text,
        is_deleted: false,
        author: socket.user.username,
        author_role: socket.user.role
      };

      io.to(slug).emit("message", msg);

      cb?.({ ok: true, id: msg.id });
    } catch {
      cb?.({ ok: false, error: "server_error" });
    }
  });

  socket.on("delete", async (payload, cb) => {
    try {
      const id = Number(payload?.id);
      if (!Number.isFinite(id)) return cb?.({ ok: false, error: "bad_id" });

      const r = await q(`SELECT id, room_id, author_id, is_deleted FROM messages WHERE id=$1 LIMIT 1;`, [id]);
      const msg = r.rows[0];
      if (!msg) return cb?.({ ok: false, error: "not_found" });
      if (msg.is_deleted) return cb?.({ ok: true });

      const isOwner = msg.author_id && Number(msg.author_id) === Number(socket.user.id);
      const isAdmin = socket.user.role === "admin";
      if (!isOwner && !isAdmin) return cb?.({ ok: false, error: "forbidden" });

      await q(
        `UPDATE messages
         SET is_deleted=true, content='[deleted]', deleted_by=$1, deleted_at=now()
         WHERE id=$2;`,
        [socket.user.id, id]
      );

      const rr = await q(`SELECT slug FROM rooms WHERE id=$1 LIMIT 1;`, [msg.room_id]);
      const slug = rr.rows[0]?.slug || "lobby";
      io.to(slug).emit("message_deleted", { id });

      cb?.({ ok: true });
    } catch {
      cb?.({ ok: false, error: "server_error" });
    }
  });
});

// --- Start
server.listen(PORT, async () => {
  try {
    await q("SELECT 1;");
    await ensureDefaultRooms();
    console.log(`Chatly listening on :${PORT}`);
  } catch (e) {
    console.error("Startup error:", e);
    process.exit(1);
  }
});

process.on("SIGTERM", async () => {
  try {
    await pool.end();
  } catch {}
  process.exit(0);
});
