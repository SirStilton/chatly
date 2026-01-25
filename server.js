// Chatly - server.js
// Node (ESM) + Express + Socket.IO + PostgreSQL (Supabase)
// Auth: username+password (NO email) | No guests
// Features: rooms (public listed / unlisted searchable / private join_code / admin-only), realtime chat,
// message types (text/system/bot), own-message delete, admin moderation (ban/mute/timeout/kick),
// timeout room (not leaveable), room creator kick, trending rooms, random room, simple automod rate limit.

import express from "express";
import http from "http";
import path from "path";
import { fileURLToPath } from "url";
import crypto from "crypto";
import { Pool } from "pg";
import bcrypt from "bcryptjs";
import cookieParser from "cookie-parser";
import { Server as IOServer } from "socket.io";

// ---------------- config ----------------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const SESSION_SECRET = process.env.SESSION_SECRET;

if (!DATABASE_URL) throw new Error("Missing env DATABASE_URL");
if (!SESSION_SECRET) throw new Error("Missing env SESSION_SECRET");

// Supabase often uses SSL; on many PaaS setups you need rejectUnauthorized:false.
// (You can tighten later with a proper CA.)
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000,
});

async function q(text, params = []) {
  return pool.query(text, params);
}

// ---------------- tiny utils ----------------
const MSG_MAX_LEN = 100;
const USERNAME_MAX = 10;

function clamp(str, max) {
  if (typeof str !== "string") return "";
  return str.length > max ? str.slice(0, max) : str;
}
function isFuture(ts) {
  if (!ts) return false;
  const d = new Date(ts);
  return !Number.isNaN(d.getTime()) && d.getTime() > Date.now();
}
function base64url(b) {
  return Buffer.from(b).toString("base64url");
}
function hmacSign(value) {
  return crypto.createHmac("sha256", SESSION_SECRET).update(value).digest("base64url");
}
function signCookie(sessionId) {
  return `${sessionId}.${hmacSign(sessionId)}`;
}
function verifyCookie(signed) {
  if (!signed || typeof signed !== "string") return null;
  const [sid, sig] = signed.split(".");
  if (!sid || !sig) return null;
  const expected = hmacSign(sid);
  try {
    return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected)) ? sid : null;
  } catch {
    return null;
  }
}
function randomJoinCode(len = 10) {
  return base64url(crypto.randomBytes(24)).slice(0, len);
}
function slugify(s) {
  return String(s || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9\- ]/g, "")
    .replace(/\s+/g, "-")
    .replace(/\-+/g, "-")
    .slice(0, 32);
}
function parseCookieHeader(cookieHeader) {
  const out = {};
  if (!cookieHeader) return out;
  for (const part of cookieHeader.split(";")) {
    const [k, ...rest] = part.trim().split("=");
    if (!k) continue;
    out[k] = decodeURIComponent(rest.join("=") || "");
  }
  return out;
}

// ---------------- DB bootstrap ----------------
async function ensureBasics() {
  // Ensure settings row exists
  await q(`INSERT INTO automod_settings (id) VALUES (1) ON CONFLICT (id) DO NOTHING`);

  // Ensure timeout room exists (admin-only so users can't search it unless timed out logic sends them there)
  await q(
    `INSERT INTO rooms (slug, title, description, visibility, kind, admin_only)
     VALUES ('timeout', 'Timeout', 'Du bist gerade im Timeout.', 'public', 'timeout', true)
     ON CONFLICT (slug) DO NOTHING`
  );
}

// ---------------- session + user loading ----------------
async function loadSessionFromCookie(rawCookie) {
  const sid = verifyCookie(rawCookie);
  if (!sid) return null;

  const sres = await q(
    `SELECT s.id as session_id, s.user_id, s.expires_at, s.session_version,
            u.username, u.role, u.status, u.banned_until, u.muted_until, u.timeout_until, u.session_version as user_sv
     FROM user_sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.id = $1`,
    [sid]
  );
  const row = sres.rows[0];
  if (!row) return null;
  if (new Date(row.expires_at).getTime() < Date.now()) return null;
  if (row.status !== "active") return null;
  if (Number(row.session_version) !== Number(row.user_sv)) return null;

  return {
    sessionId: row.session_id,
    user: {
      id: row.user_id,
      username: row.username,
      role: row.role,
      banned_until: row.banned_until,
      muted_until: row.muted_until,
      timeout_until: row.timeout_until,
      session_version: row.user_sv,
    },
  };
}

function requireAuth(handler) {
  return async (req, res) => {
    try {
      const session = await loadSessionFromCookie(req.cookies?.sid);
      if (!session) return res.status(401).json({ ok: false, error: "not_logged_in" });
      req.session = session;
      return handler(req, res);
    } catch (e) {
      console.error("auth error", e);
      return res.status(500).json({ ok: false, error: "server_error" });
    }
  };
}
function requireAdmin(handler) {
  return requireAuth((req, res) => {
    if (req.session.user.role !== "admin") return res.status(403).json({ ok: false, error: "admin_only" });
    return handler(req, res);
  });
}

// ---------------- automod (simple rate limit) ----------------
const rateState = new Map(); // userId -> {msgTimestamps:[], roomTimestamps:[]}

async function getAutomodSettings() {
  const r = await q(`SELECT * FROM automod_settings WHERE id=1`);
  return r.rows[0] || { max_msgs_per_10s: 6, max_room_switches_per_10s: 8, enable_badword_filter: true, badwords: [], enable_spam_filter: true };
}

function takeToken(userId, kind, limit, windowMs) {
  const now = Date.now();
  const st = rateState.get(userId) || { msg: [], room: [] };
  const arr = kind === "msg" ? st.msg : st.room;

  while (arr.length && arr[0] < now - windowMs) arr.shift();
  if (arr.length >= limit) {
    rateState.set(userId, st);
    return false;
  }
  arr.push(now);
  rateState.set(userId, st);
  return true;
}

function containsBadword(text, badwords) {
  const t = String(text || "").toLowerCase();
  return badwords.some((w) => w && t.includes(String(w).toLowerCase()));
}

// ---------------- message helpers ----------------
async function createMessage({ roomId, authorId, type, content }) {
  const res = await q(
    `INSERT INTO messages (room_id, author_id, type, content)
     VALUES ($1, $2, $3, $4)
     RETURNING id, created_at, room_id, author_id, type, content, is_deleted`,
    [roomId, authorId, type, content]
  );
  return res.rows[0];
}

async function createSystemMessage(roomId, content) {
  return createMessage({ roomId, authorId: null, type: "system", content });
}

async function getRoomBySlug(slug) {
  const r = await q(
    `SELECT id, slug, title, description, visibility, kind, created_by, join_code, is_locked, admin_only
     FROM rooms WHERE slug=$1`,
    [slug]
  );
  return r.rows[0] || null;
}

async function ensureMember(roomId, userId, role = "member") {
  await q(
    `INSERT INTO room_members (room_id, user_id, role)
     VALUES ($1, $2, $3)
     ON CONFLICT (room_id, user_id) DO NOTHING`,
    [roomId, userId, role]
  );
}

async function memberRole(roomId, userId) {
  const r = await q(`SELECT role FROM room_members WHERE room_id=$1 AND user_id=$2`, [roomId, userId]);
  return r.rows[0]?.role || null;
}

// ---------------- server / app ----------------
const app = express();
const server = http.createServer(app);
const io = new IOServer(server, { cors: { origin: true, credentials: true } });

app.set("trust proxy", process.env.TRUST_PROXY ? true : false);
app.use(express.json({ limit: "50kb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public"), { extensions: ["html"] }));

// ---------------- REST: auth ----------------
app.post("/api/auth/register", async (req, res) => {
  try {
    let { username, password } = req.body || {};
    username = String(username || "").trim();
    password = String(password || "");

    if (!/^[A-Za-z0-9_]+$/.test(username)) return res.status(400).json({ ok: false, error: "bad_username" });
    if (username.length < 3 || username.length > USERNAME_MAX) return res.status(400).json({ ok: false, error: "username_length" });
    if (password.length < 6 || password.length > 64) return res.status(400).json({ ok: false, error: "password_length" });

    const passHash = await bcrypt.hash(password, 10);

    const ins = await q(
      `INSERT INTO users (username, pass_hash, role, status)
       VALUES ($1, $2, 'user', 'active')
       RETURNING id, username, role`,
      [username, passHash]
    );

    const user = ins.rows[0];
    const sessionId = crypto.randomUUID();
    const expires = new Date(Date.now() + 1000 * 60 * 60 * 24 * 14).toISOString();

    await q(
      `INSERT INTO user_sessions (id, user_id, session_version, expires_at)
       VALUES ($1, $2, (SELECT session_version FROM users WHERE id=$2), $3)`,
      [sessionId, user.id, expires]
    );

    res.cookie("sid", signCookie(sessionId), { httpOnly: true, sameSite: "lax", secure: true, path: "/" });
    return res.json({ ok: true, user: { id: user.id, username: user.username, role: user.role } });
  } catch (e) {
    if (e?.code === "23505") return res.status(409).json({ ok: false, error: "username_taken" });
    console.error("register error", e);
    return res.status(500).json({ ok: false, error: "server_error" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    let { username, password } = req.body || {};
    username = String(username || "").trim();
    password = String(password || "");

    const r = await q(
      `SELECT id, username, pass_hash, role, status, banned_until, muted_until, timeout_until, session_version
       FROM users WHERE username=$1`,
      [username]
    );
    const u = r.rows[0];
    if (!u) return res.status(401).json({ ok: false, error: "bad_login" });
    if (u.status !== "active") return res.status(403).json({ ok: false, error: "account_inactive" });
    if (isFuture(u.banned_until)) return res.status(403).json({ ok: false, error: "banned" });

    const ok = await bcrypt.compare(password, u.pass_hash);
    if (!ok) return res.status(401).json({ ok: false, error: "bad_login" });

    const sessionId = crypto.randomUUID();
    const expires = new Date(Date.now() + 1000 * 60 * 60 * 24 * 14).toISOString();
    await q(`INSERT INTO user_sessions (id, user_id, session_version, expires_at) VALUES ($1,$2,$3,$4)`, [
      sessionId,
      u.id,
      u.session_version,
      expires,
    ]);

    res.cookie("sid", signCookie(sessionId), { httpOnly: true, sameSite: "lax", secure: true, path: "/" });
    return res.json({ ok: true, user: { id: u.id, username: u.username, role: u.role, muted_until: u.muted_until, timeout_until: u.timeout_until } });
  } catch (e) {
    console.error("login error", e);
    return res.status(500).json({ ok: false, error: "server_error" });
  }
});

app.post("/api/auth/logout", requireAuth(async (req, res) => {
  try {
    await q(`DELETE FROM user_sessions WHERE id=$1`, [req.session.sessionId]);
  } catch {}
  res.clearCookie("sid", { path: "/" });
  return res.json({ ok: true });
}));

app.get("/api/me", requireAuth(async (req, res) => {
  const u = req.session.user;
  return res.json({ ok: true, user: { id: u.id, username: u.username, role: u.role, muted_until: u.muted_until, timeout_until: u.timeout_until } });
}));

// ---------------- REST: profile ----------------
app.post("/api/profile/update", requireAuth(async (req, res) => {
  try {
    const { bio, avatar_url } = req.body || {};
    await q(`UPDATE users SET bio=$1, avatar_url=$2 WHERE id=$3`, [clamp(bio, 140) || null, clamp(avatar_url, 300) || null, req.session.user.id]);
    return res.json({ ok: true });
  } catch (e) {
    console.error("profile update error", e);
    return res.status(500).json({ ok: false, error: "server_error" });
  }
}));

app.post("/api/profile/change-password", requireAuth(async (req, res) => {
  try {
    const { old_password, new_password } = req.body || {};
    const r = await q(`SELECT pass_hash FROM users WHERE id=$1`, [req.session.user.id]);
    const u = r.rows[0];
    if (!u) return res.status(404).json({ ok: false, error: "not_found" });

    const ok = await bcrypt.compare(String(old_password || ""), u.pass_hash);
    if (!ok) return res.status(400).json({ ok: false, error: "wrong_old_password" });

    const np = String(new_password || "");
    if (np.length < 6 || np.length > 64) return res.status(400).json({ ok: false, error: "password_length" });

    const newHash = await bcrypt.hash(np, 10);
    await q(`UPDATE users SET pass_hash=$1, session_version=session_version+1 WHERE id=$2`, [newHash, req.session.user.id]);
    return res.json({ ok: true });
  } catch (e) {
    console.error("change password error", e);
    return res.status(500).json({ ok: false, error: "server_error" });
  }
}));

// ---------------- REST: rooms ----------------
// Listed rooms: public AND not admin_only AND kind='room'
app.get("/api/rooms/list", requireAuth(async (req, res) => {
  try {
    const rooms = (await q(
      `SELECT id, slug, title, description, visibility, kind
       FROM rooms
       WHERE visibility='public' AND admin_only=false AND kind='room'
       ORDER BY id ASC`
    )).rows;
    return res.json({ ok: true, rooms });
  } catch (e) {
    console.error("rooms list error", e);
    return res.status(500).json({ ok: false, error: "server_error" });
  }
}));

// Trending (top 10 by message count)
app.get("/api/rooms/trending", requireAuth(async (req, res) => {
  try {
    const rows = (await q(
      `SELECT r.id, r.slug, r.title, r.description,
              COUNT(m.id) AS msg_count
       FROM rooms r
       LEFT JOIN messages m ON m.room_id=r.id AND m.is_deleted=false
       WHERE r.admin_only=false AND r.kind='room'
       GROUP BY r.id
       ORDER BY msg_count DESC, r.id ASC
       LIMIT 10`
    )).rows;
    return res.json({ ok: true, rooms: rows });
  } catch (e) {
    console.error("trending error", e);
    return res.status(500).json({ ok: false, error: "server_error" });
  }
}));

// Search rooms (includes unlisted; private still needs join_code; hides admin rooms for non-admin)
app.get("/api/rooms/search", requireAuth(async (req, res) => {
  try {
    const query = String(req.query.q || "").trim().toLowerCase();
    if (!query) return res.json({ ok: true, rooms: [] });

    const rows = (await q(
      `SELECT id, slug, title, description, visibility, kind, admin_only, is_locked
       FROM rooms
       WHERE kind IN ('room','dm') AND (LOWER(slug) LIKE $1 OR LOWER(title) LIKE $1)
       ORDER BY admin_only DESC, id ASC
       LIMIT 20`,
      [`%${query}%`]
    )).rows;

    const u = req.session.user;
    const visible = u.role === "admin" ? rows : rows.filter((r) => !r.admin_only);
    return res.json({ ok: true, rooms: visible });
  } catch (e) {
    console.error("rooms search error", e);
    return res.status(500).json({ ok: false, error: "server_error" });
  }
}));

// Create room:
// users: unlisted/private (no password; private uses join_code)
// admin: can also create admin_only rooms (visibility can still be public/unlisted/private, but admin_only restricts)
app.post("/api/rooms/create", requireAuth(async (req, res) => {
  try {
    const u = req.session.user;

    const { title, description, visibility, admin_only } = req.body || {};
    const v = String(visibility || "unlisted");
    const t = clamp(String(title || "").trim(), 32);
    const d = clamp(String(description || "").trim(), 120);

    if (!t) return res.status(400).json({ ok: false, error: "title_required" });
    if (!["public", "unlisted", "private"].includes(v)) return res.status(400).json({ ok: false, error: "bad_visibility" });

    const wantAdminOnly = Boolean(admin_only) && u.role === "admin";
    if (Boolean(admin_only) && u.role !== "admin") return res.status(403).json({ ok: false, error: "admin_only" });

    let slug = slugify(t);
    if (!slug) slug = `room-${crypto.randomBytes(3).toString("hex")}`;
    const exists = await q(`SELECT 1 FROM rooms WHERE slug=$1`, [slug]);
    if (exists.rowCount) slug = `${slug}-${crypto.randomBytes(2).toString("hex")}`;

    const joinCode = v === "private" ? randomJoinCode(10) : null;

    const ins = await q(
      `INSERT INTO rooms (slug, title, description, visibility, kind, created_by, join_code, admin_only)
       VALUES ($1,$2,$3,$4,'room',$5,$6,$7)
       RETURNING id, slug, title, description, visibility, join_code, admin_only`,
      [slug, t, d || null, v, u.id, joinCode, wantAdminOnly]
    );

    const room = ins.rows[0];
    await ensureMember(room.id, u.id, "owner");
    await createSystemMessage(room.id, `Room "${room.title}" wurde erstellt.`);
    io.emit("rooms:changed");

    return res.json({ ok: true, room });
  } catch (e) {
    console.error("room create error", e);
    return res.status(500).json({ ok: false, error: "server_error" });
  }
}));

// Join room by slug; private requires join_code; admin_only requires admin role
app.post("/api/rooms/join", requireAuth(async (req, res) => {
  try {
    const u = req.session.user;
    const { slug, join_code } = req.body || {};
    const s = String(slug || "").trim().toLowerCase();
    if (!s) return res.status(400).json({ ok: false, error: "slug_required" });

    const room = await getRoomBySlug(s);
    if (!room) return res.status(404).json({ ok: false, error: "room_not_found" });

    if (room.admin_only && u.role !== "admin") return res.status(403).json({ ok: false, error: "admin_room" });
    if (room.is_locked && u.role !== "admin" && u.id !== room.created_by) return res.status(403).json({ ok: false, error: "room_locked" });
    if (room.visibility === "private") {
      if (!join_code || String(join_code) !== String(room.join_code || "")) return res.status(403).json({ ok: false, error: "bad_join_code" });
    }

    await ensureMember(room.id, u.id, "member");
    return res.json({ ok: true, room: { id: room.id, slug: room.slug, title: room.title, visibility: room.visibility, admin_only: room.admin_only } });
  } catch (e) {
    console.error("room join error", e);
    return res.status(500).json({ ok: false, error: "server_error" });
  }
}));

app.post("/api/rooms/leave", requireAuth(async (req, res) => {
  try {
    const u = req.session.user;
    const { slug } = req.body || {};
    const s = String(slug || "").trim().toLowerCase();
    if (!s) return res.status(400).json({ ok: false, error: "slug_required" });

    if (isFuture(u.timeout_until)) return res.status(403).json({ ok: false, error: "timeout_active" });

    const room = await getRoomBySlug(s);
    if (!room) return res.status(404).json({ ok: false, error: "room_not_found" });

    await q(`DELETE FROM room_members WHERE room_id=$1 AND user_id=$2`, [room.id, u.id]);
    return res.json({ ok: true });
  } catch (e) {
    console.error("room leave error", e);
    return res.status(500).json({ ok: false, error: "server_error" });
  }
}));

// Room creator can kick (not ban)
app.post("/api/rooms/kick", requireAuth(async (req, res) => {
  try {
    const u = req.session.user;
    const { slug, user_id } = req.body || {};
    const s = String(slug || "").trim().toLowerCase();
    const targetId = Number(user_id);
    if (!s || !targetId) return res.status(400).json({ ok: false, error: "bad_request" });

    const room = await getRoomBySlug(s);
    if (!room) return res.status(404).json({ ok: false, error: "room_not_found" });

    const myRole = await memberRole(room.id, u.id);
    const isOwner = myRole === "owner" || room.created_by === u.id;
    if (!isOwner && u.role !== "admin") return res.status(403).json({ ok: false, error: "not_owner" });

    await q(`DELETE FROM room_members WHERE room_id=$1 AND user_id=$2`, [room.id, targetId]);
    await createSystemMessage(room.id, `Ein Nutzer wurde aus dem Raum entfernt.`);
    io.to(`room:${room.slug}`).emit("room:member_kicked", { user_id: targetId });
    return res.json({ ok: true });
  } catch (e) {
    console.error("room kick error", e);
    return res.status(500).json({ ok: false, error: "server_error" });
  }
}));

// Random room (public/unlisted, not admin_only)
app.get("/api/rooms/random", requireAuth(async (req, res) => {
  try {
    const rows = (await q(
      `SELECT slug, title, description, visibility
       FROM rooms
       WHERE kind='room' AND admin_only=false AND visibility IN ('public','unlisted')
       ORDER BY random()
       LIMIT 1`
    )).rows;
    return res.json({ ok: true, room: rows[0] || null });
  } catch (e) {
    console.error("random room error", e);
    return res.status(500).json({ ok: false, error: "server_error" });
  }
}));

// ---------------- REST: messages ----------------
app.get("/api/messages/history", requireAuth(async (req, res) => {
  try {
    const u = req.session.user;
    const slug = String(req.query.slug || "").trim().toLowerCase();
    const limit = Math.min(Number(req.query.limit || 50) || 50, 100);

    const room = await getRoomBySlug(slug);
    if (!room) return res.status(404).json({ ok: false, error: "room_not_found" });
    if (room.admin_only && u.role !== "admin") return res.status(403).json({ ok: false, error: "admin_room" });

    // require membership for non-public rooms
    if (room.visibility !== "public") {
      const mr = await memberRole(room.id, u.id);
      if (!mr) return res.status(403).json({ ok: false, error: "not_member" });
    } else {
      // public rooms: auto-member
      await ensureMember(room.id, u.id, "member");
    }

    const rows = (await q(
      `SELECT m.id, m.created_at, m.room_id, m.author_id, m.type, m.content, m.is_deleted,
              u.username as author_name
       FROM messages m
       LEFT JOIN users u ON u.id=m.author_id
       WHERE m.room_id=$1
       ORDER BY m.id DESC
       LIMIT $2`,
      [room.id, limit]
    )).rows.reverse();

    return res.json({ ok: true, messages: rows, room: { id: room.id, slug: room.slug, title: room.title, visibility: room.visibility, admin_only: room.admin_only, kind: room.kind } });
  } catch (e) {
    console.error("history error", e);
    return res.status(500).json({ ok: false, error: "server_error" });
  }
}));

app.post("/api/messages/delete", requireAuth(async (req, res) => {
  try {
    const u = req.session.user;
    const id = Number(req.body?.id);
    if (!id) return res.status(400).json({ ok: false, error: "bad_request" });

    const r = await q(`SELECT id, room_id, author_id, is_deleted FROM messages WHERE id=$1`, [id]);
    const m = r.rows[0];
    if (!m) return res.status(404).json({ ok: false, error: "not_found" });
    if (m.is_deleted) return res.json({ ok: true });

    if (u.role !== "admin" && Number(m.author_id) !== Number(u.id)) {
      return res.status(403).json({ ok: false, error: "not_allowed" });
    }

    await q(`UPDATE messages SET is_deleted=true, deleted_by=$1, deleted_at=now() WHERE id=$2`, [u.id, id]);

    // notify room
    const rr = await q(`SELECT slug FROM rooms WHERE id=$1`, [m.room_id]);
    const slug = rr.rows[0]?.slug;
    if (slug) io.to(`room:${slug}`).emit("message:deleted", { id });

    return res.json({ ok: true });
  } catch (e) {
    console.error("delete msg error", e);
    return res.status(500).json({ ok: false, error: "server_error" });
  }
}));

// ---------------- REST: admin moderation ----------------
app.get("/api/admin/users", requireAdmin(async (req, res) => {
  try {
    const qtext = String(req.query.q || "").trim();
    const rows = (await q(
      `SELECT id, username, role, status, banned_until, muted_until, timeout_until
       FROM users
       WHERE ($1='' OR LOWER(username) LIKE LOWER($2))
       ORDER BY id ASC
       LIMIT 50`,
      [qtext, `%${qtext}%`]
    )).rows;
    return res.json({ ok: true, users: rows });
  } catch (e) {
    console.error("admin users error", e);
    return res.status(500).json({ ok: false, error: "server_error" });
  }
}));

app.post("/api/admin/punish", requireAdmin(async (req, res) => {
  try {
    const admin = req.session.user;
    const { user_id, kind, minutes, reason, room_slug } = req.body || {};
    const uid = Number(user_id);
    if (!uid || !kind) return res.status(400).json({ ok: false, error: "bad_request" });

    const until = minutes ? new Date(Date.now() + Number(minutes) * 60_000).toISOString() : null;
    const rroom = room_slug ? await getRoomBySlug(String(room_slug).trim().toLowerCase()) : null;

    if (kind === "ban") {
      await q(`UPDATE users SET banned_until=$1 WHERE id=$2`, [until, uid]);
    } else if (kind === "mute") {
      await q(`UPDATE users SET muted_until=$1 WHERE id=$2`, [until, uid]);
    } else if (kind === "timeout") {
      await q(`UPDATE users SET timeout_until=$1 WHERE id=$2`, [until, uid]);
    } else if (kind === "unban") {
      await q(`UPDATE users SET banned_until=NULL WHERE id=$1`, [uid]);
    } else if (kind === "unmute") {
      await q(`UPDATE users SET muted_until=NULL WHERE id=$1`, [uid]);
    } else if (kind === "untimeout") {
      await q(`UPDATE users SET timeout_until=NULL WHERE id=$1`, [uid]);
    } else if (kind === "kick") {
      if (!rroom) return res.status(400).json({ ok: false, error: "room_required" });
      await q(`DELETE FROM room_members WHERE room_id=$1 AND user_id=$2`, [rroom.id, uid]);
      await createSystemMessage(rroom.id, `Ein Nutzer wurde von einem Admin gekickt.`);
      io.to(`room:${rroom.slug}`).emit("room:member_kicked", { user_id: uid });
    } else {
      return res.status(400).json({ ok: false, error: "bad_kind" });
    }

    await q(
      `INSERT INTO punishments (user_id, by_admin, kind, room_id, until_at, reason)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [uid, admin.id, kind, rroom?.id || null, until, clamp(String(reason || ""), 200) || null]
    );

    await q(
      `INSERT INTO moderation_logs (by_admin, action, target_user, target_room, details)
       VALUES ($1,$2,$3,$4,$5)`,
      [admin.id, kind, uid, rroom?.id || null, JSON.stringify({ minutes: minutes || null, reason: reason || null })]
    );

    // if timeout set -> push them to timeout room on next action; client will react via /api/me refresh
    return res.json({ ok: true });
  } catch (e) {
    console.error("admin punish error", e);
    return res.status(500).json({ ok: false, error: "server_error" });
  }
}));

app.post("/api/admin/system-message", requireAdmin(async (req, res) => {
  try {
    const { room_slug, content } = req.body || {};
    const slug = String(room_slug || "").trim().toLowerCase();
    const msg = clamp(String(content || "").trim(), MSG_MAX_LEN);
    if (!slug || !msg) return res.status(400).json({ ok: false, error: "bad_request" });

    const room = await getRoomBySlug(slug);
    if (!room) return res.status(404).json({ ok: false, error: "room_not_found" });

    const m = await createSystemMessage(room.id, msg);
    io.to(`room:${room.slug}`).emit("message:new", { ...m, author_name: null });
    return res.json({ ok: true });
  } catch (e) {
    console.error("admin sysmsg error", e);
    return res.status(500).json({ ok: false, error: "server_error" });
  }
}));

// ---------------- Socket.IO (realtime) ----------------
io.use(async (socket, next) => {
  try {
    const cookies = parseCookieHeader(socket.handshake.headers.cookie || "");
    const session = await loadSessionFromCookie(cookies.sid);
    if (!session) return next(new Error("not_logged_in"));
    socket.data.session = session;
    next();
  } catch (e) {
    next(new Error("auth_error"));
  }
});

io.on("connection", (socket) => {
  const { user } = socket.data.session;

  socket.emit("hello", { ok: true, user: { id: user.id, username: user.username, role: user.role } });

  socket.on("room:join", async ({ slug, join_code } = {}, cb) => {
    try {
      const settings = await getAutomodSettings();
      if (!takeToken(user.id, "room", settings.max_room_switches_per_10s, 10_000)) {
        return cb?.({ ok: false, error: "rate_limited" });
      }

      const s = String(slug || "").trim().toLowerCase();
      const room = await getRoomBySlug(s);
      if (!room) return cb?.({ ok: false, error: "room_not_found" });

      if (room.admin_only && user.role !== "admin") return cb?.({ ok: false, error: "admin_room" });
      if (room.is_locked && user.role !== "admin" && user.id !== room.created_by) return cb?.({ ok: false, error: "room_locked" });

      if (room.visibility === "private") {
        if (!join_code || String(join_code) !== String(room.join_code || "")) return cb?.({ ok: false, error: "bad_join_code" });
      }

      // public rooms auto member
      await ensureMember(room.id, user.id, "member");

      socket.join(`room:${room.slug}`);
      cb?.({ ok: true, room: { slug: room.slug, title: room.title, visibility: room.visibility, admin_only: room.admin_only } });
    } catch (e) {
      console.error("socket join error", e);
      cb?.({ ok: false, error: "server_error" });
    }
  });

  socket.on("room:leave", async ({ slug } = {}, cb) => {
    try {
      const s = String(slug || "").trim().toLowerCase();
      if (isFuture(user.timeout_until)) return cb?.({ ok: false, error: "timeout_active" });

      socket.leave(`room:${s}`);
      cb?.({ ok: true });
    } catch {
      cb?.({ ok: false, error: "server_error" });
    }
  });

  socket.on("message:send", async ({ slug, content } = {}, cb) => {
    try {
      if (isFuture(user.banned_until)) return cb?.({ ok: false, error: "banned" });
      const settings = await getAutomodSettings();
      if (!takeToken(user.id, "msg", settings.max_msgs_per_10s, 10_000)) return cb?.({ ok: false, error: "rate_limited" });

      const s = String(slug || "").trim().toLowerCase();
      const room = await getRoomBySlug(s);
      if (!room) return cb?.({ ok: false, error: "room_not_found" });
      if (room.admin_only && user.role !== "admin") return cb?.({ ok: false, error: "admin_room" });

      // timeout -> force timeout room only
      if (isFuture(user.timeout_until) && room.slug !== "timeout") {
        return cb?.({ ok: false, error: "timeout_active" });
      }

      // muted -> can't send (system/bot still possible via server)
      if (isFuture(user.muted_until)) return cb?.({ ok: false, error: "muted" });

      const msg = clamp(String(content || "").trim(), MSG_MAX_LEN);
      if (!msg) return cb?.({ ok: false, error: "empty" });

      if (settings.enable_badword_filter && containsBadword(msg, settings.badwords || [])) {
        return cb?.({ ok: false, error: "badword" });
      }

      // membership check (public rooms auto-member)
      if (room.visibility !== "public") {
        const mr = await memberRole(room.id, user.id);
        if (!mr) return cb?.({ ok: false, error: "not_member" });
      } else {
        await ensureMember(room.id, user.id, "member");
      }

      const m = await createMessage({ roomId: room.id, authorId: user.id, type: "text", content: msg });
      io.to(`room:${room.slug}`).emit("message:new", { ...m, author_name: user.username });
      cb?.({ ok: true, message: m });
    } catch (e) {
      console.error("socket send error", e);
      cb?.({ ok: false, error: "server_error" });
    }
  });

  socket.on("message:delete", async ({ id } = {}, cb) => {
    try {
      const mid = Number(id);
      if (!mid) return cb?.({ ok: false, error: "bad_request" });

      const r = await q(`SELECT id, room_id, author_id, is_deleted FROM messages WHERE id=$1`, [mid]);
      const m = r.rows[0];
      if (!m) return cb?.({ ok: false, error: "not_found" });
      if (m.is_deleted) return cb?.({ ok: true });

      if (user.role !== "admin" && Number(m.author_id) !== Number(user.id)) return cb?.({ ok: false, error: "not_allowed" });

      await q(`UPDATE messages SET is_deleted=true, deleted_by=$1, deleted_at=now() WHERE id=$2`, [user.id, mid]);
      const rr = await q(`SELECT slug FROM rooms WHERE id=$1`, [m.room_id]);
      const slug = rr.rows[0]?.slug;
      if (slug) io.to(`room:${slug}`).emit("message:deleted", { id: mid });

      cb?.({ ok: true });
    } catch (e) {
      console.error("socket delete error", e);
      cb?.({ ok: false, error: "server_error" });
    }
  });
});

// ---------------- start ----------------
await ensureBasics();

server.listen(PORT, () => {
  console.log(`Chatly running on port ${PORT}`);
});
