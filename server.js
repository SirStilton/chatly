import express from "express";
import session from "express-session";
import bcrypt from "bcryptjs";
import pgPkg from "pg";
import path from "path";
import http from "http";
import { WebSocketServer } from "ws";
import { fileURLToPath } from "url";

const { Pool } = pgPkg;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = process.env.PORT || 10000;
const DATABASE_URL = process.env.DATABASE_URL;
const SESSION_SECRET = process.env.SESSION_SECRET;

if (!DATABASE_URL) {
  console.error("Missing env var DATABASE_URL");
  process.exit(1);
}
if (!SESSION_SECRET) {
  console.error("Missing env var SESSION_SECRET");
  process.exit(1);
}

const isSupabase = /supabase\.com/i.test(DATABASE_URL);

// SSL-Fix für Render <-> Supabase Pooler (SELF_SIGNED_CERT_IN_CHAIN)
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: isSupabase ? { rejectUnauthorized: false } : undefined,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

async function q(text, params = []) {
  return pool.query(text, params);
}

// ---- Schema-Helper (damit wir NIE wieder "column does not exist" bekommen)
const colCache = new Map();
async function hasColumn(table, column) {
  const key = `${table}.${column}`;
  if (colCache.has(key)) return colCache.get(key);
  const r = await q(
    `SELECT 1
     FROM information_schema.columns
     WHERE table_schema='public' AND table_name=$1 AND column_name=$2
     LIMIT 1;`,
    [table, column],
  );
  const ok = r.rowCount > 0;
  colCache.set(key, ok);
  return ok;
}

function normUsername(u) {
  return String(u || "").trim().toLowerCase();
}
function validUsername(u) {
  return /^[a-z0-9._-]{3,24}$/.test(u);
}
function validPassword(p) {
  return typeof p === "string" && p.length >= 6 && p.length <= 128;
}
function safeText(s, max) {
  return String(s ?? "").trim().slice(0, max);
}
function safeRoomSlug(s) {
  const x = String(s || "lobby").trim().toLowerCase();
  const cleaned = x.replace(/[^a-z0-9_-]/g, "").slice(0, 32);
  return cleaned || "lobby";
}
function minutesFromNow(min) {
  const d = new Date();
  d.setMinutes(d.getMinutes() + min);
  return d;
}

async function initDb() {
  // Wir erstellen nur, falls es NICHT existiert.
  // Deine DB hat die Tabellen schon – das ist nur "sicher".
  await q(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      pass_hash TEXT NOT NULL,
      role TEXT DEFAULT 'user',
      bio TEXT DEFAULT '',
      avatar TEXT DEFAULT '',
      status TEXT DEFAULT 'active',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      banned_until TIMESTAMPTZ,
      muted_until TIMESTAMPTZ,
      timeout_until TIMESTAMPTZ,
      needs_password_change BOOLEAN DEFAULT FALSE,
      admin_panel_hash TEXT,
      admin_panel_needs_setup BOOLEAN DEFAULT FALSE,
      session_version INTEGER DEFAULT 0,
      avatar_url TEXT
    );
  `);

  // Falls du diese Spalten noch nicht hast (bei dir sind sie aber da),
  // fügen wir sie idempotent hinzu:
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS bio TEXT DEFAULT '';`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar TEXT DEFAULT '';`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url TEXT;`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'user';`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'active';`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS banned_until TIMESTAMPTZ;`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS muted_until TIMESTAMPTZ;`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS timeout_until TIMESTAMPTZ;`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS needs_password_change BOOLEAN DEFAULT FALSE;`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS admin_panel_hash TEXT;`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS admin_panel_needs_setup BOOLEAN DEFAULT FALSE;`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS session_version INTEGER DEFAULT 0;`);

  // minimal rooms/messages (falls du sie brauchst)
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

  // Wir versuchen beide "Styles" (room_id/body ODER room/content). Falls schon existiert: ok.
  await q(`
    CREATE TABLE IF NOT EXISTS messages (
      id BIGSERIAL PRIMARY KEY,
      room TEXT DEFAULT 'lobby',
      content TEXT,
      room_id BIGINT,
      body TEXT,
      author_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      is_admin BOOLEAN DEFAULT FALSE
    );
  `);

  // Default room
  const rc = await q(`SELECT COUNT(*)::int AS c FROM rooms;`);
  if ((rc.rows[0]?.c ?? 0) === 0) {
    await q(`INSERT INTO rooms (slug, title, is_private) VALUES ('lobby','Lobby',FALSE) ON CONFLICT DO NOTHING;`);
  }

  // Optional: Admin auto-anlegen, aber NUR wenn es keinen Admin gibt
  const adminExists = await q(`SELECT 1 FROM users WHERE role='admin' LIMIT 1;`);
  if (adminExists.rowCount === 0) {
    const pass_hash = await bcrypt.hash("admin123", 12);
    const panel_hash = await bcrypt.hash("admin12", 12);
    await q(
      `INSERT INTO users (username, pass_hash, role, needs_password_change, admin_panel_hash, admin_panel_needs_setup, bio)
       VALUES ($1,$2,'admin',TRUE,$3,TRUE,$4)
       ON CONFLICT (username) DO NOTHING;`,
      ["admin", pass_hash, panel_hash, "Master Administrator"],
    );
    console.log("Created default admin: admin / admin123 (CHANGE THIS!)");
  }
}

// ---- Express App
const app = express();
app.set("trust proxy", 1);

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    name: "chatly.sid",
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: "auto", // wichtig auf Render (Proxy/HTTPS)
      maxAge: 1000 * 60 * 60 * 24 * 14,
    },
  }),
);

// Static
app.use(express.static(path.join(__dirname, "public"), { extensions: ["html"] }));
app.get("/", (_req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

// ---- Auth helpers
function requireAuth(req, res, next) {
  if (!req.session?.userId) return res.status(401).json({ error: "not_logged_in" });
  next();
}
async function getMeById(userId) {
  const hasAvatarUrl = await hasColumn("users", "avatar_url");
  const r = await q(
    `SELECT id, username, role,
            bio,
            ${hasAvatarUrl ? "avatar_url" : "NULL"} AS avatar_url,
            avatar,
            status,
            banned_until, muted_until, timeout_until,
            needs_password_change,
            admin_panel_needs_setup,
            session_version
     FROM users WHERE id=$1`,
    [userId],
  );
  return r.rows[0] || null;
}
function isStillBanned(me) {
  const now = new Date();
  if (me?.banned_until && new Date(me.banned_until) > now) return true;
  return false;
}

// ---- API
app.post("/api/register", async (req, res) => {
  try {
    const username = normUsername(req.body.username);
    const password = req.body.password;

    if (!validUsername(username)) return res.status(400).json({ error: "bad_username" });
    if (!validPassword(password)) return res.status(400).json({ error: "bad_password" });

    const pass_hash = await bcrypt.hash(password, 12);

    const r = await q(
      `INSERT INTO users (username, pass_hash, role, status, bio, avatar, session_version)
       VALUES ($1,$2,'user','active','', '', 0)
       RETURNING id;`,
      [username, pass_hash],
    );

    req.session.userId = r.rows[0].id;
    const me = await getMeById(req.session.userId);
    res.json({ ok: true, user: me });
  } catch (e) {
    if (e?.code === "23505") return res.status(409).json({ error: "username_taken" });
    console.error("register error", e);
    res.status(500).json({ error: "server_error" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const username = normUsername(req.body.username);
    const password = safeText(req.body.password, 200);

    const r = await q(
      `SELECT id, pass_hash FROM users WHERE username=$1 LIMIT 1;`,
      [username],
    );
    const u = r.rows[0];
    if (!u) return res.status(401).json({ error: "invalid_login" });

    const ok = await bcrypt.compare(password, u.pass_hash);
    if (!ok) return res.status(401).json({ error: "invalid_login" });

    req.session.userId = u.id;
    const me = await getMeById(u.id);

    if (isStillBanned(me)) {
      req.session.destroy(() => {});
      return res.status(403).json({ error: "banned", until: me.banned_until });
    }

    res.json({ ok: true, user: me });
  } catch (e) {
    console.error("login error", e);
    res.status(500).json({ error: "server_error" });
  }
});

app.post("/api/logout", (req, res) => {
  req.session?.destroy(() => res.json({ ok: true }));
});

app.get("/api/me", async (req, res) => {
  try {
    if (!req.session?.userId) return res.json({ ok: true, user: null });
    const me = await getMeById(req.session.userId);
    res.json({ ok: true, user: me });
  } catch (e) {
    console.error("me error", e);
    res.status(500).json({ error: "server_error" });
  }
});

// Profile update (bio/avatar)
app.post("/api/profile", requireAuth, async (req, res) => {
  try {
    const bio = safeText(req.body.bio, 200);
    const avatar = safeText(req.body.avatar, 300);
    const avatar_url = safeText(req.body.avatar_url ?? req.body.avatarUrl ?? "", 300);

    const hasAvatarUrl = await hasColumn("users", "avatar_url");
    if (hasAvatarUrl) {
      await q(`UPDATE users SET bio=$1, avatar=$2, avatar_url=$3 WHERE id=$4`, [
        bio,
        avatar,
        avatar_url || null,
        req.session.userId,
      ]);
    } else {
      await q(`UPDATE users SET bio=$1, avatar=$2 WHERE id=$3`, [bio, avatar, req.session.userId]);
    }

    const me = await getMeById(req.session.userId);
    res.json({ ok: true, user: me });
  } catch (e) {
    console.error("profile update error", e);
    res.status(500).json({ error: "server_error" });
  }
});

// ---- Admin Panel (Setup/Unlock/Lock) + Punish + Force Room + Admin HTML sending flag
function requireAdmin(req, res, next) {
  if (!req.session?.userId) return res.status(401).json({ error: "not_logged_in" });
  next();
}
async function requireAdminRole(req, res, next) {
  const me = await getMeById(req.session.userId);
  if (!me) return res.status(401).json({ error: "not_logged_in" });
  if (me.role !== "admin") return res.status(403).json({ error: "not_admin" });
  req.me = me;
  next();
}
function requireAdminPanelUnlocked(req, res, next) {
  if (!req.session?.adminPanelUnlocked) return res.status(403).json({ error: "admin_panel_locked" });
  next();
}

app.post("/api/admin/setup", requireAdmin, requireAdminRole, async (req, res) => {
  try {
    const newPin = safeText(req.body.pin ?? req.body.password ?? "", 200);
    if (newPin.length < 6) return res.status(400).json({ error: "pin_too_short" });

    const hash = await bcrypt.hash(newPin, 12);
    await q(`UPDATE users SET admin_panel_hash=$1, admin_panel_needs_setup=FALSE WHERE id=$2`, [
      hash,
      req.session.userId,
    ]);

    req.session.adminPanelUnlocked = true;
    res.json({ ok: true });
  } catch (e) {
    console.error("admin setup error", e);
    res.status(500).json({ error: "server_error" });
  }
});

app.post("/api/admin/unlock", requireAdmin, requireAdminRole, async (req, res) => {
  try {
    const pin = safeText(req.body.pin ?? req.body.password ?? "", 200);
    const r = await q(`SELECT admin_panel_hash FROM users WHERE id=$1`, [req.session.userId]);
    const h = r.rows[0]?.admin_panel_hash;
    if (!h) return res.status(400).json({ error: "admin_panel_not_setup" });

    const ok = await bcrypt.compare(pin, h);
    if (!ok) return res.status(401).json({ error: "wrong_pin" });

    req.session.adminPanelUnlocked = true;
    res.json({ ok: true });
  } catch (e) {
    console.error("admin unlock error", e);
    res.status(500).json({ error: "server_error" });
  }
});

app.post("/api/admin/lock", requireAdmin, requireAdminRole, async (req, res) => {
  req.session.adminPanelUnlocked = false;
  res.json({ ok: true });
});

app.post("/api/admin/punish", requireAdmin, requireAdminRole, requireAdminPanelUnlocked, async (req, res) => {
  try {
    const username = normUsername(req.body.username);
    const type = String(req.body.type || "").toLowerCase(); // ban|mute|timeout
    const minutes = Math.max(1, Math.min(60 * 24 * 30, parseInt(req.body.minutes || "10", 10)));
    if (!validUsername(username)) return res.status(400).json({ error: "bad_username" });
    if (!["ban", "mute", "timeout"].includes(type)) return res.status(400).json({ error: "bad_type" });

    const u = await q(`SELECT id, role FROM users WHERE username=$1`, [username]);
    const target = u.rows[0];
    if (!target) return res.status(404).json({ error: "not_found" });
    if (target.role === "admin") return res.status(400).json({ error: "cannot_punish_admin" });

    const until = minutesFromNow(minutes);

    if (type === "ban") {
      await q(`UPDATE users SET banned_until=$1, session_version=session_version+1 WHERE id=$2`, [until, target.id]);
    } else if (type === "mute") {
      await q(`UPDATE users SET muted_until=$1 WHERE id=$2`, [until, target.id]);
    } else {
      await q(`UPDATE users SET timeout_until=$1 WHERE id=$2`, [until, target.id]);
    }

    res.json({ ok: true, until });
  } catch (e) {
    console.error("punish error", e);
    res.status(500).json({ error: "server_error" });
  }
});

// ---- Rooms + Messages (für deine Chat UI)
app.get("/api/rooms", async (_req, res) => {
  try {
    const r = await q(`SELECT slug, title, is_private FROM rooms ORDER BY slug ASC LIMIT 200;`);
    res.json({ ok: true, rooms: r.rows });
  } catch (e) {
    console.error("rooms error", e);
    res.status(500).json({ error: "server_error" });
  }
});

app.post("/api/rooms", requireAuth, async (req, res) => {
  try {
    const slug = safeRoomSlug(req.body.slug);
    const title = safeText(req.body.title || slug, 40);
    await q(
      `INSERT INTO rooms (slug, title, created_by) VALUES ($1,$2,$3)
       ON CONFLICT (slug) DO NOTHING;`,
      [slug, title, req.session.userId],
    );
    res.json({ ok: true, slug });
  } catch (e) {
    console.error("create room error", e);
    res.status(500).json({ error: "server_error" });
  }
});

app.get("/api/messages", async (req, res) => {
  try {
    const slug = safeRoomSlug(req.query.room || "lobby");
    const limit = Math.min(200, Math.max(1, parseInt(req.query.limit || "50", 10)));

    // Unterstützt beide Schemas:
    const msgHasRoomId = await hasColumn("messages", "room_id");
    const msgHasBody = await hasColumn("messages", "body");

    if (msgHasRoomId && msgHasBody) {
      const room = await q(`SELECT id FROM rooms WHERE slug=$1`, [slug]);
      const roomId = room.rows[0]?.id;
      if (!roomId) return res.json({ ok: true, messages: [] });

      const r = await q(
        `SELECT m.id, m.created_at,
                m.body AS content,
                u.username AS author,
                COALESCE(u.avatar_url, u.avatar, '') AS avatar,
                u.role AS role
         FROM messages m
         LEFT JOIN users u ON u.id=m.author_id
         WHERE m.room_id=$1
         ORDER BY m.id DESC
         LIMIT $2`,
        [roomId, limit],
      );
      return res.json({ ok: true, messages: r.rows.reverse(), room: slug });
    }

    // Fallback: room + content
    const r = await q(
      `SELECT m.id, m.created_at,
              COALESCE(m.content,'') AS content,
              u.username AS author,
              COALESCE(u.avatar_url, u.avatar, '') AS avatar,
              u.role AS role
       FROM messages m
       LEFT JOIN users u ON u.id=m.author_id
       WHERE COALESCE(m.room,'lobby')=$1
       ORDER BY m.id DESC
       LIMIT $2`,
      [slug, limit],
    );
    res.json({ ok: true, messages: r.rows.reverse(), room: slug });
  } catch (e) {
    console.error("messages error", e);
    res.status(500).json({ error: "server_error" });
  }
});

// ---- WebSocket Chat
const server = http.createServer(app);
const wss = new WebSocketServer({ noServer: true });
const sockets = new Set();

function isMuted(me) {
  const now = new Date();
  if (me?.muted_until && new Date(me.muted_until) > now) return true;
  return false;
}
function isTimedOut(me) {
  const now = new Date();
  if (me?.timeout_until && new Date(me.timeout_until) > now) return true;
  return false;
}

server.on("upgrade", (req, socket, head) => {
  // session ist nötig:
  // express-session hängt an req, ABER nur wenn express-session middleware schon lief.
  // Bei upgrade müssen wir’s manuell ausführen:
  const res = {
    getHeader() {},
    setHeader() {},
    writeHead() {},
    end() {},
  };

  app._router.handle(req, res, async () => {
    try {
      if (!req.session?.userId) {
        socket.destroy();
        return;
      }
      wss.handleUpgrade(req, socket, head, (ws) => {
        ws.userId = req.session.userId;
        ws.room = req.session.room || "lobby";
        sockets.add(ws);

        ws.send(JSON.stringify({ type: "hello", room: ws.room }));

        ws.on("message", async (buf) => {
          let data;
          try {
            data = JSON.parse(buf.toString("utf8"));
          } catch {
            return;
          }

          if (data?.type === "join") {
            ws.room = safeRoomSlug(data.room || data.slug || "lobby");
            if (req.session) req.session.room = ws.room;
            ws.send(JSON.stringify({ type: "joined", room: ws.room }));
            return;
          }

          if (data?.type === "chat") {
            const text = safeText(data.text, 500);
            if (!text) return;

            const me = await getMeById(ws.userId);
            if (!me) return;

            if (isStillBanned(me)) {
              ws.send(JSON.stringify({ type: "system", event: "banned", until: me.banned_until }));
              ws.close();
              return;
            }
            if (isTimedOut(me)) {
              ws.send(JSON.stringify({ type: "system", event: "timeout", until: me.timeout_until }));
              return;
            }
            if (isMuted(me)) {
              ws.send(JSON.stringify({ type: "system", event: "muted", until: me.muted_until }));
              return;
            }

            const allowHtml = me.role === "admin" && !!data.is_html; // Admin darf HTML senden (dein Wunsch)
            const msgHasRoomId = await hasColumn("messages", "room_id");
            const msgHasBody = await hasColumn("messages", "body");

            let msgRow;

            if (msgHasRoomId && msgHasBody) {
              const room = await q(`SELECT id FROM rooms WHERE slug=$1`, [ws.room]);
              const roomId = room.rows[0]?.id;
              if (!roomId) return;

              const ins = await q(
                `INSERT INTO messages (room_id, author_id, body, is_admin)
                 VALUES ($1,$2,$3,$4)
                 RETURNING id, created_at`,
                [roomId, ws.userId, text, allowHtml],
              );

              const out = await q(
                `SELECT m.id, m.created_at,
                        m.body AS content,
                        u.username AS author,
                        COALESCE(u.avatar_url, u.avatar, '') AS avatar,
                        u.role AS role
                 FROM messages m
                 LEFT JOIN users u ON u.id=m.author_id
                 WHERE m.id=$1`,
                [ins.rows[0].id],
              );
              msgRow = out.rows[0];
            } else {
              const ins = await q(
                `INSERT INTO messages (room, author_id, content, is_admin)
                 VALUES ($1,$2,$3,$4)
                 RETURNING id, created_at`,
                [ws.room, ws.userId, text, allowHtml],
              );

              const out = await q(
                `SELECT m.id, m.created_at,
                        COALESCE(m.content,'') AS content,
                        u.username AS author,
                        COALESCE(u.avatar_url, u.avatar, '') AS avatar,
                        u.role AS role
                 FROM messages m
                 LEFT JOIN users u ON u.id=m.author_id
                 WHERE m.id=$1`,
                [ins.rows[0].id],
              );
              msgRow = out.rows[0];
            }

            // Broadcast nur an gleiche room
            for (const client of sockets) {
              if (client.readyState !== 1) continue;
              if (client.room !== ws.room) continue;
              client.send(JSON.stringify({ type: "message", message: msgRow }));
            }
          }
        });

        ws.on("close", () => {
          sockets.delete(ws);
        });
      });
    } catch {
      socket.destroy();
    }
  });
});

server.listen(parseInt(PORT, 10), async () => {
  try {
    await initDb();
    console.log(`Chatly listening on :${PORT}`);
  } catch (e) {
    console.error("DB init failed:", e);
    process.exit(1);
  }
});

// Sauberes shutdown
process.on("SIGTERM", async () => {
  try {
    await pool.end();
  } catch {}
  process.exit(0);
});
