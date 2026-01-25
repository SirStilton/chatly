import express from "express";
import session from "express-session";
import bcrypt from "bcryptjs";
import pgPkg from "pg";
import path from "path";
import { fileURLToPath } from "url";

const { Pool } = pgPkg;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = process.env.PORT || 10000;
const DATABASE_URL = process.env.DATABASE_URL;
const SESSION_SECRET = process.env.SESSION_SECRET;

if (!DATABASE_URL) throw new Error("Missing env DATABASE_URL");
if (!SESSION_SECRET) throw new Error("Missing env SESSION_SECRET");

// --- Supabase/Render SSL Fix ---
function stripQuery(urlString) {
  try {
    const u = new URL(urlString);
    u.search = "";
    return u.toString();
  } catch {
    return urlString;
  }
}
function isSupabase(urlString) {
  const s = String(urlString || "").toLowerCase();
  return s.includes("supabase.com") || s.includes("pooler");
}

const pool = new Pool({
  connectionString: stripQuery(DATABASE_URL),
  ssl: isSupabase(DATABASE_URL) ? { rejectUnauthorized: false } : undefined,
  max: 10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000,
});

async function q(text, params = []) {
  return pool.query(text, params);
}

// --- helpers ---
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

async function initDb() {
  // Users: entspricht deinem Schema, aber idempotent (crasht nie)
  await q(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      pass_hash TEXT NOT NULL,
      role TEXT DEFAULT 'user',
      bio TEXT DEFAULT '',
      avatar TEXT DEFAULT '',
      status TEXT DEFAULT 'active',
      banned_until TIMESTAMPTZ,
      muted_until TIMESTAMPTZ,
      timeout_until TIMESTAMPTZ,
      needs_password_change BOOLEAN DEFAULT FALSE,
      admin_panel_hash TEXT,
      admin_panel_needs_setup BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      session_version INTEGER DEFAULT 0,
      avatar_url TEXT
    );
  `);

  // Falls Spalten fehlen (ältere Versionen), hinzufügen:
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'user';`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS bio TEXT DEFAULT '';`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar TEXT DEFAULT '';`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'active';`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS banned_until TIMESTAMPTZ;`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS muted_until TIMESTAMPTZ;`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS timeout_until TIMESTAMPTZ;`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS needs_password_change BOOLEAN DEFAULT FALSE;`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS session_version INTEGER DEFAULT 0;`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url TEXT;`);

  // Posts (für dein script.js Feed)
  await q(`
    CREATE TABLE IF NOT EXISTS posts (
      id BIGSERIAL PRIMARY KEY,
      author_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      content TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await q(`CREATE INDEX IF NOT EXISTS idx_posts_created_at ON posts(created_at DESC);`);
  await q(`CREATE INDEX IF NOT EXISTS idx_posts_author_id ON posts(author_id);`);

  // Optional: Default Admin anlegen, falls keiner existiert
  // (nur damit du überhaupt admin testen kannst)
  const adminExists = await q(`SELECT 1 FROM users WHERE role='admin' LIMIT 1;`);
  if (adminExists.rowCount === 0) {
    const pass_hash = await bcrypt.hash("admin123", 12);
    await q(
      `INSERT INTO users (username, pass_hash, role, bio)
       VALUES ($1,$2,'admin',$3)
       ON CONFLICT (username) DO NOTHING;`,
      ["admin", pass_hash, "Master Administrator (CHANGE PW)"]
    );
    console.log("Default admin created: admin / admin123 (change it!)");
  }
}

// --- express app ---
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
      secure: "auto", // wichtig auf Render
      maxAge: 1000 * 60 * 60 * 24 * 14,
    },
  })
);

// Static aus /public
app.use(express.static(path.join(__dirname, "public"), { extensions: ["html"] }));
app.get("/", (_req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

// --- auth helpers ---
function requireAuth(req, res, next) {
  if (!req.session?.userId) return res.status(401).json({ error: "not_logged_in" });
  next();
}

async function getMe(req) {
  if (!req.session?.userId) return null;
  const r = await q(
    `SELECT id, username, role, bio, avatar, status, banned_until, muted_until, timeout_until
     FROM users WHERE id=$1`,
    [req.session.userId]
  );
  return r.rows[0] || null;
}

// --- API ---
app.get("/api/health", async (_req, res) => {
  try {
    await q("SELECT 1;");
    res.json({ ok: true });
  } catch {
    res.status(500).json({ ok: false });
  }
});

app.get("/api/me", async (req, res) => {
  try {
    const me = await getMe(req);
    res.json({ ok: true, user: me });
  } catch (e) {
    console.error("me error", e);
    res.status(500).json({ error: "server_error" });
  }
});

app.post("/api/register", async (req, res) => {
  try {
    const username = normUsername(req.body.username);
    const password = String(req.body.password || "");
    const bio = safeText(req.body.bio, 200);
    const avatar = safeText(req.body.avatar, 300);

    if (!validUsername(username)) return res.status(400).json({ error: "bad_username" });
    if (!validPassword(password)) return res.status(400).json({ error: "bad_password" });

    const pass_hash = await bcrypt.hash(password, 12);

    const r = await q(
      `INSERT INTO users (username, pass_hash, role, bio, avatar, status)
       VALUES ($1,$2,'user',$3,$4,'active')
       RETURNING id;`,
      [username, pass_hash, bio, avatar]
    );

    req.session.userId = r.rows[0].id;
    const me = await getMe(req);
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
    const password = String(req.body.password || "");

    const r = await q(`SELECT id, pass_hash FROM users WHERE username=$1 LIMIT 1;`, [username]);
    const u = r.rows[0];
    if (!u) return res.status(401).json({ error: "invalid_login" });

    const ok = await bcrypt.compare(password, u.pass_hash);
    if (!ok) return res.status(401).json({ error: "invalid_login" });

    req.session.userId = u.id;
    const me = await getMe(req);
    res.json({ ok: true, user: me });
  } catch (e) {
    console.error("login error", e);
    res.status(500).json({ error: "server_error" });
  }
});

app.post("/api/logout", (req, res) => {
  req.session?.destroy(() => res.json({ ok: true }));
});

// Profile
app.get("/api/profile/:username", async (req, res) => {
  try {
    const username = normUsername(req.params.username);
    const r = await q(
      `SELECT username, role, bio, avatar, status, created_at
       FROM users WHERE username=$1 LIMIT 1;`,
      [username]
    );
    if (!r.rows[0]) return res.status(404).json({ error: "not_found" });
    res.json({ ok: true, profile: r.rows[0] });
  } catch (e) {
    console.error("profile get error", e);
    res.status(500).json({ error: "server_error" });
  }
});

app.post("/api/profile", requireAuth, async (req, res) => {
  try {
    const bio = safeText(req.body.bio, 200);
    const avatar = safeText(req.body.avatar, 300);

    await q(`UPDATE users SET bio=$1, avatar=$2 WHERE id=$3;`, [
      bio,
      avatar,
      req.session.userId
    ]);

    const me = await getMe(req);
    res.json({ ok: true, user: me });
  } catch (e) {
    console.error("profile update error", e);
    res.status(500).json({ error: "server_error" });
  }
});

app.post("/api/profile/password", requireAuth, async (req, res) => {
  try {
    const oldPassword = String(req.body.oldPassword || "");
    const newPassword = String(req.body.newPassword || "");

    if (!validPassword(newPassword)) return res.status(400).json({ error: "bad_password" });

    const r = await q(`SELECT pass_hash FROM users WHERE id=$1;`, [req.session.userId]);
    if (!r.rows[0]) return res.status(401).json({ error: "not_logged_in" });

    const ok = await bcrypt.compare(oldPassword, r.rows[0].pass_hash);
    if (!ok) return res.status(401).json({ error: "wrong_password" });

    const pass_hash = await bcrypt.hash(newPassword, 12);
    await q(`UPDATE users SET pass_hash=$1, session_version=session_version+1 WHERE id=$2;`, [
      pass_hash,
      req.session.userId
    ]);

    res.json({ ok: true });
  } catch (e) {
    console.error("password change error", e);
    res.status(500).json({ error: "server_error" });
  }
});

// Posts
app.get("/api/posts", async (_req, res) => {
  try {
    const r = await q(
      `SELECT p.id, p.title, p.content, p.created_at,
              u.username AS author
       FROM posts p
       JOIN users u ON u.id=p.author_id
       ORDER BY p.created_at DESC
       LIMIT 200;`
    );

    // script.js erwartet created_at als string, das passt so.
    res.json({ ok: true, posts: r.rows });
  } catch (e) {
    console.error("posts list error", e);
    res.status(500).json({ error: "server_error" });
  }
});

app.post("/api/posts", requireAuth, async (req, res) => {
  try {
    const title = safeText(req.body.title, 80);
    const content = safeText(req.body.content, 4000);
    if (!title || !content) return res.status(400).json({ error: "missing_fields" });

    await q(
      `INSERT INTO posts (author_id, title, content)
       VALUES ($1,$2,$3);`,
      [req.session.userId, title, content]
    );

    res.json({ ok: true });
  } catch (e) {
    console.error("post create error", e);
    res.status(500).json({ error: "server_error" });
  }
});

app.delete("/api/posts/:id", requireAuth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ error: "bad_id" });

    const me = await getMe(req);
    if (!me) return res.status(401).json({ error: "not_logged_in" });

    const r = await q(`SELECT author_id FROM posts WHERE id=$1`, [id]);
    if (!r.rows[0]) return res.status(404).json({ error: "not_found" });

    const isOwner = Number(r.rows[0].author_id) === Number(me.id);
    if (!isOwner && me.role !== "admin") return res.status(403).json({ error: "forbidden" });

    await q(`DELETE FROM posts WHERE id=$1`, [id]);
    res.json({ ok: true });
  } catch (e) {
    console.error("post delete error", e);
    res.status(500).json({ error: "server_error" });
  }
});

// Admin: alle Posts löschen (für deinen "btn-admin")
app.delete("/api/admin/posts", requireAuth, async (req, res) => {
  try {
    const me = await getMe(req);
    if (!me || me.role !== "admin") return res.status(403).json({ error: "forbidden" });

    await q(`DELETE FROM posts;`);
    res.json({ ok: true });
  } catch (e) {
    console.error("admin wipe error", e);
    res.status(500).json({ error: "server_error" });
  }
});

// Start
app.listen(PORT, async () => {
  try {
    await initDb();
    console.log(`Chatly listening on :${PORT}`);
  } catch (e) {
    console.error("DB init failed:", e);
    process.exit(1);
  }
});
