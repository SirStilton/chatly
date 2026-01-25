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

if (!SESSION_SECRET) {
  console.error("Missing env var SESSION_SECRET");
  process.exit(1);
}
if (!DATABASE_URL) {
  console.error("Missing env var DATABASE_URL");
  process.exit(1);
}

// ---- Postgres Pool ----
// Fix für Supabase/Render: SELF_SIGNED_CERT_IN_CHAIN -> rejectUnauthorized:false
function makePool(connectionString) {
  const isSupabase = /supabase\.com/i.test(connectionString);

  // Default: SSL an (bei Supabase nötig). Wenn du lokal testen willst:
  // setze PGSSL=false in deiner lokalen .env
  const ssl =
    process.env.PGSSL === "false" || process.env.PGSSL === "0"
      ? false
      : isSupabase
        ? { rejectUnauthorized: false }
        : undefined;

  return new Pool({
    connectionString,
    ssl,
    max: 10,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 10_000,
  });
}

const pool = makePool(DATABASE_URL);

async function q(text, params = []) {
  return pool.query(text, params);
}

async function initDb() {
  await q(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      pass_hash TEXT NOT NULL,
      display_name TEXT,
      bio TEXT DEFAULT '',
      avatar_url TEXT DEFAULT '',
      is_admin BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS posts (
      id BIGSERIAL PRIMARY KEY,
      author_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      content TEXT NOT NULL,
      is_html BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await q(`CREATE INDEX IF NOT EXISTS idx_posts_created_at ON posts(created_at DESC);`);
  await q(`CREATE INDEX IF NOT EXISTS idx_posts_author_id ON posts(author_id);`);
}

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
      secure: process.env.NODE_ENV === "production",
      maxAge: 1000 * 60 * 60 * 24 * 14, // 14 Tage
    },
  }),
);

function safeTrim(s, max) {
  if (typeof s !== "string") return "";
  return s.trim().slice(0, max);
}

function requireAuth(req, res, next) {
  if (!req.session?.userId) return res.status(401).json({ error: "not_logged_in" });
  next();
}

async function getMe(req) {
  if (!req.session?.userId) return null;
  const { rows } = await q(
    `SELECT id, username, COALESCE(display_name, username) AS display_name, bio, avatar_url, is_admin
     FROM users WHERE id=$1`,
    [req.session.userId],
  );
  return rows[0] || null;
}

// ---- Static ----
app.use(express.static(path.join(__dirname, "public")));
app.get("/", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ---- Auth ----
app.post("/api/register", async (req, res) => {
  try {
    const username = safeTrim(req.body.username, 24).toLowerCase();
    const password = safeTrim(req.body.password, 200);

    if (!/^[a-z0-9_.-]{3,24}$/.test(username)) {
      return res.status(400).json({ error: "bad_username" });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: "password_too_short" });
    }

    const pass_hash = await bcrypt.hash(password, 10);

    const { rows } = await q(
      `INSERT INTO users (username, pass_hash, display_name)
       VALUES ($1, $2, $1)
       RETURNING id, username, COALESCE(display_name, username) AS display_name, bio, avatar_url, is_admin`,
      [username, pass_hash],
    );

    req.session.userId = rows[0].id;
    res.json({ ok: true, user: rows[0] });
  } catch (e) {
    if (e?.code === "23505") return res.status(409).json({ error: "username_taken" });
    console.error("register error", e);
    res.status(500).json({ error: "server_error" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const username = safeTrim(req.body.username, 24).toLowerCase();
    const password = safeTrim(req.body.password, 200);

    const { rows } = await q(
      `SELECT id, username, pass_hash, COALESCE(display_name, username) AS display_name, bio, avatar_url, is_admin
       FROM users WHERE username=$1`,
      [username],
    );
    const user = rows[0];
    if (!user) return res.status(401).json({ error: "invalid_login" });

    const ok = await bcrypt.compare(password, user.pass_hash);
    if (!ok) return res.status(401).json({ error: "invalid_login" });

    req.session.userId = user.id;
    delete user.pass_hash;
    res.json({ ok: true, user });
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
    const me = await getMe(req);
    res.json({ ok: true, user: me });
  } catch (e) {
    console.error("me error", e);
    res.status(500).json({ error: "server_error" });
  }
});

// ---- Profiles ----
app.get("/api/profile/:username", async (req, res) => {
  try {
    const username = safeTrim(req.params.username, 24).toLowerCase();
    const { rows } = await q(
      `SELECT username, COALESCE(display_name, username) AS display_name, bio, avatar_url, is_admin, created_at
       FROM users WHERE username=$1`,
      [username],
    );
    if (!rows[0]) return res.status(404).json({ error: "not_found" });
    res.json({ ok: true, profile: rows[0] });
  } catch (e) {
    console.error("profile get error", e);
    res.status(500).json({ error: "server_error" });
  }
});

app.post("/api/profile", requireAuth, async (req, res) => {
  try {
    const display_name = safeTrim(req.body.displayName ?? req.body.display_name ?? "", 40);
    const bio = safeTrim(req.body.bio ?? "", 280);
    const avatar_url = safeTrim(req.body.avatarUrl ?? req.body.avatar_url ?? "", 300);

    await q(`UPDATE users SET display_name=$1, bio=$2, avatar_url=$3 WHERE id=$4`, [
      display_name || null,
      bio,
      avatar_url,
      req.session.userId,
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
    const oldPassword = safeTrim(req.body.oldPassword ?? "", 200);
    const newPassword = safeTrim(req.body.newPassword ?? "", 200);
    if (newPassword.length < 6) return res.status(400).json({ error: "password_too_short" });

    const { rows } = await q(`SELECT pass_hash FROM users WHERE id=$1`, [req.session.userId]);
    if (!rows[0]) return res.status(401).json({ error: "not_logged_in" });

    const ok = await bcrypt.compare(oldPassword, rows[0].pass_hash);
    if (!ok) return res.status(401).json({ error: "wrong_password" });

    const pass_hash = await bcrypt.hash(newPassword, 10);
    await q(`UPDATE users SET pass_hash=$1 WHERE id=$2`, [pass_hash, req.session.userId]);

    res.json({ ok: true });
  } catch (e) {
    console.error("password change error", e);
    res.status(500).json({ error: "server_error" });
  }
});

// ---- Posts ----
app.get("/api/posts", async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit ?? "50", 10) || 50, 200);

    const { rows } = await q(
      `SELECT p.id,
              p.title,
              p.content,
              p.is_html,
              to_char(p.created_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS created_at,
              u.username AS author
       FROM posts p
       JOIN users u ON u.id=p.author_id
       ORDER BY p.created_at DESC
       LIMIT $1`,
      [limit],
    );

    res.json({ ok: true, posts: rows });
  } catch (e) {
    console.error("posts list error", e);
    res.status(500).json({ error: "server_error" });
  }
});

app.get("/api/posts/trending", async (_req, res) => {
  try {
    const { rows } = await q(
      `SELECT p.id,
              p.title,
              p.content,
              p.is_html,
              to_char(p.created_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS created_at,
              u.username AS author
       FROM posts p
       JOIN users u ON u.id=p.author_id
       ORDER BY p.created_at DESC
       LIMIT 10`,
    );

    res.json({ ok: true, posts: rows });
  } catch (e) {
    console.error("posts trending error", e);
    res.status(500).json({ error: "server_error" });
  }
});

app.post("/api/posts", requireAuth, async (req, res) => {
  try {
    const me = await getMe(req);
    if (!me) return res.status(401).json({ error: "not_logged_in" });

    const title = safeTrim(req.body.title ?? "", 80);
    const content = safeTrim(req.body.content ?? "", 4000);
    if (!title || !content) return res.status(400).json({ error: "missing_fields" });

    // Admin darf HTML senden (Flag). Alle anderen: immer plain text.
    const wantHtml = !!req.body.isHtml || !!req.body.is_html;
    const is_html = me.is_admin ? wantHtml : false;

    const { rows } = await q(
      `INSERT INTO posts (author_id, title, content, is_html)
       VALUES ($1, $2, $3, $4)
       RETURNING id`,
      [me.id, title, content, is_html],
    );

    res.json({ ok: true, id: rows[0].id });
  } catch (e) {
    console.error("post create error", e);
    res.status(500).json({ error: "server_error" });
  }
});

app.delete("/api/posts/:id", requireAuth, async (req, res) => {
  try {
    const me = await getMe(req);
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ error: "bad_id" });

    const { rows } = await q(`SELECT author_id FROM posts WHERE id=$1`, [id]);
    if (!rows[0]) return res.status(404).json({ error: "not_found" });

    const isOwner = rows[0].author_id === me.id;
    if (!isOwner && !me.is_admin) return res.status(403).json({ error: "forbidden" });

    await q(`DELETE FROM posts WHERE id=$1`, [id]);
    res.json({ ok: true });
  } catch (e) {
    console.error("post delete error", e);
    res.status(500).json({ error: "server_error" });
  }
});

// ---- Admin ----
app.delete("/api/admin/posts", requireAuth, async (req, res) => {
  try {
    const me = await getMe(req);
    if (!me?.is_admin) return res.status(403).json({ error: "forbidden" });

    await q(`DELETE FROM posts`);
    res.json({ ok: true });
  } catch (e) {
    console.error("admin wipe error", e);
    res.status(500).json({ error: "server_error" });
  }
});

app.get("/api/health", async (_req, res) => {
  try {
    await q("SELECT 1");
    res.json({ ok: true });
  } catch {
    res.status(500).json({ ok: false });
  }
});

const server = app.listen(PORT, async () => {
  try {
    await initDb();
    console.log(`Chatly listening on :${PORT}`);
  } catch (e) {
    console.error("DB init failed:", e);
    process.exit(1);
  }
});

process.on("SIGTERM", async () => {
  server.close(() => {});
  try {
    await pool.end();
  } catch {}
  process.exit(0);
});
