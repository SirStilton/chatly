// Chatly FINAL server.js
// Node 18+, Express + Socket.IO + Supabase Postgres
import express from "express";
import http from "http";
import { Server } from "socket.io";
import session from "express-session";
import bcrypt from "bcryptjs";
import pg from "pg";

const { Pool } = pg;

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: true, credentials: true }
});

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

app.use(express.json());
app.use(express.static("public"));

app.use(
  session({
    name: "chatly.sid",
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: false
    }
  })
);

async function q(text, params = []) {
  const { rows } = await pool.query(text, params);
  return rows;
}

function requireLogin(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "not logged in" });
  next();
}

// AUTH
app.post("/api/auth/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: "missing fields" });
  if (username.length > 10)
    return res.status(400).json({ error: "username too long" });

  const hash = await bcrypt.hash(password, 10);
  try {
    const rows = await q(
      "INSERT INTO users (username, pass_hash) VALUES ($1,$2) RETURNING id, username, role",
      [username, hash]
    );
    req.session.user = rows[0];
    res.json({ user: rows[0] });
  } catch {
    res.status(400).json({ error: "username exists" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body;
  const rows = await q("SELECT * FROM users WHERE username=$1", [username]);
  const user = rows[0];
  if (!user) return res.status(401).json({ error: "invalid login" });

  const ok = await bcrypt.compare(password, user.pass_hash);
  if (!ok) return res.status(401).json({ error: "invalid login" });

  req.session.user = { id: user.id, username: user.username, role: user.role };
  res.json({ user: req.session.user });
});

app.post("/api/auth/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get("/api/me", (req, res) => {
  if (!req.session.user) return res.status(401).json({});
  res.json({ user: req.session.user });
});

// ROOMS
app.get("/api/rooms", requireLogin, async (req, res) => {
  const user = req.session.user;
  const rows =
    user.role === "admin"
      ? await q("SELECT * FROM rooms ORDER BY id")
      : await q("SELECT * FROM rooms WHERE admin_only=false ORDER BY id");
  res.json({ rooms: rows });
});

// MESSAGES
app.get("/api/messages/:roomId", requireLogin, async (req, res) => {
  const rows = await q(
    "SELECT m.*, u.username FROM messages m LEFT JOIN users u ON u.id=m.author_id WHERE room_id=$1 AND is_deleted=false ORDER BY id",
    [req.params.roomId]
  );
  res.json({ messages: rows });
});

app.post("/api/messages", requireLogin, async (req, res) => {
  const { roomId, content, type = "text" } = req.body;
  if (!content || content.length > 100)
    return res.status(400).json({ error: "invalid message" });

  const rows = await q(
    "INSERT INTO messages (room_id, author_id, content, type) VALUES ($1,$2,$3,$4) RETURNING *",
    [roomId, req.session.user.id, content, type]
  );
  const msg = rows[0];
  io.to("room:" + roomId).emit("message", {
    ...msg,
    username: req.session.user.username
  });
  res.json({ message: msg });
});

app.delete("/api/messages/:id", requireLogin, async (req, res) => {
  await q(
    "UPDATE messages SET is_deleted=true WHERE id=$1 AND author_id=$2",
    [req.params.id, req.session.user.id]
  );
  res.json({ ok: true });
});

io.on("connection", (socket) => {
  socket.on("join", (roomId) => {
    socket.join("room:" + roomId);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log("Chatly running on port", PORT);
});

// --- PATCH: auth/me alias ---
app.get("/api/auth/me", (req, res) => {
  if (!req.session.user) return res.status(401).json({});
  res.json({ user: req.session.user });
});

// --- PATCH: rooms/list ---
app.get("/api/rooms/list", requireLogin, async (req, res) => {
  const user = req.session.user;
  const rows = user.role === "admin"
    ? await q("SELECT * FROM rooms ORDER BY id")
    : await q("SELECT * FROM rooms WHERE admin_only=false ORDER BY id");
  res.json({ rooms: rows });
});

// --- PATCH: rooms/trending ---
app.get("/api/rooms/trending", requireLogin, async (req, res) => {
  const rows = await q("SELECT * FROM rooms ORDER BY id DESC LIMIT 10");
  res.json({ rooms: rows });
});
