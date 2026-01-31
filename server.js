// Chatly server.js – FINAL (Automod + Render + Supabase)
// Node >=18, ESM

import express from 'express';
import http from 'http';
import session from 'express-session';
import bcrypt from 'bcryptjs';
import pg from 'pg';
import { Server } from 'socket.io';

const { Pool } = pg;

/* =========================
   App & Server
========================= */
const app = express();
app.set('trust proxy', process.env.TRUST_PROXY === '1');

const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: true, credentials: true }
});

/* =========================
   Database (Supabase)
========================= */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5
});

async function q(text, params = []) {
  const { rows } = await pool.query(text, params);
  return rows;
}

/* =========================
   AutoMod
========================= */
const AUTOMOD = {
  maxMsgs10s: Number(process.env.AUTOMOD_MAX_MSGS_10S || 6),
  spam: process.env.AUTOMOD_ENABLE_SPAM === 'true',
  badwords: process.env.AUTOMOD_ENABLE_BADWORDS === 'true'
};

const msgBuckets = new Map(); // userId -> timestamps[]
const BADWORDS = ['hurensohn', 'arschloch', 'fotze'];

function isSpam(userId) {
  const now = Date.now();
  const bucket = msgBuckets.get(userId) || [];
  const recent = bucket.filter(t => now - t < 10_000);
  recent.push(now);
  msgBuckets.set(userId, recent);
  return recent.length > AUTOMOD.maxMsgs10s;
}

function hasBadword(text) {
  const t = text.toLowerCase();
  return BADWORDS.some(w => t.includes(w));
}

/* =========================
   Middleware
========================= */
app.use(express.json());
app.use(express.static('public'));

app.use(session({
  name: 'chatly.sid',
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 1000 * 60 * 60 * 24
  }
}));

/* =========================
   Guards
========================= */
async function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: 'not logged in' });
  }

  const [u] = await q(
    'SELECT banned_until, muted_until, timeout_until FROM users WHERE id=$1',
    [req.session.user.id]
  );

  const now = new Date();
  if (u?.banned_until && new Date(u.banned_until) > now) {
    return res.status(403).json({ error: 'banned' });
  }
  if (u?.timeout_until && new Date(u.timeout_until) > now) {
    return res.status(403).json({ error: 'timeout' });
  }

  next();
}

function requireAdmin(req, res, next) {
  if (req.session.user?.role !== 'admin') {
    return res.status(403).json({ error: 'admin only' });
  }
  next();
}

/* =========================
   Auth
========================= */
app.post('/api/auth/register', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) return res.status(400).json({ error: 'missing' });
  if (username.length > 10) return res.status(400).json({ error: 'username too long' });
  if (password.length < 6) return res.status(400).json({ error: 'password too short' });

  const hash = await bcrypt.hash(password, 10);

  try {
    const [u] = await q(
      'INSERT INTO users (username, pass_hash) VALUES ($1,$2) RETURNING id, username, role',
      [username, hash]
    );
    req.session.user = u;
    res.json({ user: u });
  } catch {
    res.status(400).json({ error: 'username exists' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const [user] = await q('SELECT * FROM users WHERE username=$1', [username]);
  if (!user) return res.status(401).json({ error: 'invalid login' });

  const ok = await bcrypt.compare(password, user.pass_hash);
  if (!ok) return res.status(401).json({ error: 'invalid login' });

  req.session.user = { id: user.id, username: user.username, role: user.role };
  res.json({ user: req.session.user });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/auth/me', (req, res) => {
  if (!req.session.user) return res.status(401).json({});
  res.json({ user: req.session.user });
});

/* =========================
   Rooms
========================= */
app.get('/api/rooms/list', requireLogin, async (req, res) => {
  const isAdmin = req.session.user.role === 'admin';
  const rows = isAdmin
    ? await q('SELECT * FROM rooms ORDER BY id')
    : await q("SELECT * FROM rooms WHERE admin_only=false AND visibility='public' ORDER BY id");
  res.json({ rooms: rows });
});

/* =========================
   Messages
========================= */
app.post('/api/messages/send', requireLogin, async (req, res) => {
  const { room_id, content } = req.body;
  const userId = req.session.user.id;

  if (!content || content.length > 100) {
    return res.status(400).json({ error: 'invalid message' });
  }

  if (AUTOMOD.spam && isSpam(userId)) {
    await q(
      `UPDATE users SET timeout_until = now() + interval '2 minutes' WHERE id=$1`,
      [userId]
    );
    return res.status(429).json({ error: 'spam detected' });
  }

  if (AUTOMOD.badwords && hasBadword(content)) {
    return res.status(400).json({ error: 'badword detected' });
  }

  const [msg] = await q(
    `INSERT INTO messages (room_id, author_id, content, type)
     VALUES ($1,$2,$3,'text') RETURNING *`,
    [room_id, userId, content]
  );

  msg.author_name = req.session.user.username;
  io.to('room:' + room_id).emit('message:new', msg);
  res.json({ message: msg });
});

/* =========================
   Admin
========================= */
app.post('/api/admin/ban', requireLogin, requireAdmin, async (req, res) => {
  const { username } = req.body;
  const [u] = await q('SELECT id FROM users WHERE username=$1', [username]);
  if (!u) return res.status(404).json({ error: 'not found' });

  await q(
    `UPDATE users SET banned_until = now() + interval '7 days' WHERE id=$1`,
    [u.id]
  );

  await q(
    `INSERT INTO moderation_logs (admin_id, action, target_user)
     VALUES ($1,'ban',$2)`,
    [req.session.user.id, u.id]
  );

  res.json({ ok: true });
});

/* =========================
   Socket.IO
========================= */
io.on('connection', socket => {
  socket.on('room:join', ({ room_id }) => {
    socket.join('room:' + room_id);
  });
});

/* =========================
   Start
========================= */
const PORT = Number(process.env.PORT) || 3000;
server.listen(PORT, () => {
  console.log('Chatly running on port', PORT);
});
