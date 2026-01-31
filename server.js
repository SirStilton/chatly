// Chatly server.js – Hardened & Structured Version
// Node 18+, Express, Socket.IO, PostgreSQL (Supabase compatible)

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
app.set('trust proxy', 1);

const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: true, credentials: true }
});

/* =========================
   Database
========================= */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function q(text, params = []) {
  const { rows } = await pool.query(text, params);
  return rows;
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
    secure: false
  }
}));

/* =========================
   Helpers
========================= */
function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: 'not logged in' });
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

  if (!username || !password)
    return res.status(400).json({ error: 'missing fields' });
  if (username.length > 10)
    return res.status(400).json({ error: 'username too long' });
  if (password.length < 6)
    return res.status(400).json({ error: 'password too short' });

  const hash = await bcrypt.hash(password, 10);

  try {
    const rows = await q(
      'INSERT INTO users (username, pass_hash) VALUES ($1,$2) RETURNING id, username, role',
      [username, hash]
    );
    req.session.user = rows[0];
    res.json({ user: rows[0] });
  } catch {
    res.status(400).json({ error: 'username exists' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const rows = await q('SELECT * FROM users WHERE username=$1', [username]);
  const user = rows[0];

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
    : await q('SELECT * FROM rooms WHERE admin_only=false ORDER BY id');
  res.json({ rooms: rows });
});

app.get('/api/rooms/trending', requireLogin, async (_req, res) => {
  const rows = await q('SELECT * FROM rooms ORDER BY id DESC LIMIT 10');
  res.json({ rooms: rows });
});

app.post('/api/rooms/join', requireLogin, async (req, res) => {
  const { roomId } = req.body;
  await q(
    'INSERT INTO room_members (room_id, user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
    [roomId, req.session.user.id]
  );
  res.json({ ok: true });
});

/* =========================
   Messages
========================= */
app.get('/api/messages/history', requireLogin, async (req, res) => {
  const { room_id } = req.query;
  const rows = await q(
    `SELECT m.*, u.username AS author_name
     FROM messages m
     LEFT JOIN users u ON u.id=m.author_id
     WHERE room_id=$1
     ORDER BY m.id`,
    [room_id]
  );
  res.json({ messages: rows });
});

app.post('/api/messages/send', requireLogin, async (req, res) => {
  const { room_id, content, type = 'text' } = req.body;

  if (!content || content.length > 100)
    return res.status(400).json({ error: 'invalid message' });

  const safeType =
    req.session.user.role === 'admin' ? type : 'text';

  const rows = await q(
    `INSERT INTO messages (room_id, author_id, content, type)
     VALUES ($1,$2,$3,$4) RETURNING *`,
    [room_id, req.session.user.id, content, safeType]
  );

  const msg = {
    ...rows[0],
    author_name: req.session.user.username
  };

  io.to('room:' + room_id).emit('message:new', msg);
  res.json({ message: msg });
});

app.delete('/api/messages/:id', requireLogin, async (req, res) => {
  await q(
    'UPDATE messages SET is_deleted=true WHERE id=$1 AND author_id=$2',
    [req.params.id, req.session.user.id]
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
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log('Chatly running on port', PORT);
});
