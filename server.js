// Chatly server.js – FINAL
// Garantiert passend zu index.html & script.js

import express from 'express';
import http from 'http';
import session from 'express-session';
import bcrypt from 'bcryptjs';
import pg from 'pg';
import { Server } from 'socket.io';

const { Pool } = pg;

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: true, credentials: true }
});

/* ================= DB ================= */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const q = async (text, params = []) => {
  const { rows } = await pool.query(text, params);
  return rows;
};

/* ============== Middleware ============== */
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
    secure: process.env.NODE_ENV === 'production'
  }
}));

/* ============== Guards ============== */
async function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: 'not logged in' });
  }

  const [u] = await q(
    'SELECT banned_until FROM users WHERE id=$1',
    [req.session.user.id]
  );

  if (u?.banned_until && new Date(u.banned_until) > new Date()) {
    return res.status(403).json({ error: 'banned' });
  }

  next();
}

/* ============== Auth ============== */
app.post('/api/auth/register', async (req, res) => {
  const { username, password } = req.body;
  const hash = await bcrypt.hash(password, 10);

  const [u] = await q(
    'INSERT INTO users (username, pass_hash) VALUES ($1,$2) RETURNING id, username, role',
    [username, hash]
  );

  req.session.user = u;
  res.json({ user: u });
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

/* ============== Rooms ============== */
app.get('/api/rooms/list', requireLogin, async (req, res) => {
  const rows =
    req.session.user.role === 'admin'
      ? await q('SELECT * FROM rooms ORDER BY id')
      : await q(
          "SELECT * FROM rooms WHERE admin_only=false AND visibility='public' ORDER BY id"
        );

  res.json({ rooms: rows });
});

app.get('/api/rooms/trending', requireLogin, async (req, res) => {
  const rows = await q(`
    SELECT r.id, r.slug, COUNT(m.id) AS messages
    FROM rooms r
    LEFT JOIN messages m ON m.room_id=r.id AND m.is_deleted=false
    WHERE r.admin_only=false AND r.visibility='public'
    GROUP BY r.id
    ORDER BY messages DESC
    LIMIT 10
  `);

  res.json({ rooms: rows });
});

/* ============== Messages ============== */
app.get('/api/messages/history', requireLogin, async (req, res) => {
  const rows = await q(
    `SELECT m.*, u.username AS author_name
     FROM messages m
     LEFT JOIN users u ON u.id=m.author_id
     WHERE m.room_id=$1
     ORDER BY m.id`,
    [req.query.room_id]
  );

  res.json({ messages: rows });
});

app.post('/api/messages/send', requireLogin, async (req, res) => {
  const { room_id, content, type = 'text' } = req.body;

  const [msg] = await q(
    `INSERT INTO messages (room_id, author_id, content, type)
     VALUES ($1,$2,$3,$4) RETURNING *`,
    [room_id, req.session.user.id, content, type]
  );

  msg.author_name = req.session.user.username;
  io.to('room:' + room_id).emit('message:new', msg);
  res.json({ message: msg });
});

app.post('/api/messages/delete', requireLogin, async (req, res) => {
  const { message_id } = req.body;

  const [m] = await q(
    'SELECT author_id FROM messages WHERE id=$1',
    [message_id]
  );

  if (!m) return res.status(404).json({ error: 'not found' });

  if (
    m.author_id !== req.session.user.id &&
    req.session.user.role !== 'admin'
  ) {
    return res.status(403).json({ error: 'not allowed' });
  }

  await q('UPDATE messages SET is_deleted=true WHERE id=$1', [message_id]);
  res.json({ ok: true });
});

/* ============== Socket ============== */
io.on('connection', socket => {
  socket.on('room:join', ({ room_id }) => {
    socket.join('room:' + room_id);
  });
});

/* ============== Start ============== */
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log('Chatly running on port', PORT);
});
