// Chatly server.js – ADMIN API FINAL
// Compatible with: script_admin_final.js, Supabase schema, Render env

import express from 'express';
import http from 'http';
import session from 'express-session';
import bcrypt from 'bcryptjs';
import pg from 'pg';
import { Server } from 'socket.io';

const { Pool } = pg;

const app = express();
app.set('trust proxy', process.env.TRUST_PROXY === '1');

const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: true, credentials: true }
});

/* ---------- DB ---------- */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5
});

const q = async (text, params = []) => (await pool.query(text, params)).rows;

/* ---------- middleware ---------- */
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

/* ---------- guards ---------- */
async function requireLogin(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'not logged in' });

  const [u] = await q(
    'SELECT banned_until FROM users WHERE id=$1',
    [req.session.user.id]
  );

  if (u?.banned_until && new Date(u.banned_until) > new Date()) {
    return res.status(403).json({ error: 'banned' });
  }

  next();
}

function requireAdmin(req, res, next) {
  if (req.session.user?.role !== 'admin') {
    return res.status(403).json({ error: 'admin only' });
  }
  next();
}

/* ---------- auth ---------- */
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const [user] = await q('SELECT * FROM users WHERE username=$1', [username]);
  if (!user) return res.status(401).json({ error: 'invalid login' });

  const ok = await bcrypt.compare(password, user.pass_hash);
  if (!ok) return res.status(401).json({ error: 'invalid login' });

  req.session.user = { id: user.id, username: user.username, role: user.role };
  res.json({ user: req.session.user });
});

app.post('/api/auth/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'missing fields' });

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

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/auth/me', (req, res) => {
  if (!req.session.user) return res.status(401).json({});
  res.json({ user: req.session.user });
});

/* ---------- rooms ---------- */
app.get('/api/rooms/list', requireLogin, async (req, res) => {
  const rows = req.session.user.role === 'admin'
    ? await q('SELECT * FROM rooms ORDER BY id')
    : await q("SELECT * FROM rooms WHERE admin_only=false AND visibility='public' ORDER BY id");
  res.json({ rooms: rows });
});

/* ---------- messages ---------- */
app.get('/api/messages/history', requireLogin, async (req, res) => {
  const rows = await q(
    `SELECT m.*, u.username AS author_name
     FROM messages m
     LEFT JOIN users u ON u.id=m.author_id
     WHERE room_id=$1
     ORDER BY m.id`,
    [req.query.room_id]
  );
  res.json({ messages: rows });
});

app.post('/api/messages/send', requireLogin, async (req, res) => {
  const { room_id, content, type } = req.body;
  if (!content || content.length > 100)
    return res.status(400).json({ error: 'invalid message' });

  const [u] = await q(
    'SELECT muted_until FROM users WHERE id=$1',
    [req.session.user.id]
  );
  if (u?.muted_until && new Date(u.muted_until) > new Date()) {
    return res.status(403).json({ error: 'muted' });
  }

  const safeType = req.session.user.role === 'admin' ? type : 'text';

  const [msg] = await q(
    `INSERT INTO messages (room_id, author_id, content, type)
     VALUES ($1,$2,$3,$4) RETURNING *`,
    [room_id, req.session.user.id, content, safeType]
  );

  msg.author_name = req.session.user.username;
  io.to('room:' + room_id).emit('message:new', msg);
  res.json({ message: msg });
});

/* ---------- ADMIN API ---------- */
app.post('/api/admin/ban', requireLogin, requireAdmin, async (req, res) => {
  const { username } = req.body;
  const [u] = await q('SELECT id FROM users WHERE username=$1', [username]);
  if (!u) return res.status(404).json({ error: 'user not found' });

  await q(
    'UPDATE users SET banned_until=now()+interval '7 days' WHERE id=$1',
    [u.id]
  );

  await q(
    `INSERT INTO moderation_logs (admin_id, action, target_user)
     VALUES ($1,'ban',$2)`,
    [req.session.user.id, u.id]
  );

  res.json({ ok: true });
});

app.post('/api/admin/mute', requireLogin, requireAdmin, async (req, res) => {
  const { username } = req.body;
  const [u] = await q('SELECT id FROM users WHERE username=$1', [username]);
  if (!u) return res.status(404).json({ error: 'user not found' });

  await q(
    'UPDATE users SET muted_until=now()+interval '30 minutes' WHERE id=$1',
    [u.id]
  );

  await q(
    `INSERT INTO moderation_logs (admin_id, action, target_user)
     VALUES ($1,'mute',$2)`,
    [req.session.user.id, u.id]
  );

  res.json({ ok: true });
});

app.post('/api/admin/timeout', requireLogin, requireAdmin, async (req, res) => {
  const { username } = req.body;
  const [u] = await q('SELECT id FROM users WHERE username=$1', [username]);
  if (!u) return res.status(404).json({ error: 'user not found' });

  await q(
    'UPDATE users SET timeout_until=now()+interval '10 minutes' WHERE id=$1',
    [u.id]
  );

  await q(
    `INSERT INTO moderation_logs (admin_id, action, target_user)
     VALUES ($1,'timeout',$2)`,
    [req.session.user.id, u.id]
  );

  res.json({ ok: true });
});

/* ---------- socket ---------- */
io.on('connection', socket => {
  socket.on('room:join', ({ room_id }) => {
    socket.join('room:' + room_id);
  });
});

/* ---------- start ---------- */
const PORT = Number(process.env.PORT) || 3000;
server.listen(PORT, () => {
  console.log('Chatly running on port', PORT);
});
