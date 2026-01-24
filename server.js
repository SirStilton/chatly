import express from "express";
import session from "express-session";
import bcrypt from "bcryptjs";
import path from "path";
import http from "http";
import { WebSocketServer } from "ws";
import { fileURLToPath } from "url";
import pg from "pg";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import sanitizeHtml from "sanitize-html";
import connectPgSimple from "connect-pg-simple";

const { Pool } = pg;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  console.error("Missing DATABASE_URL env var");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// --- PFAD-ANPASSUNG FÜR DEINEN PUBLIC-ORDNER ---
// Statische Dateien (CSS, JS) aus dem Unterordner 'public' laden
app.use(express.static(path.join(__dirname, "public")));

app.use(express.json());

const pgSession = connectPgSimple(session);
app.use(session({
  store: new pgSession({ pool, tableName: "session" }),
  secret: process.env.SESSION_SECRET || "super-secret-key",
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 30 * 24 * 60 * 60 * 1000, secure: false }
}));

// Deine API-Routen (Login, Register, etc.) bleiben hier...
// [Hier steht dein existierender Code für app.post('/api/login') etc.]

// Die Route für die Startseite - zeigt jetzt auf den public-Ordner
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

const server = http.createServer(app);
const wss = new WebSocketServer({ server });

// Dein WebSocket-Code bleibt hier...
// [Hier steht dein existierender wss.on('connection') Code]

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🚀 Chatly läuft auf Port ${PORT}`);
  console.log(`📂 Statische Dateien werden aus /public serviert`);
});