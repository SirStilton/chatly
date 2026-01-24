import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import http from "http";
import { WebSocketServer } from "ws";

// WICHTIG: Pfade korrekt definieren
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 3000;

// Statische Dateien (CSS, JS, Bilder) direkt aus dem Root-Verzeichnis servieren
// Das sorgt dafür, dass ./style.css und ./script.js gefunden werden
app.use(express.static(__dirname));

// Die Hauptroute für die index.html
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Fallback für Single Page Application (optional, falls du Unterseiten nutzt)
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Dummy WebSocket Setup (damit der Server nicht abstürzt, falls script.js connectet)
const wss = new WebSocketServer({ server });
wss.on('connection', (ws) => {
  console.log('Ein Client hat sich verbunden');
  ws.on('message', (message) => {
    console.log('Empfangen:', message.toString());
  });
});

server.listen(PORT, () => {
  console.log(`🚀 Server läuft auf Port ${PORT}`);
  console.log(`📂 Arbeitsverzeichnis: ${__dirname}`);
});