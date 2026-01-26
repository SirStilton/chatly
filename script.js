// Chatly script.js (wires index.html to CURRENT server.js routes, with safe fallbacks)
// IMPORTANT: Your deployed server.js currently exposes /api/register, /api/login, /api/logout, /api/me (blog-style),
// but does NOT expose chat endpoints like /api/rooms/* or socket.io. This script keeps the UI and will show
// clear in-app messages instead of crashing if endpoints are missing.

const $ = (id) => document.getElementById(id);

const state = {
  me: null,
  activeRoom: null,
  socket: null,
};

async function fetchJSON(url, opts = {}) {
  const res = await fetch(url, {
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  const text = await res.text();
  let data = {};
  try { data = text ? JSON.parse(text) : {}; } catch { data = { raw: text }; }
  if (!res.ok) {
    const err = new Error(data?.error || data?.message || `HTTP ${res.status}`);
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data;
}

function show(el, on) {
  if (!el) return;
  el.style.display = on ? "" : "none";
}

function setAuthMode(mode) {
  const tabLogin = $("tabLogin");
  const tabRegister = $("tabRegister");
  const btnAuth = $("btnAuth");
  const msg = $("authMsg");

  if (tabLogin) tabLogin.classList.toggle("active", mode === "login");
  if (tabRegister) tabRegister.classList.toggle("active", mode === "register");
  if (btnAuth) btnAuth.textContent = mode === "login" ? "Login" : "Registrieren";
  if (msg) msg.textContent = "";
  $("authForm")?.setAttribute("data-mode", mode);
}

function setMe(user) {
  state.me = user;
  const pill = $("mePill");
  if (pill) pill.textContent = user ? `${user.username} (${user.role || "user"})` : "nicht angemeldet";

  show($("authCard"), !user);
  show($("appCard"), !!user);
  show($("btnLogout"), !!user);
  show($("btnAdmin"), !!user && (user.role === "admin"));

  // Admin-only checkbox in create room dialog
  const adminOnlyRow = $("crAdminOnlyRow");
  if (adminOnlyRow) adminOnlyRow.style.display = (user && user.role === "admin") ? "" : "none";
}

function appNotice(text) {
  const msgs = $("msgs");
  if (!msgs) return;
  const div = document.createElement("div");
  div.className = "msg system";
  div.innerHTML = `
    <div class="meta">
      <div class="who">System</div>
      <div class="when">${new Date().toLocaleString()}</div>
    </div>
    <div class="content">${escapeHTML(text)}</div>
    <div class="actions"></div>
  `;
  msgs.prepend(div);
}

function escapeHTML(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
  }[c]));
}

// ---------- Auth ----------
async function doAuth(e) {
  e.preventDefault();
  const mode = $("authForm")?.getAttribute("data-mode") || "login";
  const msg = $("authMsg");
  if (msg) msg.textContent = "";

  const username = $("username")?.value?.trim() || "";
  const password = $("password")?.value || "";
  const agree = $("agreeRules")?.checked;

  if (!username || !password) {
    if (msg) msg.textContent = "Bitte Username und Passwort ausfüllen.";
    return;
  }
  if (username.length > 10) {
    if (msg) msg.textContent = "Username darf max. 10 Zeichen haben.";
    return;
  }
  if (!agree) {
    if (msg) msg.textContent = "Bitte Regeln akzeptieren.";
    return;
  }

  try {
    if (mode === "register") {
      await fetchJSON("/api/register", { method: "POST", body: JSON.stringify({ username, password }) });
      if (msg) msg.textContent = "Registriert ✅ Jetzt einloggen…";
      setAuthMode("login");
      return;
    }

    const r = await fetchJSON("/api/login", { method: "POST", body: JSON.stringify({ username, password }) });
    // current server returns {ok:true, user:{...}} or similar; be tolerant
    const user = r.user || r?.data?.user || { username, role: "user" };
    setMe(user);
    await afterLogin();
  } catch (err) {
    if (msg) msg.textContent = err.data?.error || err.message || "Fehler";
  }
}

async function bootMe() {
  try {
    const r = await fetchJSON("/api/me");
    // current server returns {user:{...}} or {ok:true, user:{...}}
    setMe(r.user || r?.data?.user || null);
    if (state.me) await afterLogin();
  } catch (err) {
    // Not logged in is normal (401)
    setMe(null);
  }
}

// ---------- Chat wiring (requires chat endpoints; shows notices if missing) ----------
async function refreshRooms() {
  const listEl = $("roomList");
  const trendEl = $("trendingList");
  if (listEl) listEl.innerHTML = "";
  if (trendEl) trendEl.innerHTML = "";

  // These endpoints do NOT exist in your current server.js.
  // We try them; if missing, we show a clear in-app message and stop.
  try {
    const rooms = await fetchJSON("/api/rooms/list"); // expected by chat server
    renderRooms(listEl, rooms.rooms || rooms || []);
  } catch (err) {
    if (err.status === 404) {
      appNotice("Dein aktueller server.js hat keine Chat-Room-API (/api/rooms/list). Deshalb können Räume nicht geladen werden. (Das fixen wir als NÄCHSTEN Schritt im server.js.)");
      return;
    }
    appNotice(`Rooms laden fehlgeschlagen: ${err.message}`);
    return;
  }

  try {
    const trending = await fetchJSON("/api/rooms/trending");
    renderRooms(trendEl, trending.rooms || trending || []);
  } catch {
    // trending optional; ignore
  }
}

function renderRooms(container, rooms) {
  if (!container) return;
  if (!Array.isArray(rooms) || rooms.length === 0) {
    container.innerHTML = `<div class="muted small">Keine Räume.</div>`;
    return;
  }
  rooms.forEach((r) => {
    const btn = document.createElement("button");
    btn.className = "roomBtn";
    const title = r.title || r.slug || "room";
    const desc = r.description || "";
    btn.innerHTML = `
      <div>
        <div style="font-weight:900">${escapeHTML(title)}</div>
        <div class="muted tiny">${escapeHTML(desc)}</div>
      </div>
      <span class="badge">${escapeHTML(r.visibility || "")}</span>
    `;
    btn.addEventListener("click", () => selectRoom(r));
    container.appendChild(btn);
  });
}

function selectRoom(room) {
  state.activeRoom = room;
  if ($("roomTitle")) $("roomTitle").textContent = room.title || room.slug || "—";
  if ($("roomDesc")) $("roomDesc").textContent = room.description || "";
  // Try to load history if API exists
  loadMessages().catch(() => {});
}

async function loadMessages() {
  const msgs = $("msgs");
  if (!msgs) return;
  msgs.innerHTML = "";

  if (!state.activeRoom?.id && !state.activeRoom?.slug) {
    msgs.innerHTML = `<div class="muted small">Wähle links einen Raum.</div>`;
    return;
  }

  try {
    const r = await fetchJSON("/api/messages/list", {
      method: "POST",
      body: JSON.stringify({ room: state.activeRoom.id || state.activeRoom.slug }),
    });
    const arr = r.messages || r || [];
    arr.forEach(addMessageToUI);
  } catch (err) {
    if (err.status === 404) {
      appNotice("Dein aktueller server.js hat keine Nachrichten-API (/api/messages/*). Chat kann noch nicht senden/anzeigen. (Fix kommt im nächsten Schritt im server.js.)");
      return;
    }
    appNotice(`Messages laden fehlgeschlagen: ${err.message}`);
  }
}

function addMessageToUI(m) {
  const msgs = $("msgs");
  if (!msgs) return;

  const div = document.createElement("div");
  const type = m.type || "text";
  div.className = `msg ${type === "system" ? "system" : type === "bot" ? "bot" : ""}`;

  const who = m.author?.username || m.username || m.author_username || "User";
  const when = m.created_at ? new Date(m.created_at).toLocaleString() : new Date().toLocaleString();
  const content = m.is_deleted ? "[gelöscht]" : (m.content || "");

  div.innerHTML = `
    <div class="meta">
      <div class="who">${escapeHTML(who)}${type !== "text" ? `<span class="type">${escapeHTML(type)}</span>` : ""}</div>
      <div class="when">${escapeHTML(when)}</div>
    </div>
    <div class="content">${escapeHTML(content)}</div>
    <div class="actions"></div>
  `;
  msgs.appendChild(div);
  msgs.scrollTop = msgs.scrollHeight;
}

async function sendMessage(e) {
  e.preventDefault();
  const input = $("msgInput");
  if (!input) return;
  const text = input.value.trim();
  if (!text) return;
  if (text.length > 100) {
    appNotice("Max 100 Zeichen.");
    return;
  }
  if (!state.activeRoom) {
    appNotice("Bitte zuerst einen Raum wählen.");
    return;
  }
  const type = $("msgType")?.value || "text";

  try {
    await fetchJSON("/api/messages/send", {
      method: "POST",
      body: JSON.stringify({ room: state.activeRoom.id || state.activeRoom.slug, type, content: text }),
    });
    input.value = "";
  } catch (err) {
    if (err.status === 404) {
      appNotice("Senden geht noch nicht: server.js hat kein /api/messages/send. (Fix kommt im nächsten Schritt im server.js.)");
      return;
    }
    appNotice(`Senden fehlgeschlagen: ${err.message}`);
  }
}

// ---------- Admin overlay (UI only; actions require endpoints) ----------
function openOverlay(id) {
  const el = $(id);
  if (!el) return;
  el.style.display = "flex";
  document.body.classList.add("noScroll");
}
function closeOverlay(id) {
  const el = $(id);
  if (!el) return;
  el.style.display = "none";
  document.body.classList.remove("noScroll");
}

function bindUI() {
  $("authForm")?.addEventListener("submit", doAuth);

  $("tabLogin")?.addEventListener("click", () => setAuthMode("login"));
  $("tabRegister")?.addEventListener("click", () => setAuthMode("register"));

  $("btnLogout")?.addEventListener("click", async () => {
    try { await fetchJSON("/api/logout", { method: "POST" }); } catch {}
    location.reload();
  });

  $("btnAdmin")?.addEventListener("click", () => openOverlay("adminOverlay"));

  // close buttons
  document.querySelectorAll("[data-close]").forEach((btn) => {
    btn.addEventListener("click", () => closeOverlay(btn.getAttribute("data-close")));
  });

  // mobile sidebar
  const mobileBtn = $("btnMobileMenu");
  const sb = $("sidebar");
  if (mobileBtn && sb) mobileBtn.addEventListener("click", () => sb.classList.toggle("open"));

  // overlays openers
  $("btnCreateRoom")?.addEventListener("click", () => openOverlay("createRoomOverlay"));
  $("btnJoinRoom")?.addEventListener("click", () => openOverlay("joinRoomOverlay"));
  $("btnProfile")?.addEventListener("click", () => openOverlay("profileOverlay"));

  // send form
  $("sendForm")?.addEventListener("submit", sendMessage);

  // admin tabs switching (pure UI)
  const admBtns = Array.from(document.querySelectorAll("[data-admtab]"));
  const tabs = {
    users: $("admUsers"),
    rooms: $("admRooms"),
    logs: $("admLogs"),
    bots: $("admBots"),
    system: $("admSystem"),
  };
  if (admBtns.length) {
    const setTab = (k) => {
      admBtns.forEach((b) => b.classList.toggle("active", b.getAttribute("data-admtab") === k));
      Object.entries(tabs).forEach(([name, el]) => {
        if (!el) return;
        el.style.display = name === k ? "block" : "none";
      });
    };
    admBtns.forEach((b) => b.addEventListener("click", () => setTab(b.getAttribute("data-admtab"))));
    setTab("users");
  }
}

async function afterLogin() {
  // Try to connect socket.io if the server supports it
  if (window.io && !state.socket) {
    try {
      state.socket = window.io({ withCredentials: true });
      state.socket.on("connect", () => {
        appNotice("Realtime verbunden ✅");
      });
      state.socket.on("connect_error", () => {
        // don't spam
      });
      state.socket.on("message", (m) => addMessageToUI(m));
    } catch {
      // ignore
    }
  }
  await refreshRooms();
}

async function boot() {
  bindUI();
  setAuthMode("login");
  await bootMe();
}

boot();
