const $ = (id) => document.getElementById(id);

const state = {
  me: null,
  rooms: [],
  room: "lobby",
  roomInfo: null,
  socket: null
};

function setStatus(t) {
  $("statusText").textContent = t;
}

function showMsg(el, text, ok = false) {
  el.textContent = text || "";
  el.classList.toggle("ok", !!ok);
}

function fmtTime(ts) {
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  } catch {
    return "";
  }
}

async function api(path, opts = {}) {
  const res = await fetch(path, {
    credentials: "include",
    headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
    ...opts
  });
  let data = null;
  try { data = await res.json(); } catch {}
  if (!res.ok) {
    const err = data?.error || `http_${res.status}`;
    throw new Error(err);
  }
  return data;
}

function usernameHintNormalize(u) {
  return String(u || "").trim();
}

function validUsername(u) {
  const x = usernameHintNormalize(u);
  if (x.length < 3 || x.length > 10) return false;
  return /^[a-z0-9]+$/i.test(x);
}

function validPassword(p) {
  return typeof p === "string" && p.length >= 8 && p.length <= 128;
}

function setAuthedUI(isAuthed) {
  $("authCard").style.display = isAuthed ? "none" : "block";
  $("appCard").style.display = isAuthed ? "grid" : "none";
  $("btnLogout").style.display = isAuthed ? "inline-block" : "none";

  if (!isAuthed) {
    $("mePill").textContent = "nicht angemeldet";
    $("rooms").innerHTML = "";
    $("msgs").innerHTML = "";
    $("footMsg").textContent = "";
  }
}

function meLabel() {
  if (!state.me) return "nicht angemeldet";
  return `${state.me.username} (${state.me.role})`;
}

function renderRooms() {
  const wrap = $("rooms");
  wrap.innerHTML = "";

  state.rooms.forEach((r) => {
    const btn = document.createElement("button");
    btn.className = "roomBtn" + (r.slug === state.room ? " active" : "");
    btn.innerHTML = `
      <div><b>#${r.slug}</b> — ${escapeHtml(r.title || r.slug)}</div>
      <div class="roomMeta">
        <span>${escapeHtml(r.description || "")}</span>
        ${r.admin_only ? `<span class="badge admin">admin</span>` : `<span class="badge">public</span>`}
      </div>
    `;
    btn.onclick = () => joinRoom(r.slug);
    wrap.appendChild(btn);
  });
}

function setRoomHeader(room) {
  $("roomPill").textContent = `#${room.slug}`;
  $("roomTitle").textContent = room.title || room.slug;
  $("roomSub").textContent = room.description || "";
}

async function fetchRooms() {
  const data = await api("/api/rooms");
  state.rooms = data.rooms || [];
  const found = state.rooms.find((r) => r.slug === state.room) || state.rooms[0];
  if (found) {
    state.room = found.slug;
    state.roomInfo = found;
    setRoomHeader(found);
  }
  renderRooms();
}

async function fetchMessages(slug) {
  const data = await api(`/api/rooms/${encodeURIComponent(slug)}/messages?limit=80`);
  const msgs = data.messages || [];
  $("msgs").innerHTML = "";
  msgs.forEach(renderMessage);
  scrollDown();
}

function scrollDown() {
  const el = $("msgs");
  el.scrollTop = el.scrollHeight;
}

function escapeHtml(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function renderAdminHtml(html) {
  const iframe = document.createElement("iframe");
  iframe.className = "htmlbox";
  iframe.setAttribute("sandbox", ""); // scripts NICHT erlaubt
  iframe.srcdoc = String(html || "");
  iframe.style.height = "120px";
  return iframe;
}

function renderMessage(m) {
  const wrap = $("msgs");

  if (m.type === "system") {
    const sys = document.createElement("div");
    sys.className = "sys";
    sys.textContent = m.content || "";
    wrap.appendChild(sys);
    return;
  }

  const b = document.createElement("div");
  b.className = "bubble";

  const author = m.author || "unknown";
  const role = m.author_role || "user";
  const mine = state.me && author.toLowerCase() === state.me.username.toLowerCase();

  const top = document.createElement("div");
  top.className = "rowTop";

  const left = document.createElement("div");
  left.style.display = "flex";
  left.style.gap = "10px";
  left.style.alignItems = "center";

  const a = document.createElement("div");
  a.className = "author" + (role === "admin" ? " admin" : "");
  a.textContent = author;

  const t = document.createElement("div");
  t.className = "time";
  t.textContent = fmtTime(m.created_at);

  left.appendChild(a);
  left.appendChild(t);

  const actions = document.createElement("div");
  actions.className = "actions";

  const canDelete = !!state.me && (mine || state.me.role === "admin");
  if (canDelete && !m.is_deleted) {
    const del = document.createElement("button");
    del.className = "linkbtn";
    del.textContent = "löschen";
    del.onclick = () => deleteMsg(m.id);
    actions.appendChild(del);
  }

  top.appendChild(left);
  top.appendChild(actions);

  const text = document.createElement("div");
  text.className = "text";

  if (m.type === "admin_html" && state.me?.role === "admin") {
    text.appendChild(renderAdminHtml(m.content));
  } else {
    text.textContent = m.content || "";
  }

  b.appendChild(top);
  b.appendChild(text);
  wrap.appendChild(b);
}

function attachAuthTabs() {
  const tabLogin = $("tabLogin");
  const tabRegister = $("tabRegister");
  const loginForm = $("loginForm");
  const registerForm = $("registerForm");

  tabLogin.onclick = () => {
    tabLogin.classList.add("active");
    tabRegister.classList.remove("active");
    loginForm.style.display = "flex";
    registerForm.style.display = "none";
    showMsg($("loginMsg"), "");
    showMsg($("regMsg"), "");
  };

  tabRegister.onclick = () => {
    tabRegister.classList.add("active");
    tabLogin.classList.remove("active");
    registerForm.style.display = "flex";
    loginForm.style.display = "none";
    showMsg($("loginMsg"), "");
    showMsg($("regMsg"), "");
  };
}

async function refreshMe() {
  const data = await api("/api/me");
  state.me = data.user;
  $("mePill").textContent = meLabel();
  setAuthedUI(!!state.me);
}

function setupAdminHtmlToggle() {
  const isAdmin = state.me?.role === "admin";
  $("htmlWrap").style.display = isAdmin ? "flex" : "none";
  if (!isAdmin) $("sendHtml").checked = false;
}

function connectSocket() {
  if (state.socket) {
    try { state.socket.disconnect(); } catch {}
    state.socket = null;
  }

  const socket = io({
    withCredentials: true,
    transports: ["websocket", "polling"]
  });

  state.socket = socket;

  setStatus("verbinden…");

  socket.on("connect", () => setStatus("online"));
  socket.on("disconnect", () => setStatus("offline"));

  socket.on("hello", async () => {
    await joinRoom(state.room);
  });

  socket.on("message", (m) => {
    if (m?.type === "system") {
      // system msg in current room only (server sends to room)
      renderMessage(m);
      scrollDown();
      return;
    }
    renderMessage(m);
    scrollDown();
  });

  socket.on("message_deleted", ({ id }) => {
    // quick & simple: reload messages for current room
    fetchMessages(state.room).catch(() => {});
  });

  socket.on("connect_error", (e) => {
    $("footMsg").textContent = `Socket Fehler: ${e?.message || "unknown"}`;
    setStatus("offline");
  });
}

async function joinRoom(slug) {
  slug = String(slug || "lobby");
  const room = state.rooms.find((r) => r.slug === slug);
  if (!room) return;

  state.room = slug;
  state.roomInfo = room;
  setRoomHeader(room);
  renderRooms();
  $("footMsg").textContent = "";

  // Optional: private join code prompt (nur wenn visibility private)
  let join_code = undefined;
  if (room.visibility === "private") {
    join_code = prompt("Join-Code für diesen Raum:");
    if (!join_code) return;
  }

  // join via API (setzt membership / checks admin_only / join_code)
  await api(`/api/rooms/${encodeURIComponent(slug)}/join`, {
    method: "POST",
    body: JSON.stringify({ join_code })
  });

  // join via socket room
  await new Promise((resolve) => {
    state.socket.emit("join", { slug, join_code }, () => resolve());
  });

  await fetchMessages(slug);
}

async function sendMsg() {
  const input = $("msgInput");
  const text = String(input.value || "").trim();
  if (!text) return;

  if (text.length > 100) {
    $("footMsg").textContent = "Max 100 Zeichen.";
    return;
  }

  $("footMsg").textContent = "";

  const is_html = state.me?.role === "admin" && $("sendHtml").checked;

  state.socket.emit("send", { room: state.room, text, is_html }, (res) => {
    if (!res?.ok) {
      $("footMsg").textContent = `Senden fehlgeschlagen: ${res?.error || "unknown"}`;
    }
  });

  input.value = "";
  input.focus();
}

async function deleteMsg(id) {
  try {
    // Socket delete (schneller)
    state.socket.emit("delete", { id }, async (res) => {
      if (!res?.ok) {
        // fallback API
        await api(`/api/messages/${id}`, { method: "DELETE" });
      }
      await fetchMessages(state.room);
    });
  } catch {
    $("footMsg").textContent = "Löschen fehlgeschlagen.";
  }
}

function bindUI() {
  attachAuthTabs();

  $("loginForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const u = $("loginUser").value.trim();
    const p = $("loginPass").value;

    if (!validUsername(u)) return showMsg($("loginMsg"), "Username: 3–10 Zeichen, nur Buchstaben/Zahlen.");
    if (!validPassword(p)) return showMsg($("loginMsg"), "Passwort: mind. 8 Zeichen.");

    try {
      await api("/api/login", { method: "POST", body: JSON.stringify({ username: u, password: p }) });
      showMsg($("loginMsg"), "Eingeloggt ✅", true);
      await afterAuth();
    } catch (err) {
      showMsg($("loginMsg"), `Login fehlt: ${err.message}`);
    }
  });

  $("registerForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const u = $("regUser").value.trim();
    const p = $("regPass").value;

    if (!validUsername(u)) return showMsg($("regMsg"), "Username: 3–10 Zeichen, nur Buchstaben/Zahlen.");
    if (!validPassword(p)) return showMsg($("regMsg"), "Passwort: mind. 8 Zeichen.");

    try {
      await api("/api/register", { method: "POST", body: JSON.stringify({ username: u, password: p }) });
      showMsg($("regMsg"), "Account erstellt ✅", true);
      await afterAuth();
    } catch (err) {
      showMsg($("regMsg"), `Registrieren fehlt: ${err.message}`);
    }
  });

  $("btnLogout").onclick = async () => {
    try { await api("/api/logout", { method: "POST" }); } catch {}
    try { state.socket?.disconnect(); } catch {}
    state.me = null;
    setAuthedUI(false);
    setStatus("offline");
  };

  $("btnRefreshRooms").onclick = async () => {
    try {
      await fetchRooms();
    } catch (e) {
      $("footMsg").textContent = `Rooms laden fehlgeschlagen: ${e.message}`;
    }
  };

  $("btnSend").onclick = sendMsg;
  $("msgInput").addEventListener("keydown", (e) => {
    if (e.key === "Enter") sendMsg();
  });
}

async function afterAuth() {
  await refreshMe();
  setupAdminHtmlToggle();
  await fetchRooms();
  connectSocket();
  await fetchMessages(state.room);
}

async function boot() {
  bindUI();

  try {
    await refreshMe();
    if (state.me) {
      setupAdminHtmlToggle();
      await fetchRooms();
      connectSocket();
      await fetchMessages(state.room);
    } else {
      setStatus("offline");
    }
  } catch {
    setStatus("offline");
    setAuthedUI(false);
  }
}

boot();
