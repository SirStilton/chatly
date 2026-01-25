const $ = (id) => document.getElementById(id);

const state = {
  me: null,
  rooms: [],
  room: "lobby",
  roomInfo: null,
  socket: null,
  isMobileMenuOpen: false,
  adminOpen: false,
  adminUsers: [],
  adminBots: [],
  adminLogs: []
};

function setStatus(t) {
  $("statusText").textContent = t;
}

function showMsg(el, text, ok = false) {
  if (!el) return;
  el.textContent = text || "";
  el.classList.toggle("ok", !!ok);
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

function fmtTime(ts) {
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  } catch {
    return "";
  }
}

function escapeHtml(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function validUsername(u) {
  const x = String(u || "").trim();
  if (x.length < 3 || x.length > 10) return false;
  return /^[a-z0-9]+$/i.test(x);
}

function validPassword(p) {
  return typeof p === "string" && p.length >= 8 && p.length <= 128;
}

function meLabel() {
  if (!state.me) return "nicht angemeldet";
  return `${state.me.username} (${state.me.role})`;
}

function setAuthedUI(isAuthed) {
  $("authCard").style.display = isAuthed ? "none" : "block";
  $("appCard").style.display = isAuthed ? "grid" : "none";
  $("btnLogout").style.display = isAuthed ? "inline-block" : "none";
  $("btnAdmin").style.display = isAuthed && state.me?.role === "admin" ? "inline-block" : "none";
  if (!isAuthed) {
    $("mePill").textContent = "nicht angemeldet";
    $("rooms").innerHTML = "";
    $("roomsMobile").innerHTML = "";
    $("msgs").innerHTML = "";
    $("footMsg").textContent = "";
  }
}

async function refreshMe() {
  const data = await api("/api/me");
  state.me = data.user;
  $("mePill").textContent = meLabel();
  setAuthedUI(!!state.me);
  setupAdminHtmlToggle();
}

function setupAdminHtmlToggle() {
  const isAdmin = state.me?.role === "admin";
  $("htmlWrap").style.display = isAdmin ? "flex" : "none";
  if (!isAdmin) $("sendHtml").checked = false;
}

function scrollDown() {
  const el = $("msgs");
  el.scrollTop = el.scrollHeight;
}

/* ---------- Rooms UI ---------- */

function renderRoomsInto(containerId) {
  const wrap = $(containerId);
  wrap.innerHTML = "";
  state.rooms.forEach((r) => {
    const btn = document.createElement("button");
    btn.className = "roomBtn" + (r.slug === state.room ? " active" : "");
    btn.innerHTML = `
      <div><b>#${escapeHtml(r.slug)}</b> — ${escapeHtml(r.title || r.slug)}</div>
      <div class="roomMeta">
        <span>${escapeHtml(r.description || "")}</span>
        ${r.admin_only ? `<span class="badge admin">admin</span>` : `<span class="badge">public</span>`}
      </div>
    `;
    btn.onclick = () => {
      joinRoom(r.slug).catch(() => {});
      closeMobileMenu();
    };
    wrap.appendChild(btn);
  });
}

function renderRooms() {
  renderRoomsInto("rooms");
  renderRoomsInto("roomsMobile");
  $("roomPillMini").textContent = `#${state.room}`;
}

function setRoomHeader(room) {
  $("roomPill").textContent = `#${room.slug}`;
  $("roomTitle").textContent = room.title || room.slug;
  $("roomSub").textContent = room.description || "";
  $("roomPillMini").textContent = `#${room.slug}`;
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
  // also update admin panel room selects
  renderAdminRoomSelects();
}

async function fetchMessages(slug) {
  const data = await api(`/api/rooms/${encodeURIComponent(slug)}/messages?limit=120`);
  const msgs = data.messages || [];
  $("msgs").innerHTML = "";
  msgs.forEach(renderMessage);
  scrollDown();
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

  let join_code = undefined;
  if (room.visibility === "private") {
    join_code = prompt("Join-Code für diesen Raum:");
    if (!join_code) return;
  }

  await api(`/api/rooms/${encodeURIComponent(slug)}/join`, {
    method: "POST",
    body: JSON.stringify({ join_code })
  });

  await new Promise((resolve) => {
    state.socket.emit("join", { slug, join_code }, () => resolve());
  });

  await fetchMessages(slug);
}

/* ---------- Messages UI ---------- */

function renderAdminHtml(html) {
  const iframe = document.createElement("iframe");
  iframe.className = "htmlbox";
  iframe.setAttribute("sandbox", "");
  iframe.srcdoc = String(html || "");
  iframe.style.height = "140px";
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
    state.socket.emit("delete", { id }, async (res) => {
      if (!res?.ok) {
        await api(`/api/messages/${id}`, { method: "DELETE" });
      }
      await fetchMessages(state.room);
    });
  } catch {
    $("footMsg").textContent = "Löschen fehlgeschlagen.";
  }
}

/* ---------- Mobile menu ---------- */

function openMobileMenu() {
  state.isMobileMenuOpen = true;
  $("mobileOverlay").style.display = "flex";
}
function closeMobileMenu() {
  state.isMobileMenuOpen = false;
  $("mobileOverlay").style.display = "none";
}

/* ---------- Admin panel ---------- */

function openAdmin() {
  state.adminOpen = true;
  $("adminOverlay").style.display = "flex";
}
function closeAdmin() {
  state.adminOpen = false;
  $("adminOverlay").style.display = "none";
}

function setAdminTab(tab) {
  const tabs = ["Users", "System", "Move", "Bots", "Logs"];
  tabs.forEach((t) => {
    const btn = $(`admTab${t}`);
    const sec = $(`adm${t}`);
    const on = t.toLowerCase() === tab.toLowerCase();
    btn.classList.toggle("active", on);
    sec.style.display = on ? "block" : "none";
  });
}

function renderAdminRoomSelects() {
  const roomOptions = state.rooms.map((r) => `<option value="${escapeHtml(r.slug)}">${escapeHtml(r.slug)}</option>`).join("");
  const sysSel = $("admSysRoom");
  const moveSel = $("admMoveRoom");
  const botSel = $("admBotRoom");
  if (sysSel) sysSel.innerHTML = roomOptions;
  if (moveSel) moveSel.innerHTML = roomOptions;
  if (botSel) botSel.innerHTML = roomOptions;
}

function chipForPun(u) {
  const parts = [];
  const now = Date.now();
  if (u.banned_until && new Date(u.banned_until).getTime() > now) parts.push(`<span class="chip bad">banned</span>`);
  if (u.muted_until && new Date(u.muted_until).getTime() > now) parts.push(`<span class="chip bad">muted</span>`);
  if (u.timeout_until && new Date(u.timeout_until).getTime() > now) parts.push(`<span class="chip bad">timeout</span>`);
  return parts.join(" ");
}

function renderAdminUsersList(filter = "") {
  const wrap = $("admUsersList");
  wrap.innerHTML = "";
  const f = String(filter || "").trim().toLowerCase();

  const list = state.adminUsers.filter((u) => {
    if (!f) return true;
    return String(u.username || "").toLowerCase().includes(f) || String(u.role || "").toLowerCase().includes(f);
  });

  if (list.length === 0) {
    $("admUsersHint").textContent = "Keine Users gefunden.";
    return;
  }
  $("admUsersHint").textContent = `${list.length} Users`;

  list.forEach((u) => {
    const item = document.createElement("div");
    item.className = "admItem";
    item.innerHTML = `
      <div class="admItemTop">
        <div>
          <div class="admItemName">${escapeHtml(u.username)} ${u.role === "admin" ? `<span class="chip">admin</span>` : ""}</div>
          <div class="admItemMeta">id ${u.id} · status ${escapeHtml(u.status || "")}</div>
        </div>
        <div class="admItemActions">
          ${chipForPun(u)}
          <button class="btn ghost small" data-user="${escapeHtml(u.username)}">select</button>
        </div>
      </div>
    `;
    item.querySelector("button").onclick = () => {
      $("admPunishUser").value = String(u.username || "");
      $("admMoveUser").value = String(u.username || "");
      $("admUsersHint").textContent = `Selected: ${u.username}`;
    };
    wrap.appendChild(item);
  });
}

async function adminFetchUsers() {
  const msg = $("admUsersHint");
  msg.textContent = "Lade…";
  const data = await api("/api/admin/users");
  state.adminUsers = data.users || [];
  renderAdminUsersList($("admUserSearch").value);
}

async function adminPunish() {
  showMsg($("admPunishMsg"), "");
  const username = String($("admPunishUser").value || "").trim().toLowerCase();
  const kind = String($("admPunishKind").value || "ban");
  const minutes = Number($("admPunishMinutes").value || 10);
  const reason = String($("admPunishReason").value || "").trim();

  if (!validUsername(username)) return showMsg($("admPunishMsg"), "bad username");
  if (!["ban", "mute", "timeout"].includes(kind)) return showMsg($("admPunishMsg"), "bad kind");
  if (!Number.isFinite(minutes) || minutes < 1) return showMsg($("admPunishMsg"), "bad minutes");

  await api("/api/admin/punish", {
    method: "POST",
    body: JSON.stringify({ username, kind, minutes, reason })
  });

  showMsg($("admPunishMsg"), "ok ✅", true);
  await adminFetchUsers();
}

async function adminSendSystem() {
  showMsg($("admSysMsg"), "");
  const room = String($("admSysRoom").value || state.room);
  const text = String($("admSysText").value || "").trim();
  if (!text) return showMsg($("admSysMsg"), "empty");

  await api("/api/admin/system", {
    method: "POST",
    body: JSON.stringify({ room, text })
  });

  $("admSysText").value = "";
  showMsg($("admSysMsg"), "sent ✅", true);

  if (room === state.room) {
    await fetchMessages(state.room);
  }
}

async function adminForceMove() {
  showMsg($("admMoveMsg"), "");
  const username = String($("admMoveUser").value || "").trim().toLowerCase();
  const room = String($("admMoveRoom").value || "").trim();
  const join_code = String($("admMoveJoinCode").value || "").trim();

  if (!validUsername(username)) return showMsg($("admMoveMsg"), "bad username");
  if (!room) return showMsg($("admMoveMsg"), "select room");

  await api("/api/admin/force-move", {
    method: "POST",
    body: JSON.stringify({ username, room, join_code })
  });

  showMsg($("admMoveMsg"), "moved ✅", true);
}

function safeParseJSON(text) {
  try {
    if (!String(text || "").trim()) return {};
    const obj = JSON.parse(text);
    if (obj && typeof obj === "object") return obj;
    return {};
  } catch {
    return null;
  }
}

async function adminFetchBots() {
  const wrap = $("admBotsList");
  wrap.innerHTML = "Lade…";
  const data = await api("/api/admin/bots");
  state.adminBots = data.bots || [];
  renderBots();
}

function renderBots() {
  const wrap = $("admBotsList");
  wrap.innerHTML = "";

  if (!state.adminBots.length) {
    wrap.innerHTML = `<div class="admHint">Keine Bots.</div>`;
    return;
  }

  state.adminBots.forEach((b) => {
    const item = document.createElement("div");
    item.className = "admItem";
    item.innerHTML = `
      <div class="admItemTop">
        <div>
          <div class="admItemName">${escapeHtml(b.name)} ${b.enabled ? `<span class="chip">enabled</span>` : `<span class="chip bad">off</span>`}</div>
          <div class="admItemMeta">#${escapeHtml(b.room_slug || "?")} · id ${b.id}</div>
        </div>
        <div class="admItemActions">
          <button class="btn ghost small" data-id="${b.id}" data-enabled="${b.enabled ? "1":"0"}">${b.enabled ? "disable" : "enable"}</button>
        </div>
      </div>
    `;
    item.querySelector("button").onclick = async (e) => {
      const id = Number(e.currentTarget.getAttribute("data-id"));
      const enabled = e.currentTarget.getAttribute("data-enabled") !== "1";
      await api("/api/admin/bots/toggle", { method: "POST", body: JSON.stringify({ id, enabled }) });
      await adminFetchBots();
    };
    wrap.appendChild(item);
  });
}

async function adminCreateBot() {
  showMsg($("admBotMsg"), "");
  const name = String($("admBotName").value || "").trim();
  const room = String($("admBotRoom").value || "lobby").trim();
  const cfgText = String($("admBotConfig").value || "");
  const config = safeParseJSON(cfgText);
  if (config === null) return showMsg($("admBotMsg"), "config JSON invalid");

  if (!name) return showMsg($("admBotMsg"), "name missing");

  await api("/api/admin/bots/create", {
    method: "POST",
    body: JSON.stringify({ name, room, config })
  });

  $("admBotName").value = "";
  $("admBotConfig").value = "";
  showMsg($("admBotMsg"), "created ✅", true);
  await adminFetchBots();
}

async function adminFetchLogs() {
  const msg = $("admLogsMsg");
  msg.textContent = "Lade…";
  const data = await api("/api/admin/logs?limit=150");
  state.adminLogs = data.logs || [];
  renderLogs();
}

function renderLogs() {
  const wrap = $("admLogsList");
  wrap.innerHTML = "";

  if (!state.adminLogs.length) {
    wrap.innerHTML = `<div class="admHint">Keine Logs.</div>`;
    $("admLogsMsg").textContent = "";
    return;
  }

  state.adminLogs.forEach((l) => {
    const item = document.createElement("div");
    item.className = "admItem";
    const by = l.by_admin_name || "admin";
    const tu = l.target_user_name ? ` · user ${l.target_user_name}` : "";
    const tr = l.target_room_slug ? ` · room #${l.target_room_slug}` : "";
    const detail = l.details ? escapeHtml(JSON.stringify(l.details)) : "";
    item.innerHTML = `
      <div class="admItemTop">
        <div>
          <div class="admItemName">${escapeHtml(l.action || "")}</div>
          <div class="admItemMeta">${fmtTime(l.created_at)} · by ${escapeHtml(by)}${tu}${tr}</div>
        </div>
      </div>
      ${detail ? `<div class="admItemMeta" style="margin-top:8px; opacity:.9;">${detail}</div>` : ``}
    `;
    wrap.appendChild(item);
  });

  $("admLogsMsg").textContent = `${state.adminLogs.length} logs`;
}

/* ---------- Socket ---------- */

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
    renderMessage(m);
    scrollDown();
  });

  socket.on("message_deleted", ({ id }) => {
    fetchMessages(state.room).catch(() => {});
  });

  socket.on("punished", (p) => {
    $("footMsg").textContent = `Moderation: ${p.kind} bis ${new Date(p.until_at).toLocaleString()}`;
    refreshMe().catch(() => {});
  });

  socket.on("force_move", async ({ room, join_code }) => {
    try {
      const target = state.rooms.find((r) => r.slug === room);
      if (!target) await fetchRooms();
      await api(`/api/rooms/${encodeURIComponent(room)}/join`, {
        method: "POST",
        body: JSON.stringify({ join_code })
      });
      await new Promise((resolve) => {
        state.socket.emit("join", { slug: room, join_code }, () => resolve());
      });
      state.room = room;
      await fetchMessages(room);
      $("footMsg").textContent = `Du wurdest in #${room} verschoben.`;
    } catch {
      $("footMsg").textContent = `Force-Move fehlgeschlagen.`;
    }
  });

  socket.on("connect_error", (e) => {
    $("footMsg").textContent = `Socket Fehler: ${e?.message || "unknown"}`;
    setStatus("offline");
  });
}

/* ---------- Auth tabs ---------- */

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

/* ---------- Bind UI ---------- */

function bindUI() {
  attachAuthTabs();

  $("loginForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const u = String($("loginUser").value || "").trim();
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
    const u = String($("regUser").value || "").trim();
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
    closeAdmin();
    closeMobileMenu();
    state.me = null;
    setAuthedUI(false);
    setStatus("offline");
  };

  $("btnRefreshRooms").onclick = async () => {
    try { await fetchRooms(); } catch (e) { $("footMsg").textContent = `Rooms laden fehlgeschlagen: ${e.message}`; }
  };

  $("btnSend").onclick = sendMsg;
  $("msgInput").addEventListener("keydown", (e) => {
    if (e.key === "Enter") sendMsg();
  });

  // Mobile menu
  $("btnMobileMenu").onclick = () => {
    if (!state.me) return;
    if (state.isMobileMenuOpen) closeMobileMenu();
    else openMobileMenu();
  };
  $("btnMobileClose").onclick = closeMobileMenu;
  $("mobileBackdrop").onclick = closeMobileMenu;

  // Admin overlay
  $("btnAdmin").onclick = async () => {
    openAdmin();
    setAdminTab("Users");
    try {
      await adminFetchUsers();
    } catch (e) {
      $("admUsersHint").textContent = `Fehler: ${e.message}`;
    }
    try {
      await adminFetchBots();
    } catch {}
    try {
      await adminFetchLogs();
    } catch {}
  };
  $("btnAdminClose").onclick = closeAdmin;
  $("adminBackdrop").onclick = closeAdmin;

  // Admin tabs
  $("admTabUsers").onclick = () => setAdminTab("Users");
  $("admTabSystem").onclick = () => setAdminTab("System");
  $("admTabMove").onclick = () => setAdminTab("Move");
  $("admTabBots").onclick = () => setAdminTab("Bots");
  $("admTabLogs").onclick = () => setAdminTab("Logs");

  // Admin: users
  $("admRefreshUsers").onclick = () => adminFetchUsers().catch((e) => { $("admUsersHint").textContent = `Fehler: ${e.message}`; });
  $("admUserSearch").addEventListener("input", () => renderAdminUsersList($("admUserSearch").value));

  // Admin: punish
  $("admPunishGo").onclick = () => adminPunish().catch((e) => showMsg($("admPunishMsg"), `Fehler: ${e.message}`));

  // Admin: system
  $("admSysUseCurrent").onclick = () => { $("admSysRoom").value = state.room; };
  $("admSysSend").onclick = () => adminSendSystem().catch((e) => showMsg($("admSysMsg"), `Fehler: ${e.message}`));

  // Admin: move
  $("admMoveGo").onclick = () => adminForceMove().catch((e) => showMsg($("admMoveMsg"), `Fehler: ${e.message}`));

  // Admin: bots
  $("admRefreshBots").onclick = () => adminFetchBots().catch((e) => showMsg($("admBotMsg"), `Fehler: ${e.message}`));
  $("admBotCreate").onclick = () => adminCreateBot().catch((e) => showMsg($("admBotMsg"), `Fehler: ${e.message}`));

  // Admin: logs
  $("admRefreshLogs").onclick = () => adminFetchLogs().catch((e) => { $("admLogsMsg").textContent = `Fehler: ${e.message}`; });
}

/* ---------- Boot ---------- */

async function afterAuth() {
  await refreshMe();
  await fetchRooms();
  connectSocket();
  await fetchMessages(state.room);
}

async function boot() {
  bindUI();

  try {
    await refreshMe();
    if (state.me) {
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
