
/* Chatly script.js (frontend)
   Works with server_chatly.js endpoints + Socket.IO.
   Features:
   - Login/Register (no email)
   - Rooms: list, trending, search, random, create (public/unlisted/private)
   - Join private rooms with join code prompt
   - Realtime messages via Socket.IO
   - Message delete (own; admin all)
   - Admin panel (role=admin): users list + punish, system message, create admin rooms
*/

const $ = (id) => document.getElementById(id);

const state = {
  me: null,
  socket: null,
  room: { slug: "lobby", title: "Lobby", description: "Allgemeiner Chat", visibility: "public", admin_only: false, kind: "room" },
  joined: new Set(),
  rooms: [],
  trending: [],
  searching: false,
};

function setText(el, txt) { if (el) el.textContent = txt; }
function show(el, on = true) { if (!el) return; el.style.display = on ? "" : "none"; }
function escapeHtml(str) {
  return String(str || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
function fmtTime(iso) {
  try {
    const d = new Date(iso);
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  } catch { return ""; }
}

async function api(url, opts = {}) {
  const res = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    ...opts,
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw { status: res.status, ...json };
  return json;
}

function switchAuthTab(which) {
  const loginForm = $("loginForm");
  const regForm = $("registerForm");
  const tabLogin = $("tabLogin");
  const tabRegister = $("tabRegister");

  if (which === "login") {
    show(loginForm, true); show(regForm, false);
    tabLogin.classList.add("active"); tabRegister.classList.remove("active");
  } else {
    show(loginForm, false); show(regForm, true);
    tabLogin.classList.remove("active"); tabRegister.classList.add("active");
  }
}

function setLoggedInUI(on) {
  show($("authCard"), !on);
  show($("appCard"), on);
  show($("btnLogout"), on);
  if (!on) {
    $("msgs").innerHTML = "";
  }
}

function updateMePill() {
  if (!state.me) {
    setText($("mePill"), "nicht angemeldet");
    return;
  }
  setText($("mePill"), `${state.me.username} · ${state.me.role}`);
}

function setRoomHeader(room) {
  setText($("roomPill"), `#${room.slug}`);
  setText($("roomTitle"), room.title || room.slug);
  setText($("roomSub"), room.description || "");
}

function setStatus(txt) { setText($("statusText"), txt); }

function renderRoomButton(room, container, { mini = false } = {}) {
  const btn = document.createElement("button");
  btn.className = mini ? "roomBtn mini" : "roomBtn";
  btn.innerHTML = `
    <div class="rTop">
      <span class="rSlug">#${escapeHtml(room.slug)}</span>
      ${room.visibility === "private" ? `<span class="tag">privat</span>` : ""}
      ${room.visibility === "unlisted" ? `<span class="tag">unlisted</span>` : ""}
      ${room.admin_only ? `<span class="tag admin">admin</span>` : ""}
    </div>
    <div class="rTitle">${escapeHtml(room.title || room.slug)}</div>
  `;
  btn.onclick = () => joinAndOpen(room.slug, room.visibility);
  container.appendChild(btn);
}

function renderRooms() {
  const roomsEl = $("rooms");
  const roomsMobile = $("roomsMobile");
  roomsEl.innerHTML = "";
  roomsMobile.innerHTML = "";
  state.rooms.forEach((r) => {
    renderRoomButton(r, roomsEl);
    renderRoomButton(r, roomsMobile);
  });
}

function renderTrending() {
  const tEl = $("trending");
  const tMobile = $("trendingMobile");
  tEl.innerHTML = "";
  tMobile.innerHTML = "";
  state.trending.forEach((r) => {
    renderRoomButton(r, tEl, { mini: true });
    renderRoomButton(r, tMobile, { mini: true });
  });
}

function renderSearchResults(rooms) {
  const el = $("searchResults");
  el.innerHTML = "";
  rooms.forEach((r) => renderRoomButton(r, el, { mini: true }));
}

function addMsgRow(msg) {
  const wrap = $("msgs");
  const row = document.createElement("div");
  row.className = "msgRow";
  row.dataset.id = msg.id;

  const type = msg.type || "text";
  const isSystem = type === "system";
  const isBot = type === "bot";
  const isDeleted = msg.is_deleted;

  let contentHtml = "";
  if (isDeleted) {
    contentHtml = `<span class="deleted">Nachricht gelöscht</span>`;
  } else if (type === "html") {
    // Admin HTML message: sandboxed iframe
    const safe = String(msg.content || "");
    const iframe = document.createElement("iframe");
    iframe.className = "htmlFrame";
    iframe.setAttribute("sandbox", "allow-same-origin");
    iframe.srcdoc = safe;
    contentHtml = `<div class="htmlHolder"></div>`;
    row.innerHTML = `
      <div class="meta">
        <span class="who">${escapeHtml(msg.author_name || "Admin")}</span>
        <span class="time">${fmtTime(msg.created_at)}</span>
        <span class="badge html">HTML</span>
      </div>
      <div class="bubble htmlBubble"></div>
    `;
    row.querySelector(".bubble").appendChild(iframe);
    wrap.appendChild(row);
    wrap.scrollTop = wrap.scrollHeight;
    return;
  } else {
    contentHtml = escapeHtml(msg.content || "");
  }

  const who = isSystem ? "System" : (msg.author_name || (isBot ? "Bot" : "User"));
  const badge = isSystem ? `<span class="badge sys">SYSTEM</span>` : isBot ? `<span class="badge bot">BOT</span>` : "";

  const canDelete = state.me && (state.me.role === "admin" || Number(msg.author_id) === Number(state.me.id));

  row.innerHTML = `
    <div class="meta">
      <span class="who">${escapeHtml(who)}</span>
      <span class="time">${fmtTime(msg.created_at)}</span>
      ${badge}
      ${canDelete && !isSystem ? `<button class="delBtn" title="löschen">🗑</button>` : ``}
    </div>
    <div class="bubble ${isSystem ? "sysBubble" : isBot ? "botBubble" : ""}">${contentHtml}</div>
  `;

  if (canDelete && !isSystem) {
    row.querySelector(".delBtn").onclick = () => deleteMessage(msg.id);
  }

  wrap.appendChild(row);
  wrap.scrollTop = wrap.scrollHeight;
}

function applyDeleted(id) {
  const el = document.querySelector(`.msgRow[data-id="${id}"]`);
  if (!el) return;
  const bubble = el.querySelector(".bubble");
  if (bubble) {
    bubble.innerHTML = `<span class="deleted">Nachricht gelöscht</span>`;
  }
}

async function loadHistory(slug) {
  const r = await api(`/api/messages/history?slug=${encodeURIComponent(slug)}&limit=80`);
  // server returns room meta too
  if (r.room) {
    state.room = {
      slug: r.room.slug,
      title: r.room.title,
      description: r.room.description || "",
      visibility: r.room.visibility,
      admin_only: r.room.admin_only,
      kind: r.room.kind,
    };
    setRoomHeader(state.room);
  }
  $("msgs").innerHTML = "";
  (r.messages || []).forEach(addMsgRow);
}

async function refreshRooms() {
  const r = await api("/api/rooms/list");
  state.rooms = r.rooms || [];
  renderRooms();
}

async function refreshTrending() {
  const r = await api("/api/rooms/trending");
  state.trending = r.rooms || [];
  renderTrending();
}

async function searchRooms() {
  const q = $("roomSearch").value.trim();
  if (!q) return renderSearchResults([]);
  const r = await api(`/api/rooms/search?q=${encodeURIComponent(q)}`);
  renderSearchResults(r.rooms || []);
}

async function randomRoom() {
  const r = await api("/api/rooms/random");
  if (!r.room) return;
  await joinAndOpen(r.room.slug, r.room.visibility);
}

async function joinAndOpen(slug, visibilityHint) {
  // For private rooms we need join code.
  let join_code = null;
  if (visibilityHint === "private") {
    join_code = prompt("Join-Code für privaten Raum:");
    if (!join_code) return;
  }
  // join via REST ensures membership & permission; then join socket room too.
  try {
    const join = await api("/api/rooms/join", {
      method: "POST",
      body: JSON.stringify({ slug, join_code }),
    });

    await openRoom(join.room.slug);
  } catch (e) {
    toast(`Join fehlgeschlagen: ${prettyErr(e)}`, true);
  }
}

async function openRoom(slug) {
  // leave current room in socket
  if (state.socket && state.room?.slug) {
    state.socket.emit("room:leave", { slug: state.room.slug }, () => {});
  }

  await loadHistory(slug);

  if (state.socket) {
    state.socket.emit("room:join", { slug }, (resp) => {
      if (!resp?.ok) {
        toast(`Socket join: ${resp?.error || "error"}`, true);
      }
    });
  }
}

function toast(msg, isErr = false) {
  const el = $("footMsg");
  el.textContent = msg;
  el.className = "footMsg" + (isErr ? " err" : "");
  clearTimeout(toast._t);
  toast._t = setTimeout(() => (el.textContent = ""), 3500);
}

function prettyErr(e) {
  if (!e) return "unbekannter Fehler";
  return e.error || e.message || `HTTP ${e.status || "?"}`;
}

async function sendMessage() {
  const input = $("msgInput");
  const txt = input.value.trim();
  if (!txt) return;

  // Client-side hard limit
  if (txt.length > 100) {
    toast("Max 100 Zeichen.", true);
    return;
  }

  // Timeout UX: if server blocks, it will return timeout_active
  if (!state.socket) return toast("offline", true);

  state.socket.emit("message:send", { slug: state.room.slug, content: txt }, (resp) => {
    if (!resp?.ok) {
      toast(`Senden: ${resp?.error || "error"}`, true);
      return;
    }
    input.value = "";
  });
}

async function deleteMessage(id) {
  if (!state.socket) return;
  state.socket.emit("message:delete", { id }, (resp) => {
    if (!resp?.ok) toast(`Löschen: ${resp?.error || "error"}`, true);
  });
}

// --- Admin panel ---
function setAdminUI() {
  const isAdmin = state.me?.role === "admin";
  show($("btnAdmin"), isAdmin);
  show($("htmlWrap"), isAdmin);
  show($("crAdminOnlyRow"), isAdmin);
}

function openOverlay(id) { show($(id), true); document.body.classList.add("noScroll"); }
function closeOverlay(id) { show($(id), false); document.body.classList.remove("noScroll"); }

function switchAdmTab(which) {
  const map = {
    users: ["admUsers", "admTabUsers"],
    system: ["admSystem", "admTabSystem"],
    rooms: ["admRooms", "admTabRooms"],
    logs: ["admLogs", "admTabLogs"],
  };
  for (const k of Object.keys(map)) {
    const [sec, tab] = map[k];
    const on = k === which;
    show($(sec), on);
    $(tab).classList.toggle("active", on);
  }
}

async function adminLoadUsers() {
  try {
    const qtxt = $("admUserSearch").value.trim();
    const r = await api(`/api/admin/users?q=${encodeURIComponent(qtxt)}`);
    const list = $("admUsersList");
    list.innerHTML = "";
    (r.users || []).forEach((u) => {
      const card = document.createElement("div");
      card.className = "uCard";
      card.innerHTML = `
        <div class="uTop">
          <div class="uName">${escapeHtml(u.username)} <span class="tag ${u.role === "admin" ? "admin" : ""}">${escapeHtml(u.role)}</span></div>
          <div class="uId">id: ${u.id}</div>
        </div>
        <div class="uFlags">
          ${u.banned_until ? `<span class="flag">banned</span>` : ""}
          ${u.muted_until ? `<span class="flag">muted</span>` : ""}
          ${u.timeout_until ? `<span class="flag">timeout</span>` : ""}
        </div>
      `;
      list.appendChild(card);
    });
    setText($("admUsersHint"), `${(r.users || []).length} user`);
  } catch (e) {
    setText($("admUsersHint"), `Fehler: ${prettyErr(e)}`);
  }
}

async function adminPunish() {
  try {
    const user_id = $("admPunishUserId").value.trim();
    const kind = $("admPunishKind").value;
    const minutes = $("admPunishMinutes").value.trim();
    const room_slug = $("admPunishRoom").value.trim();
    const reason = $("admPunishReason").value.trim();

    const body = {
      user_id: user_id ? Number(user_id) : null,
      kind,
      minutes: minutes ? Number(minutes) : null,
      room_slug: room_slug || null,
      reason: reason || null,
    };

    const r = await api("/api/admin/punish", { method: "POST", body: JSON.stringify(body) });
    setText($("admPunishMsg"), r.ok ? "ok" : "nicht ok");
    $("admPunishMsg").className = "msg ok";
    adminLoadUsers();
  } catch (e) {
    $("admPunishMsg").className = "msg err";
    setText($("admPunishMsg"), `Fehler: ${prettyErr(e)}`);
  }
}

async function adminSendSystem() {
  try {
    const room_slug = $("admSysRoom").value.trim() || state.room.slug;
    const content = $("admSysText").value.trim();
    if (!room_slug || !content) return;

    const r = await api("/api/admin/system-message", { method: "POST", body: JSON.stringify({ room_slug, content }) });
    $("admSysMsg").className = "msg ok";
    setText($("admSysMsg"), r.ok ? "gesendet" : "fehler");
    $("admSysText").value = "";
  } catch (e) {
    $("admSysMsg").className = "msg err";
    setText($("admSysMsg"), `Fehler: ${prettyErr(e)}`);
  }
}

async function adminCreateRoom() {
  try {
    const title = $("admCrTitle").value.trim();
    const description = $("admCrDesc").value.trim();
    const visibility = $("admCrVis").value;
    const admin_only = $("admCrAdminOnly").checked;

    const r = await api("/api/rooms/create", { method: "POST", body: JSON.stringify({ title, description, visibility, admin_only }) });
    $("admCrMsg").className = "msg ok";
    setText($("admCrMsg"), `Erstellt: #${r.room.slug} ${r.room.join_code ? `(code: ${r.room.join_code})` : ""}`);
    refreshRooms();
    refreshTrending();
  } catch (e) {
    $("admCrMsg").className = "msg err";
    setText($("admCrMsg"), `Fehler: ${prettyErr(e)}`);
  }
}

async function adminRoomInfo() {
  // We don't have a dedicated endpoint; use search and display join_code is not returned by search for safety.
  // For now: inform user to check Supabase or create room response.
  setText($("admRoomInfoOut"), "Join-Code wird aktuell nur beim Erstellen angezeigt (oder in Supabase Tabelle rooms.join_code).");
}

function bindUI() {
  // tabs
  $("tabLogin").onclick = () => switchAuthTab("login");
  $("tabRegister").onclick = () => switchAuthTab("register");

  // auth forms
  $("loginForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    $("loginMsg").textContent = "";
    try {
      const username = $("loginUser").value.trim();
      const password = $("loginPass").value;
      const r = await api("/api/auth/login", { method: "POST", body: JSON.stringify({ username, password }) });
      state.me = r.user;
      updateMePill();
      setAdminUI();
      setLoggedInUI(true);
      await initAppAfterLogin();
    } catch (err) {
      $("loginMsg").textContent = `Fehler: ${prettyErr(err)}`;
      $("loginMsg").className = "msg err";
    }
  });

  $("registerForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    $("regMsg").textContent = "";
    try {
      const username = $("regUser").value.trim();
      const password = $("regPass").value;
      const r = await api("/api/auth/register", { method: "POST", body: JSON.stringify({ username, password }) });
      state.me = r.user;
      updateMePill();
      setAdminUI();
      setLoggedInUI(true);
      await initAppAfterLogin();
    } catch (err) {
      $("regMsg").textContent = `Fehler: ${prettyErr(err)}`;
      $("regMsg").className = "msg err";
    }
  });

  $("btnLogout").onclick = async () => {
    try { await api("/api/auth/logout", { method: "POST" }); } catch {}
    state.me = null;
    updateMePill();
    setLoggedInUI(false);
    if (state.socket) { state.socket.disconnect(); state.socket = null; }
  };

  // mobile overlay
  $("btnMobileMenu").onclick = () => openOverlay("mobileOverlay");
  $("btnMobileClose").onclick = () => closeOverlay("mobileOverlay");
  $("mobileBackdrop").onclick = () => closeOverlay("mobileOverlay");

  // create room overlay
  $("btnOpenCreateRoom").onclick = () => openOverlay("createOverlay");
  $("btnCreateClose").onclick = () => closeOverlay("createOverlay");
  $("createBackdrop").onclick = () => closeOverlay("createOverlay");

  $("createRoomForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    $("crMsg").textContent = "";
    try {
      const title = $("crTitle").value.trim();
      const description = $("crDesc").value.trim();
      const visibility = $("crVis").value;
      const admin_only = $("crAdminOnly").checked;

      const r = await api("/api/rooms/create", { method: "POST", body: JSON.stringify({ title, description, visibility, admin_only }) });
      $("crMsg").className = "msg ok";
      $("crMsg").textContent = `Erstellt: #${r.room.slug} ${r.room.join_code ? `(Join-Code: ${r.room.join_code})` : ""}`;
      refreshRooms();
      refreshTrending();
    } catch (err) {
      $("crMsg").className = "msg err";
      $("crMsg").textContent = `Fehler: ${prettyErr(err)}`;
    }
  });

  $("btnRefreshRooms").onclick = async () => { await refreshRooms(); await refreshTrending(); };

  $("btnSearch").onclick = searchRooms;
  $("roomSearch").addEventListener("keydown", (e) => { if (e.key === "Enter") searchRooms(); });

  $("btnRandomRoom").onclick = randomRoom;

  // send msg
  $("btnSend").onclick = sendMessage;
  $("msgInput").addEventListener("keydown", (e) => {
    if (e.key === "Enter") sendMessage();
  });

  // admin overlay
  $("btnAdmin").onclick = () => { openOverlay("adminOverlay"); switchAdmTab("users"); adminLoadUsers(); };
  $("btnAdminClose").onclick = () => closeOverlay("adminOverlay");
  $("adminBackdrop").onclick = () => closeOverlay("adminOverlay");

  $("admTabUsers").onclick = () => { switchAdmTab("users"); adminLoadUsers(); };
  $("admTabSystem").onclick = () => switchAdmTab("system");
  $("admTabRooms").onclick = () => switchAdmTab("rooms");
  $("admTabLogs").onclick = () => switchAdmTab("logs");

  $("admRefreshUsers").onclick = adminLoadUsers;
  $("admPunishGo").onclick = adminPunish;

  $("admSysUseCurrent").onclick = () => { $("admSysRoom").value = state.room.slug; };
  $("admSysSend").onclick = adminSendSystem;

  $("admCrGo").onclick = adminCreateRoom;
  $("admRoomInfoGo").onclick = adminRoomInfo;

  // logs placeholder
  $("admRefreshLogs").onclick = () => {
    $("admLogsMsg").textContent = "Logs API kommt als nächster Schritt (server endpoint /api/admin/logs).";
  };
}

async function initAppAfterLogin() {
  setStatus("verbinden…");
  await refreshRooms();
  await refreshTrending();

  // default join lobby
  await openRoom("lobby");

  connectSocket();
}

function connectSocket() {
  try {
    state.socket = io({ withCredentials: true });

    state.socket.on("connect", () => {
      setStatus("online");
      // join current room
      state.socket.emit("room:join", { slug: state.room.slug }, () => {});
    });

    state.socket.on("disconnect", () => setStatus("offline"));

    state.socket.on("message:new", (msg) => {
      // Only if message belongs to current room; server does not include slug, so we ignore if room_id mismatches in header?
      // We'll accept and display; it will only be emitted to the room namespace we joined.
      addMsgRow(msg);
    });

    state.socket.on("message:deleted", (payload) => applyDeleted(payload.id));

    state.socket.on("rooms:changed", async () => {
      await refreshRooms();
      await refreshTrending();
    });

  } catch (e) {
    setStatus("offline");
  }
}

async function boot() {
  bindUI();
  try {
    const r = await api("/api/me");
    state.me = r.user;
    updateMePill();
    setAdminUI();
    setLoggedInUI(true);
    await initAppAfterLogin();
  } catch {
    state.me = null;
    updateMePill();
    setLoggedInUI(false);
    setStatus("offline");
  }
}

boot();


// --- UI helpers (safe additions) ---
(function(){
  // close overlays by data-close
  document.querySelectorAll('[data-close]').forEach(btn=>{
    btn.addEventListener('click', ()=>{
      const id = btn.getAttribute('data-close');
      const el = document.getElementById(id);
      if (el) { try{ el.style.display='none'; }catch(e){} document.body.classList.remove('noScroll'); }
    });
  });

  // Admin tabs switching (if markup exists)
  const admButtons = Array.from(document.querySelectorAll('[data-admtab]'));
  if (admButtons.length){
    const tabs = {
      users: document.getElementById('admUsers'),
      rooms: document.getElementById('admRooms'),
      logs: document.getElementById('admLogs'),
      bots: document.getElementById('admBots'),
      system: document.getElementById('admSystem'),
    };
    const setTab = (k)=>{
      admButtons.forEach(b=>b.classList.toggle('active', b.getAttribute('data-admtab')===k));
      Object.entries(tabs).forEach(([name, el])=>{
        if (!el) return;
        el.style.display = (name===k) ? 'block' : 'none';
      });
    };
    admButtons.forEach(b=> b.addEventListener('click', ()=> setTab(b.getAttribute('data-admtab')) ));
    setTab('users');
  }

  // mobile sidebar toggle
  const btn = document.getElementById('btnMobileMenu');
  const sb = document.getElementById('sidebar');
  if (btn && sb){
    btn.addEventListener('click', ()=> sb.classList.toggle('open'));
  }
})();

