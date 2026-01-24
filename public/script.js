const byId = (id) => document.getElementById(id);
const qs = (sel, root = document) => root.querySelector(sel);
const qsa = (sel, root = document) => Array.from(root.querySelectorAll(sel));

let me = null;
let flags = null;
let ws = null;
let currentRoom = "lobby";

let adminUnlocked = false;

let dmThreadId = null;
let dmPeer = null;

let typingUsers = new Map();
let typingTimer = null;

function esc(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function safeRoom(input) {
  const room = String(input || "lobby")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_-]/g, "")
    .slice(0, 32);
  return room || "lobby";
}

function toast(msg, ms = 2200) {
  const t = byId("toast");
  if (!t) return;
  t.textContent = String(msg ?? "");
  t.classList.remove("hidden");
  t.classList.add("show");
  clearTimeout(toast._t);
  toast._t = setTimeout(() => {
    t.classList.remove("show");
    if (t.classList.contains("toast") && t.id === "toast") t.classList.add("hidden");
  }, ms);
}

async function api(url, opt = {}) {
  const res = await fetch(url, {
    method: opt.method || "GET",
    headers: { "Content-Type": "application/json", ...(opt.headers || {}) },
    body: opt.body,
    credentials: "include"
  });
  let data = null;
  try { data = await res.json(); } catch { data = null; }
  if (!res.ok) throw new Error(data?.error || `http_${res.status}`);
  return data;
}

function show(el, on) {
  if (!el) return;
  if (el.classList) el.classList.toggle("hidden", !on);
  else el.style.display = on ? "" : "none";
}

function setDisplayById(id, on) {
  const el = byId(id);
  if (!el) return;
  if (el.classList) el.classList.toggle("hidden", !on);
  else el.style.display = on ? "" : "none";
}

function setConn(txt) {
  const a = byId("conn");
  if (a) a.textContent = txt;
  const b = byId("meStatus");
  if (b) b.textContent = txt;
}

function wsUrl() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  return `${proto}://${location.host}`;
}

function openModal(id) {
  const el = byId(id);
  if (!el) return;
  el.style.display = "";
  el.classList?.remove("hidden");
  const back = byId("modalBackdrop");
  if (back) back.classList.remove("hidden");
}
function closeModal(id) {
  const el = byId(id);
  if (!el) return;
  el.style.display = "none";
  el.classList?.add("hidden");
  const back = byId("modalBackdrop");
  if (back) back.classList.add("hidden");
}
function closeAllModals() {
  const ids = [
    "modalProfile","modalAdmin","modalSetup","modalUnlock","modalSettings",
    "modalDMs","modalFriends","modalRoomInfo","modalTrending","modalUserCard",
    "profileModal"
  ];
  ids.forEach((id) => {
    const el = byId(id);
    if (!el) return;
    if (el.style) el.style.display = "none";
    el.classList?.add("hidden");
  });
  const back = byId("modalBackdrop");
  if (back) back.classList.add("hidden");
}

function handleErr(e) {
  const msg = String(e?.message || e || "error");
  const map = {
    not_logged_in: "Du bist nicht eingeloggt.",
    bad_login: "Login falsch.",
    banned: "Dieser Account ist gebannt.",
    username_taken: "Username ist schon vergeben.",
    username_invalid: "Username ist ungültig.",
    password_short: "Passwort zu kurz.",
    missing_fields: "Bitte alles ausfüllen.",
    not_admin: "Nur Admin.",
    admin_panel_locked: "Admin Panel ist gesperrt.",
    admin_panel_needs_setup: "Admin Setup nötig.",
    admin_panel_bad_password: "Falsches Admin-Panel-Passwort.",
    setup_not_required: "Setup ist nicht nötig.",
    cannot_change_admin: "Admin kann nicht so geändert werden.",
    cannot_punish_admin: "Admin kann nicht bestraft werden.",
    cannot_force_admin: "Admin kann nicht verschoben werden.",
    bad_action: "Ungültige Aktion.",
    forbidden: "Nicht erlaubt.",
    not_found: "Nicht gefunden."
  };
  toast(map[msg] || msg, 2600);
}

function authUI(loggedIn) {
  const auth = byId("auth");
  const app = byId("app");
  if (auth && app) {
    auth.style.display = loggedIn ? "none" : "";
    app.style.display = loggedIn ? "" : "none";
  } else {
    setDisplayById("auth", !loggedIn);
    setDisplayById("app", loggedIn);
  }

  const meBar = byId("meBar");
  if (meBar) meBar.style.display = loggedIn ? "" : "none";
}

function setMeUI() {
  const name1 = byId("meName"); if (name1) name1.textContent = me?.username || "-";
  const role1 = byId("meRole"); if (role1) role1.textContent = me?.role || "-";

  const name2 = byId("me-name"); if (name2) name2.textContent = me?.username || "";
  const role2 = byId("me-role"); if (role2) role2.textContent = me?.role || "";

  const btnAdmin = byId("btnAdminPanel") || byId("btnAdmin");
  if (btnAdmin) btnAdmin.style.display = (me?.role === "admin") ? "" : "none";

  const av = byId("me-avatar") || byId("meAvatarImg");
  if (av && me?.username) {
    loadProfile(me.username).then((p) => {
      if (!p) return;
      if (p.avatar) { av.src = p.avatar; av.style.visibility = "visible"; }
      else { av.src = ""; av.style.visibility = "hidden"; }
    }).catch(() => {});
  }
}

async function refreshMe() {
  const data = await api("/api/me");
  me = data.user || null;
  flags = data.flags || null;
  adminUnlocked = !!flags?.adminPanelUnlocked;

  if (!me) return null;

  setMeUI();
  updateAdminStateUI();

  if (me.role === "admin" && (flags?.needsPasswordChange || flags?.adminPanelNeedsSetup)) {
    const setupModal = byId("modalSetup");
    if (setupModal) openModal("modalSetup");
  }
  return me;
}

async function loadProfile(username) {
  try {
    const data = await api(`/api/profile/${encodeURIComponent(username)}`);
    return data.profile || null;
  } catch {
    return null;
  }
}

async function loadMyProfileIntoInputs() {
  if (!me) return;
  const p = await loadProfile(me.username);
  const bio = p?.bio || "";
  const avatar = p?.avatar || "";

  const a = byId("meBio"); if (a) a.value = bio;
  const b = byId("meAvatar"); if (b) b.value = avatar;

  const c = byId("set-bio"); if (c) c.value = bio;
  const d = byId("set-avatar"); if (d) d.value = avatar;
}

async function saveProfile() {
  const bio = (byId("meBio")?.value ?? byId("set-bio")?.value ?? "").toString();
  const avatar = (byId("meAvatar")?.value ?? byId("set-avatar")?.value ?? "").toString();
  await api("/api/profile", { method: "POST", body: JSON.stringify({ bio, avatar }) });
  toast("Profil gespeichert");
  setMeUI();
}

async function changePassword() {
  const oldPassword = (byId("pwOld")?.value || "").toString();
  const newPassword = (byId("pwNew")?.value || "").toString();
  await api("/api/change-password", { method: "POST", body: JSON.stringify({ oldPassword, newPassword }) });
  if (byId("pwOld")) byId("pwOld").value = "";
  if (byId("pwNew")) byId("pwNew").value = "";
  toast("Passwort geändert");
  await refreshMe();
}

function chatBoxEl() {
  return byId("chat") || byId("chatBox") || byId("feed");
}

function clearChat() {
  const box = chatBoxEl();
  if (!box) return;
  box.innerHTML = "";
}

function addMessageCard(m) {
  const box = chatBoxEl();
  if (!box) return;

  const id = m.id != null ? Number(m.id) : null;
  const wrap = document.createElement("div");

  const room = m.room ? `#${esc(m.room)}` : "";
  const when = esc(m.created_at || "");
  const author = esc(m.author || m.author_name || "unknown");
  const role = esc(m.role || m.author_role || "");
  const content = esc(m.content || "");

  wrap.className = "msg";
  wrap.dataset.mid = id != null ? String(id) : "";

  if (box.id === "feed") {
    wrap.className = "post";
    wrap.innerHTML = `
      <div class="top">
        <div class="title">${author}${role ? ` • ${role}` : ""}</div>
        <div class="meta">${room} • ${when}</div>
      </div>
      <div class="body">${content}</div>
    `;
  } else {
    wrap.innerHTML = `
      <div class="msgTop">
        <div class="msgTitle">${author}${role ? ` • ${role}` : ""}</div>
        <div class="msgMeta">${room} ${room && when ? "•" : ""} ${when}</div>
      </div>
      <div class="msgBody">${content}</div>
    `;
  }

  wrap.addEventListener("contextmenu", async (e) => {
    e.preventDefault();
    if (!id) return;
    const ok = confirm("Nachricht löschen?");
    if (!ok) return;
    try {
      await api(`/api/messages/${id}`, { method: "DELETE" });
      toast("Gelöscht");
      wrap.remove();
    } catch (err) { handleErr(err); }
  });

  box.appendChild(wrap);
  if (box.scrollHeight != null) box.scrollTop = box.scrollHeight;
}

function addSystem(text) {
  addMessageCard({ id: null, room: currentRoom, author: "System", role: "", content: String(text || ""), created_at: new Date().toLocaleString() });
}

function applyMessageDeleted(messageId) {
  const box = chatBoxEl();
  if (!box) return;
  const el = box.querySelector(`[data-mid="${CSS.escape(String(messageId))}"]`);
  if (el) el.remove();
}

async function loadMessages(room) {
  const r = safeRoom(room);
  await api(`/api/messages?room=${encodeURIComponent(r)}&limit=120`).then((data) => {
    currentRoom = data.room || r;
    const roomName = byId("roomName") || byId("roomTitle");
    if (roomName) roomName.textContent = currentRoom;

    const roomInput = byId("room") || byId("roomInput");
    if (roomInput) roomInput.value = currentRoom;

    clearChat();
    (data.messages || []).forEach(addMessageCard);
  });
}

function sendChat(text) {
  const msg = String(text || "").trim();
  if (!msg) return;
  if (!ws || ws.readyState !== 1) return toast("Nicht verbunden");
  ws.send(JSON.stringify({ type: "chat", text: msg }));
}

function setTypingUI() {
  const el = byId("typingBar") || byId("typing") || byId("typingStatus");
  if (!el) return;

  const list = Array.from(typingUsers.values())
    .filter((x) => x.room === currentRoom && Date.now() - x.ts < 3000)
    .map((x) => x.user);

  if (!list.length) {
    el.textContent = "";
    el.classList?.add("hidden");
    return;
  }

  const shown = list.slice(0, 3);
  el.textContent = `${shown.join(", ")} tippt…`;
  el.classList?.remove("hidden");
}

function startTypingHeartbeat(on) {
  if (!ws || ws.readyState !== 1) return;
  try { ws.send(JSON.stringify({ type: "typing", room: currentRoom, on: !!on })); } catch {}
}

function bindTypingToInput(inputEl) {
  if (!inputEl) return;

  inputEl.addEventListener("input", () => {
    startTypingHeartbeat(true);
    clearTimeout(typingTimer);
    typingTimer = setTimeout(() => startTypingHeartbeat(false), 1200);
  });
}

function connectWs() {
  if (!me) return;
  if (ws) { try { ws.close(); } catch {} }

  setConn("connecting…");
  ws = new WebSocket(wsUrl());

  ws.addEventListener("open", () => {
    setConn("online");
    try { ws.send(JSON.stringify({ type: "join", room: currentRoom })); } catch {}
  });

  ws.addEventListener("message", async (ev) => {
    let data = null;
    try { data = JSON.parse(ev.data); } catch { return; }
    if (!data) return;

    if (data.type === "joined") {
      currentRoom = safeRoom(data.room || currentRoom);
      const roomName = byId("roomName") || byId("roomTitle");
      if (roomName) roomName.textContent = currentRoom;
      const roomInput = byId("room") || byId("roomInput");
      if (roomInput) roomInput.value = currentRoom;
      return;
    }

    if (data.type === "message" && data.message) {
      addMessageCard(data.message);
      return;
    }

    if (data.type === "typing") {
      const u = String(data.user || "").trim();
      if (!u || u === me.username) return;
      typingUsers.set(u, { user: u, room: safeRoom(data.room || currentRoom), ts: Date.now(), on: !!data.on });
      setTypingUI();
      return;
    }

    if (data.type === "dm") {
      const msg = data.message || null;
      if (msg) {
        toast(`DM von ${msg.author}`, 1800);
      }
      if (byId("modalDMs") && byId("modalDMs").style.display !== "none") {
        await dmRefreshList().catch(() => {});
        if (dmThreadId && Number(data.threadId) === Number(dmThreadId)) {
          await dmLoadThread(dmThreadId).catch(() => {});
        }
      }
      return;
    }

    if (data.type === "system") {
      const evn = data.event;

      if (evn === "message_deleted") {
        applyMessageDeleted(data.messageId);
        return;
      }

      if (evn === "muted" || evn === "muted_set") {
        const until = data.until_ts ? new Date(Number(data.until_ts) * 1000).toLocaleString() : "unendlich";
        addSystem(`Timeout aktiv (bis ${until})`);
        toast(`Timeout bis ${until}`);
        return;
      }
      if (evn === "unmuted") {
        addSystem("Timeout aufgehoben");
        toast("Timeout aufgehoben");
        return;
      }
      if (evn === "force_room") {
        const r = safeRoom(data.room || "lobby");
        currentRoom = r;
        await loadMessages(r).catch(() => {});
        toast(`Verschoben nach #${r}`);
        return;
      }
      if (evn === "kick") {
        addSystem("Du wurdest gekickt");
        toast("Gekickt");
        try { ws.close(); } catch {}
        return;
      }
      if (evn === "banned") {
        addSystem("Du bist gebannt");
        toast("Gebannt");
        try { ws.close(); } catch {}
        return;
      }
      if (evn === "admin_announce") {
        const room = safeRoom(data.room || currentRoom);
        const mode = data.mode === "html" ? "html" : "text";
        if (mode === "html") {
          addMessageCard({ id: null, room, author: "Announcement", role: "admin", content: `[HTML]\n${String(data.content || "")}`, created_at: new Date().toLocaleString() });
        } else {
          addMessageCard({ id: null, room, author: "Announcement", role: "admin", content: String(data.content || ""), created_at: new Date().toLocaleString() });
        }
        toast("Announcement");
        return;
      }
    }
  });

  ws.addEventListener("close", () => {
    setConn("offline");
    if (me) setTimeout(connectWs, 800);
  });

  ws.addEventListener("error", () => setConn("offline"));

  setInterval(setTypingUI, 800);
}

/* ========= UPDATE 2: ONLINE / FRIENDS / DMs ========= */

async function onlineRefresh() {
  const box = byId("onlineList") || byId("onlineBox") || byId("onlineMembersBox") || byId("roomMembersBox");
  if (!box) return;
  try {
    const data = await api("/api/online");
    const list = data.online || [];
    box.innerHTML = list.map((u) => `• ${esc(u.username)} (${esc(u.status)})`).join("<br>") || "<span class='hint'>keiner online</span>";
  } catch {
    box.innerHTML = "<span class='hint'>offline</span>";
  }
}

async function statusSave() {
  const sel = byId("meStatusSelect") || byId("statusSelect");
  if (!sel) return toast("Kein Status-Select gefunden");
  const status = String(sel.value || "online");
  await api("/api/status", { method: "POST", body: JSON.stringify({ status }) });
  toast("Status gespeichert");
  await onlineRefresh().catch(() => {});
}

async function friendsRefresh() {
  const listEl = byId("friendsList");
  const reqEl = byId("friendRequests");
  const blockEl = byId("blockedList");
  if (!listEl && !reqEl && !blockEl) return;

  const data = await api("/api/friends/list");
  const items = data.items || [];

  const accepted = items.filter((x) => x.status === "accepted");
  const incoming = items.filter((x) => x.status === "incoming");
  const blocked = items.filter((x) => x.status === "blocked");

  if (listEl) listEl.innerHTML = accepted.map((x) => `• ${esc(x.username)}`).join("<br>") || "<span class='hint'>keine friends</span>";

  if (reqEl) {
    reqEl.innerHTML = incoming.map((x) => {
      const u = esc(x.username);
      return `<div class="row" style="justify-content:space-between; gap:10px;">
        <span>• ${u}</span>
        <button class="btn" data-accept="${u}">Accept</button>
      </div>`;
    }).join("") || "<span class='hint'>keine requests</span>";

    qsa("[data-accept]", reqEl).forEach((b) => {
      b.addEventListener("click", async () => {
        const u = b.getAttribute("data-accept");
        try {
          await api("/api/friends/accept", { method: "POST", body: JSON.stringify({ username: u }) });
          toast("Accepted");
          await friendsRefresh();
        } catch (e) { handleErr(e); }
      });
    });
  }

  if (blockEl) blockEl.innerHTML = blocked.map((x) => `• ${esc(x.username)}`).join("<br>") || "<span class='hint'>keine geblockt</span>";
}

async function friendsRequest(username) {
  await api("/api/friends/request", { method: "POST", body: JSON.stringify({ username }) });
  toast("Friend request gesendet");
  await friendsRefresh().catch(() => {});
}

async function friendsBlock(username) {
  await api("/api/friends/block", { method: "POST", body: JSON.stringify({ username }) });
  toast("Geblockt");
  await friendsRefresh().catch(() => {});
}

async function dmStart(username) {
  const data = await api("/api/dm/start", { method: "POST", body: JSON.stringify({ username }) });
  dmThreadId = Number(data.threadId);
  dmPeer = username;
  return dmThreadId;
}

async function dmRefreshList() {
  const listEl = byId("dmList");
  if (!listEl) return;
  const data = await api("/api/dm/list");
  const items = data.items || [];
  if (!items.length) {
    listEl.innerHTML = "<span class='hint'>keine DMs</span>";
    return;
  }
  listEl.innerHTML = items.map((x) => {
    const active = dmThreadId && Number(x.thread_id) === Number(dmThreadId);
    return `<button class="chip" data-dm="${esc(x.thread_id)}" style="width:100%; text-align:left; ${active ? "border-color: rgba(40,255,160,.55);" : ""}">
      ${esc(x.username)}
      <span class="pill" style="float:right;">#${esc(x.thread_id)}</span>
    </button>`;
  }).join("");

  qsa("[data-dm]", listEl).forEach((b) => {
    b.addEventListener("click", async () => {
      const tid = Number(b.getAttribute("data-dm"));
      dmThreadId = tid;
      await dmLoadThread(tid).catch(handleErr);
    });
  });
}

async function dmLoadThread(threadId) {
  const chatEl = byId("dmChat");
  if (!chatEl) return;
  const data = await api(`/api/dm/${encodeURIComponent(threadId)}/messages`);
  const msgs = data.messages || [];
  chatEl.innerHTML = msgs.map((m) => {
    return `<div class="post">
      <div class="postTop">
        <div class="postTitleWrap">
          <div>
            <div class="postTitle">${esc(m.author)}</div>
            <div class="postMeta">${esc(m.created_at)}</div>
          </div>
        </div>
      </div>
      <div class="postContent">${esc(m.content)}</div>
    </div>`;
  }).join("") || "<span class='hint'>noch keine Nachrichten</span>";

  chatEl.scrollTop = chatEl.scrollHeight;
}

async function dmSend() {
  const input = byId("dmText") || byId("dmMsg") || byId("dmInput");
  if (!input) return toast("Kein DM Input");
  const text = String(input.value || "").trim();
  if (!text) return;
  if (!dmThreadId) return toast("Kein DM ausgewählt");
  await api(`/api/dm/${encodeURIComponent(dmThreadId)}/send`, { method: "POST", body: JSON.stringify({ content: text }) });
  input.value = "";
  await dmLoadThread(dmThreadId);
}

/* ========= UPDATE 1–3: ADMIN ========= */

function updateAdminStateUI() {
  const lockState = byId("adminLockState");
  if (lockState) lockState.textContent = adminUnlocked ? "entsperrt" : "gesperrt";
  const lockBtn = byId("btnAdminLock");
  if (lockBtn) show(lockBtn, adminUnlocked);
}

async function adminSetup() {
  const currentLoginPassword = (byId("setupCurrentLogin")?.value || "").toString();
  const newLoginPassword = (byId("setupNewLogin")?.value || "").toString();
  const newAdminPanelPassword = (byId("setupNewPanel")?.value || "").toString();
  await api("/api/admin/setup", { method: "POST", body: JSON.stringify({ currentLoginPassword, newLoginPassword, newAdminPanelPassword }) });
  byId("setupCurrentLogin") && (byId("setupCurrentLogin").value = "");
  byId("setupNewLogin") && (byId("setupNewLogin").value = "");
  byId("setupNewPanel") && (byId("setupNewPanel").value = "");
  toast("Admin Setup gespeichert");
  closeModal("modalSetup");
  await refreshMe();
}

async function adminUnlock() {
  const adminPanelPassword = (byId("unlockPw")?.value || "").toString();
  await api("/api/admin/panel/unlock", { method: "POST", body: JSON.stringify({ adminPanelPassword }) });
  byId("unlockPw") && (byId("unlockPw").value = "");
  toast("Admin entsperrt");
  closeModal("modalUnlock");
  await refreshMe();
}

async function adminLock() {
  await api("/api/admin/panel/lock", { method: "POST" });
  toast("Admin gesperrt");
  await refreshMe();
}

async function adminPunish() {
  const username = (byId("admTarget")?.value || "").trim();
  const action = (byId("admAction")?.value || "").trim();
  const durationSec = (byId("admDur")?.value || "perm").trim();
  const reason = (byId("admReason")?.value || "").trim();
  await api("/api/admin/punish", { method: "POST", body: JSON.stringify({ username, action, durationSec, reason }) });
  toast("OK");
}

async function adminForceRoom() {
  const username = (byId("admTarget")?.value || "").trim();
  const room = (byId("admRoom")?.value || "").trim();
  const data = await api("/api/admin/force-room", { method: "POST", body: JSON.stringify({ username, room }) });
  toast(`Forced → #${data.room}`);
}

async function adminChangeUserPassword() {
  const username = (byId("admUser")?.value || "").trim();
  const newPassword = (byId("admNewPw")?.value || "").toString();
  await api("/api/admin/change-user-password", { method: "POST", body: JSON.stringify({ username, newPassword }) });
  byId("admNewPw") && (byId("admNewPw").value = "");
  toast("Passwort gesetzt");
}

async function adminAnnounce() {
  const room = safeRoom((byId("annRoom")?.value || currentRoom).trim());
  const mode = (byId("annMode")?.value || "text").trim();
  const content = (byId("annContent")?.value || "").toString();
  await api("/api/admin/announce", { method: "POST", body: JSON.stringify({ room, mode, content }) });
  byId("annContent") && (byId("annContent").value = "");
  toast("Sent");
}

async function adminLoadUsers() {
  const out = byId("adminUsersBox") || byId("usersList") || byId("admUsersOut");
  if (!out) return toast("Kein Users-Box Element im HTML");
  const data = await api("/api/admin/users");
  const users = data.users || [];
  out.innerHTML = users.map((u) => {
    const b = u.banned_until ? ` banned` : "";
    const m = u.muted_until ? ` muted` : "";
    return `• ${esc(u.username)} (${esc(u.role)}) ${esc(u.status || "")}${b}${m}`;
  }).join("<br>") || "<span class='hint'>leer</span>";
  toast("Users geladen");
}

async function adminLoadLogs() {
  const out = byId("adminLogsBox") || byId("logsList") || byId("admLogsOut");
  if (!out) return toast("Kein Logs-Box Element im HTML");
  const data = await api("/api/admin/logs");
  const logs = data.logs || [];
  out.innerHTML = logs.map((l) => {
    return `• ${esc(l.admin)} → ${esc(l.action)} ${l.target_name ? esc(l.target_name) : ""} ${l.room ? "#" + esc(l.room) : ""} (${esc(new Date(l.created_at).toLocaleString())})`;
  }).join("<br>") || "<span class='hint'>leer</span>";
  toast("Logs geladen");
}

async function adminLoadRooms() {
  const out = byId("adminRoomsBox") || byId("roomsList") || byId("admRoomsOut");
  if (!out) return toast("Kein Rooms-Box Element im HTML");
  const data = await api("/api/admin/rooms");
  const rooms = data.rooms || [];
  out.innerHTML = rooms.map((r) => `• #${esc(r.name)} (${esc(r.category)}) ${r.locked ? "🔒" : ""}`).join("<br>") || "<span class='hint'>leer</span>";
  toast("Rooms geladen");
}

async function adminSaveRoom() {
  const name = (byId("roomEditName")?.value || byId("roomNameEdit")?.value || "").trim();
  const category = (byId("roomEditCat")?.value || byId("roomCategoryEdit")?.value || "General").trim();
  const rules = (byId("roomEditRules")?.value || byId("roomRulesEdit")?.value || "").trim();
  const password = (byId("roomEditPw")?.value || byId("roomPasswordEdit")?.value || "").toString();
  await api("/api/admin/rooms", { method: "POST", body: JSON.stringify({ name, category, rules, password }) });
  toast("Room gespeichert");
  await adminLoadRooms().catch(() => {});
}

async function adminBotsList() {
  const out = byId("botsList") || byId("adminBotsBox");
  if (!out) return toast("Kein Bots-Box Element im HTML");
  const data = await api("/api/admin/bots");
  const bots = data.bots || [];
  out.innerHTML = bots.map((b) => {
    const count = b.commands ? Object.keys(b.commands).length : 0;
    return `• ${esc(b.name)} in #${esc(b.room)} ${b.enabled ? "✅" : "⛔"} (${count} cmds)`;
  }).join("<br>") || "<span class='hint'>keine bots</span>";
  toast("Bots geladen");
}

function parseBotCommands(text) {
  const lines = String(text || "").split("\n").map((x) => x.trim()).filter(Boolean);
  const obj = {};
  for (const line of lines) {
    const parts = line.split("=>");
    if (parts.length < 2) continue;
    const key = parts[0].trim().toLowerCase();
    const val = parts.slice(1).join("=>").trim();
    if (!key.startsWith("!")) continue;
    if (!val) continue;
    obj[key] = val.slice(0, 800);
  }
  return obj;
}

async function adminBotSave() {
  const name = (byId("botName")?.value || "").trim();
  const room = (byId("botRoom")?.value || currentRoom).trim();
  const enabledEl = byId("botEnabled");
  const enabled = enabledEl ? !!enabledEl.checked : true;
  const commandsText = (byId("botCommands")?.value || "").toString();
  const commands = parseBotCommands(commandsText);
  await api("/api/admin/bots", { method: "POST", body: JSON.stringify({ name, room, enabled, commands }) });
  toast("Bot gespeichert");
  await adminBotsList().catch(() => {});
}

async function adminAutomodLoad() {
  const room = (byId("amRoom")?.value || currentRoom).trim();
  const data = await api(`/api/admin/automod?room=${encodeURIComponent(room)}`);
  const cfg = data.cfg || {};
  if (byId("amRate")) byId("amRate").value = String(cfg.rate_max ?? 8);
  if (byId("amMode")) byId("amMode").value = String(cfg.bad_words_mode ?? "off");
  if (byId("amWords")) byId("amWords").value = (cfg.blacklist || []).join("\n");
  toast("Automod geladen");
}

async function adminAutomodSave() {
  const room = (byId("amRoom")?.value || currentRoom).trim();
  const rateMax = Number(byId("amRate")?.value || 8);
  const badWordsMode = String(byId("amMode")?.value || "off");
  const blacklist = String(byId("amWords")?.value || "")
    .split("\n").map((x) => x.trim()).filter(Boolean).slice(0, 200);
  await api("/api/admin/automod", { method: "POST", body: JSON.stringify({ room, rateMax, badWordsMode, blacklist }) });
  toast("Automod gespeichert");
}

/* ========= AUTH ========= */

async function loginFlow() {
  const u = (byId("logUser")?.value ?? byId("log-user")?.value ?? "").toString().trim();
  const p = (byId("logPass")?.value ?? byId("log-pass")?.value ?? "").toString();
  await api("/api/login", { method: "POST", body: JSON.stringify({ username: u, password: p }) });
  authUI(true);
  await afterLogin();
}

async function registerFlow() {
  const u = (byId("regUser")?.value ?? byId("reg-user")?.value ?? "").toString().trim();
  const p = (byId("regPass")?.value ?? byId("reg-pass")?.value ?? "").toString();
  const bio = (byId("regBio")?.value ?? byId("reg-bio")?.value ?? "").toString();
  const avatar = (byId("regAvatar")?.value ?? byId("reg-avatar")?.value ?? "").toString();
  await api("/api/register", { method: "POST", body: JSON.stringify({ username: u, password: p, bio, avatar }) });
  authUI(true);
  await afterLogin();
}

async function logoutFlow() {
  try { await api("/api/logout", { method: "POST" }); } catch {}
  me = null; flags = null; adminUnlocked = false;
  if (ws) { try { ws.close(); } catch {} ws = null; }
  closeAllModals();
  authUI(false);
  setConn("offline");
  toast("Logout");
}

/* ========= AFTER LOGIN ========= */

async function afterLogin() {
  await refreshMe();
  const roomInput = byId("room") || byId("roomInput");
  currentRoom = safeRoom(roomInput?.value || "lobby");
  await loadMessages(currentRoom);
  connectWs();
  await onlineRefresh().catch(() => {});
}

/* ========= Binding ========= */

function bind(el, ev, fn) {
  if (!el) return;
  el.addEventListener(ev, fn);
}

function bindAll() {
  bind(document, "keydown", (e) => {
    if (e.key === "Escape") closeAllModals();
  });

  bind(byId("btnLogin") || byId("btn-login"), "click", () => loginFlow().catch(handleErr));
  bind(byId("btnRegister") || byId("btn-register"), "click", () => registerFlow().catch(handleErr));
  bind(byId("btnLogout"), "click", () => logoutFlow().catch(handleErr));

  const passLogin = byId("logPass") || byId("log-pass");
  bind(passLogin, "keydown", (e) => { if (e.key === "Enter") (byId("btnLogin") || byId("btn-login"))?.click(); });

  const passReg = byId("regPass") || byId("reg-pass");
  bind(passReg, "keydown", (e) => { if (e.key === "Enter") (byId("btnRegister") || byId("btn-register"))?.click(); });

  bind(byId("btnJoin"), "click", async () => {
    try {
      const roomInput = byId("room") || byId("roomInput");
      const r = safeRoom(roomInput?.value || "lobby");
      currentRoom = r;
      await loadMessages(r);
      if (ws && ws.readyState === 1) ws.send(JSON.stringify({ type: "join", room: r }));
      else connectWs();
      toast(`#${r}`);
    } catch (e) { handleErr(e); }
  });

  const msgInput = byId("msg") || byId("msgInput") || byId("messageInput");
  bindTypingToInput(msgInput);

  bind(byId("btnSend"), "click", () => {
    const el = byId("msg") || byId("msgInput") || byId("messageInput");
    const txt = el ? el.value : "";
    if (el) el.value = "";
    sendChat(txt);
  });

  bind(msgInput, "keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      (byId("btnSend"))?.click();
    }
  });

  bind(byId("btnSaveProfile") || byId("btn-save-profile"), "click", () => saveProfile().catch(handleErr));
  bind(byId("btnChangePw"), "click", () => changePassword().catch(handleErr));

  bind(byId("btn-profile"), "click", async () => {
    await loadMyProfileIntoInputs().catch(() => {});
    openModal("profileModal");
  });
  bind(byId("btn-close-profile"), "click", () => closeModal("profileModal"));

  bind(byId("btnProfile"), "click", async () => {
    await loadMyProfileIntoInputs().catch(() => {});
    openModal("modalProfile");
  });

  bind(byId("btnAdminPanel") || byId("btnAdmin"), "click", () => {
    if (!adminUnlocked) openModal("modalUnlock");
    else openModal("modalAdmin");
  });

  bind(byId("btnSetupClose"), "click", () => closeModal("modalSetup"));
  bind(byId("btnUnlockClose"), "click", () => closeModal("modalUnlock"));
  bind(byId("btnAdminClose"), "click", () => closeModal("modalAdmin"));

  bind(byId("btnDoSetup"), "click", () => adminSetup().catch(handleErr));
  bind(byId("btnDoUnlock"), "click", () => adminUnlock().catch(handleErr));
  bind(byId("btnAdminLock"), "click", () => adminLock().catch(handleErr));

  bind(byId("btnAdmDo"), "click", () => adminPunish().catch(handleErr));
  bind(byId("btnAdmForceRoom"), "click", () => adminForceRoom().catch(handleErr));
  bind(byId("btnAdmChangePw"), "click", () => adminChangeUserPassword().catch(handleErr));
  bind(byId("btnAnnSend"), "click", () => adminAnnounce().catch(handleErr));

  bind(byId("btnAdmLoadUsers"), "click", () => adminLoadUsers().catch(handleErr));
  bind(byId("btnLoadLogs"), "click", () => adminLoadLogs().catch(handleErr));
  bind(byId("btnLoadRooms"), "click", () => adminLoadRooms().catch(handleErr));
  bind(byId("btnSaveRoom"), "click", () => adminSaveRoom().catch(handleErr));

  bind(byId("btnBotList"), "click", () => adminBotsList().catch(handleErr));
  bind(byId("btnBotSave"), "click", () => adminBotSave().catch(handleErr));

  bind(byId("btnAutomodLoad"), "click", () => adminAutomodLoad().catch(handleErr));
  bind(byId("btnAutomodSave") || byId("btnSaveAutomod"), "click", () => adminAutomodSave().catch(handleErr));

  bind(byId("btnSaveStatus"), "click", () => statusSave().catch(handleErr));
  bind(byId("btnRefreshOnline"), "click", () => onlineRefresh().catch(() => toast("offline")));

  bind(byId("btnDMs"), "click", async () => {
    openModal("modalDMs");
    await dmRefreshList().catch(handleErr);
  });
  bind(byId("btnFriends"), "click", async () => {
    openModal("modalFriends");
    await friendsRefresh().catch(handleErr);
  });

  bind(byId("btnDmRefresh"), "click", () => dmRefreshList().catch(handleErr));
  bind(byId("btnDmSend"), "click", () => dmSend().catch(handleErr));

  bind(byId("btnAddFriend"), "click", async () => {
    const u = prompt("Username?");
    if (!u) return;
    await friendsRequest(u.trim()).catch(handleErr);
  });

  bind(byId("btnSearchUser"), "click", async () => {
    const u = (byId("searchUser")?.value || "").trim();
    if (!u) return;
    const out = byId("searchResult");
    if (out) out.textContent = "loading…";
    const p = await loadProfile(u);
    if (!p) {
      if (out) out.textContent = "not found";
      toast("Nicht gefunden");
      return;
    }
    if (out) out.textContent = `@${p.username}\nrole: ${p.role}\nstatus: ${p.status}\nbio: ${p.bio || "-"}`;
    const ucName = byId("ucName"); if (ucName) ucName.textContent = p.username;
    const ucBio = byId("ucBio"); if (ucBio) ucBio.textContent = p.bio || "-";
    const ucMeta = byId("ucMeta"); if (ucMeta) ucMeta.textContent = `role: ${p.role} • status: ${p.status}`;
    const ucAv = byId("ucAvatar");
    if (ucAv) { ucAv.src = p.avatar || ""; ucAv.style.visibility = p.avatar ? "visible" : "hidden"; }
  });

  bind(byId("btnOpenUserCard"), "click", () => openModal("modalUserCard"));
  bind(byId("btnUcDM"), "click", async () => {
    const u = (byId("ucName")?.textContent || "").trim();
    if (!u) return;
    await dmStart(u).catch(handleErr);
    openModal("modalDMs");
    await dmRefreshList().catch(() => {});
    await dmLoadThread(dmThreadId).catch(() => {});
  });
  bind(byId("btnUcFriend"), "click", async () => {
    const u = (byId("ucName")?.textContent || "").trim();
    if (!u) return;
    await friendsRequest(u).catch(handleErr);
  });
  bind(byId("btnUcBlock"), "click", async () => {
    const u = (byId("ucName")?.textContent || "").trim();
    if (!u) return;
    await friendsBlock(u).catch(handleErr);
  });

  qsa("[data-close]").forEach((b) => bind(b, "click", () => closeAllModals()));
  bind(byId("modalBackdrop"), "click", () => closeAllModals());
}

async function boot() {
  bindAll();
  setConn("offline");

  try {
    const data = await api("/api/me");
    if (data.user) {
      authUI(true);
      await afterLogin();
    } else {
      authUI(false);
    }
  } catch {
    authUI(false);
    toast("Server nicht erreichbar");
  }
}

boot();
