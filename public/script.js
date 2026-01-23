const $ = (id) => document.getElementById(id);

let me = null;
let flags = null;
let ws = null;
let currentRoom = "lobby";

function escapeHtml(str) {
  return String(str)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function showToast(text, ms = 2400) {
  const el = $("toast");
  if (!el) return alert(text);
  el.textContent = text;
  el.classList.add("show");
  clearTimeout(showToast._t);
  showToast._t = setTimeout(() => el.classList.remove("show"), ms);
}

async function api(url, options = {}) {
  const res = await fetch(url, {
    ...options,
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    credentials: "include"
  });

  let data = null;
  try { data = await res.json(); } catch { data = null; }

  if (!res.ok) throw new Error(data?.error || `http_${res.status}`);
  return data;
}

function wsUrl() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  return `${proto}://${location.host}`;
}

function safeRoom(input) {
  const room = String(input || "lobby")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_-]/g, "")
    .slice(0, 32);
  return room || "lobby";
}

function setConnectionState(text) {
  if ($("conn")) $("conn").textContent = text;
}

function openModal(id) {
  const m = $(id);
  if (m) m.style.display = "";
}

function closeModal(id) {
  const m = $(id);
  if (m) m.style.display = "none";
}

function setAuthUi(isAuthed) {
  if ($("auth")) $("auth").style.display = isAuthed ? "none" : "";
  if ($("app")) $("app").style.display = isAuthed ? "" : "none";
  if ($("meBar")) $("meBar").style.display = isAuthed ? "" : "none";

  if ($("meName")) $("meName").textContent = me ? me.username : "-";
  if ($("meRole")) $("meRole").textContent = me ? me.role : "-";

  const isAdmin = me?.role === "admin";
  if ($("btnAdminPanel")) $("btnAdminPanel").style.display = isAuthed && isAdmin ? "" : "none";
}

function clearChatBox() {
  const box = $("chat");
  if (box) box.innerHTML = "";
}

function addChatLine(m) {
  const box = $("chat");
  if (!box) return;

  const line = document.createElement("div");
  line.className = "post";
  line.style.marginTop = "10px";

  const avatar = m.avatar ? `<img class="avatar" src="${escapeHtml(m.avatar)}" alt="">` : "";
  const roleBadge = m.role ? `<span class="badge">${escapeHtml(m.role)}</span>` : "";

  line.innerHTML = `
    <div class="postTop">
      <div class="postTitleWrap">
        ${avatar}
        <div>
          <div class="postTitle">${escapeHtml(m.author)} ${roleBadge}</div>
          <div class="postMeta">${escapeHtml(m.created_at)} • #${escapeHtml(m.room)}</div>
        </div>
      </div>
    </div>
    <div class="postContent">${escapeHtml(m.content)}</div>
  `;

  box.appendChild(line);
  box.scrollTop = box.scrollHeight;
}

function addSystemLine(text) {
  const box = $("chat");
  if (!box) return;

  const line = document.createElement("div");
  line.className = "post";
  line.style.marginTop = "10px";
  line.style.maxWidth = "92%";
  line.style.opacity = "0.9";

  line.innerHTML = `
    <div class="postContent"><b>System:</b> ${escapeHtml(text)}</div>
  `;

  box.appendChild(line);
  box.scrollTop = box.scrollHeight;
}

async function loadMessages(room) {
  const r = safeRoom(room);
  const data = await api(`/api/messages?room=${encodeURIComponent(r)}&limit=80`, { method: "GET" });
  currentRoom = data.room || r;
  if ($("room")) $("room").value = currentRoom;
  if ($("roomName")) $("roomName").textContent = currentRoom;

  clearChatBox();
  for (const m of data.messages || []) addChatLine(m);
}

function connectWs() {
  if (!me) return;

  if (ws) {
    try { ws.onopen = ws.onmessage = ws.onclose = null; ws.close(); } catch {}
    ws = null;
  }

  setConnectionState("connecting…");
  ws = new WebSocket(wsUrl());

  ws.addEventListener("open", () => {
    setConnectionState("online");
    ws.send(JSON.stringify({ type: "join", room: currentRoom }));
  });

  ws.addEventListener("message", async (ev) => {
    let data;
    try { data = JSON.parse(ev.data); } catch { return; }

    if (data.type === "joined") {
      currentRoom = data.room || currentRoom;
      if ($("room")) $("room").value = currentRoom;
      if ($("roomName")) $("roomName").textContent = currentRoom;
      showToast(`Raum: ${currentRoom}`);
      return;
    }

    if (data.type === "message" && data.message) {
      addChatLine(data.message);
      return;
    }

    if (data.type === "system") {
      if (data.event === "muted" || data.event === "muted_set") {
        const until = data.until_ts ? new Date(data.until_ts * 1000).toLocaleString() : "unendlich";
        addSystemLine(`Timeout aktiv (bis ${until})`);
        showToast(`Timeout aktiv bis: ${until}`);
        return;
      }
      if (data.event === "unmuted") {
        addSystemLine("Timeout aufgehoben");
        showToast("Timeout aufgehoben");
        return;
      }
      if (data.event === "force_room") {
        const r = safeRoom(data.room || "lobby");
        currentRoom = r;
        if ($("room")) $("room").value = r;
        if ($("roomName")) $("roomName").textContent = r;
        await loadMessages(r);
        addSystemLine(`Du wurdest nach #${r} verschoben`);
        showToast(`Verschoben nach #${r}`);
        return;
      }
      if (data.event === "kick") {
        addSystemLine("Du wurdest gekickt");
        showToast("Du wurdest gekickt");
        try { ws.close(); } catch {}
        return;
      }
      if (data.event === "banned") {
        addSystemLine("Du bist gebannt");
        showToast("Du bist gebannt");
        try { ws.close(); } catch {}
        return;
      }
    }
  });

  ws.addEventListener("close", () => {
    setConnectionState("offline");
    if (me) setTimeout(connectWs, 900);
  });

  ws.addEventListener("error", () => {
    setConnectionState("offline");
  });
}

function sendChat(text) {
  const msg = String(text || "").trim();
  if (!msg) return;

  if (!ws || ws.readyState !== 1) {
    showToast("Nicht verbunden");
    return;
  }
  ws.send(JSON.stringify({ type: "chat", text: msg }));
}

async function refreshMe() {
  const data = await api("/api/me", { method: "GET" });
  me = data.user || null;
  flags = data.flags || null;
  setAuthUi(!!me);
  updateAdminUiState();
  return me;
}

function updateAdminUiState() {
  if (me?.role !== "admin") return;

  const unlocked = !!flags?.adminPanelUnlocked;
  if ($("adminLockState")) $("adminLockState").textContent = unlocked ? "entsperrt" : "gesperrt";
  if ($("btnAdminLock")) $("btnAdminLock").style.display = unlocked ? "" : "none";

  const needsSetup = !!flags?.adminPanelNeedsSetup || !!flags?.needsPasswordChange;
  if (needsSetup) openModal("modalSetup");
}

async function doRegister() {
  const username = $("regUser")?.value?.trim() || "";
  const password = $("regPass")?.value || "";
  const bio = $("regBio")?.value || "";
  const avatar = $("regAvatar")?.value || "";

  const data = await api("/api/register", {
    method: "POST",
    body: JSON.stringify({ username, password, bio, avatar })
  });

  me = data.user;
  flags = null;
  setAuthUi(true);
  showToast("Registriert & eingeloggt");
  await afterLogin();
}

async function doLogin() {
  const username = $("logUser")?.value?.trim() || "";
  const password = $("logPass")?.value || "";

  const data = await api("/api/login", {
    method: "POST",
    body: JSON.stringify({ username, password })
  });

  me = data.user;
  flags = data.flags || null;
  setAuthUi(true);
  showToast("Eingeloggt");
  await afterLogin();

  if (me?.role === "admin" && (flags?.needsPasswordChange || flags?.adminPanelNeedsSetup)) {
    openModal("modalSetup");
  }

  if (flags?.muted) {
    const until = flags?.mute?.until_ts ? new Date(flags.mute.until_ts * 1000).toLocaleString() : "unendlich";
    addSystemLine(`Timeout aktiv (bis ${until})`);
  }
}

async function doLogout() {
  try { await api("/api/logout", { method: "POST" }); } catch {}

  me = null;
  flags = null;

  if (ws) {
    try { ws.onopen = ws.onmessage = ws.onclose = null; ws.close(); } catch {}
    ws = null;
  }

  closeModal("modalSetup");
  closeModal("modalUnlock");
  closeModal("modalAdmin");

  setAuthUi(false);
  setConnectionState("offline");
  showToast("Ausgeloggt");
}

async function saveProfile() {
  const bio = $("meBio")?.value || "";
  const avatar = $("meAvatar")?.value || "";
  await api("/api/profile", {
    method: "POST",
    body: JSON.stringify({ bio, avatar })
  });
  showToast("Profil gespeichert");
}

async function loadMyProfile() {
  if (!me) return;
  const data = await api(`/api/profile/${encodeURIComponent(me.username)}`, { method: "GET" });
  const p = data.profile || {};
  if ($("meBio")) $("meBio").value = p.bio || "";
  if ($("meAvatar")) $("meAvatar").value = p.avatar || "";
}

async function changeMyPassword() {
  const oldPassword = $("pwOld")?.value || "";
  const newPassword = $("pwNew")?.value || "";
  await api("/api/change-password", {
    method: "POST",
    body: JSON.stringify({ oldPassword, newPassword })
  });
  if ($("pwOld")) $("pwOld").value = "";
  if ($("pwNew")) $("pwNew").value = "";
  showToast("Passwort geändert");
  await refreshMe();
}

async function afterLogin() {
  currentRoom = safeRoom($("room")?.value || "lobby");
  await loadMyProfile();
  await loadMessages(currentRoom);
  connectWs();
}

async function adminSetup() {
  const currentLoginPassword = $("setupCurrentLogin")?.value || "";
  const newLoginPassword = $("setupNewLogin")?.value || "";
  const newAdminPanelPassword = $("setupNewPanel")?.value || "";

  await api("/api/admin/setup", {
    method: "POST",
    body: JSON.stringify({ currentLoginPassword, newLoginPassword, newAdminPanelPassword })
  });

  if ($("setupCurrentLogin")) $("setupCurrentLogin").value = "";
  if ($("setupNewLogin")) $("setupNewLogin").value = "";
  if ($("setupNewPanel")) $("setupNewPanel").value = "";

  closeModal("modalSetup");
  showToast("Admin Setup gespeichert");
  await refreshMe();
}

async function adminUnlock() {
  const adminPanelPassword = $("unlockPw")?.value || "";
  await api("/api/admin/panel/unlock", {
    method: "POST",
    body: JSON.stringify({ adminPanelPassword })
  });
  if ($("unlockPw")) $("unlockPw").value = "";
  closeModal("modalUnlock");
  showToast("Admin Panel entsperrt");
  await refreshMe();
}

async function adminLock() {
  await api("/api/admin/panel/lock", { method: "POST" });
  showToast("Admin Panel gesperrt");
  await refreshMe();
}

async function adminChangeUserPassword() {
  const username = $("admUser")?.value?.trim() || "";
  const newPassword = $("admNewPw")?.value || "";

  await api("/api/admin/change-user-password", {
    method: "POST",
    body: JSON.stringify({ username, newPassword })
  });

  if ($("admNewPw")) $("admNewPw").value = "";
  showToast("User-Passwort geändert");
}

async function adminDoPunish() {
  const username = $("admTarget")?.value?.trim() || "";
  const reason = $("admReason")?.value || "";
  const action = $("admAction")?.value || "ban";
  const durationSec = $("admDur")?.value || "perm";

  await api("/api/admin/punish", {
    method: "POST",
    body: JSON.stringify({ username, action, durationSec, reason })
  });

  showToast(`OK: ${action}`);
}

async function adminForceRoom() {
  const username = $("admTarget")?.value?.trim() || "";
  const room = $("admRoom")?.value?.trim() || "lobby";

  const data = await api("/api/admin/force-room", {
    method: "POST",
    body: JSON.stringify({ username, room })
  });

  showToast(`Forced: ${username} → #${data.room}`);
}

function handleErr(e) {
  const msg = String(e?.message || e || "error");

  const map = {
    not_logged_in: "Du bist nicht eingeloggt.",
    bad_login: "Login falsch (Name oder Passwort).",
    banned: "Dieser Account ist gebannt.",
    username_taken: "Der Username ist schon vergeben.",
    username_short: "Username zu kurz (mind. 3).",
    username_invalid: "Username hat ungültige Zeichen.",
    password_short: "Passwort zu kurz.",
    missing_fields: "Bitte alles ausfüllen.",
    not_admin: "Nur Admin.",
    admin_panel_locked: "Admin Panel ist gesperrt.",
    admin_panel_needs_setup: "Admin Panel muss zuerst eingerichtet werden.",
    admin_panel_bad_password: "Falsches Admin-Panel-Passwort.",
    setup_not_required: "Setup ist nicht nötig.",
    cannot_change_admin: "Admin-Passwort hier nicht änderbar.",
    cannot_punish_admin: "Admin kann nicht bestraft werden.",
    cannot_force_admin: "Admin kann nicht verschoben werden.",
    bad_action: "Ungültige Aktion."
  };

  showToast(map[msg] || msg);
}

function bindEvents() {
  if ($("btnLogin")) $("btnLogin").addEventListener("click", () => doLogin().catch(handleErr));
  if ($("btnRegister")) $("btnRegister").addEventListener("click", () => doRegister().catch(handleErr));
  if ($("btnLogout")) $("btnLogout").addEventListener("click", () => doLogout().catch(handleErr));

  if ($("logPass")) $("logPass").addEventListener("keydown", (e) => { if (e.key === "Enter") $("btnLogin")?.click(); });
  if ($("regPass")) $("regPass").addEventListener("keydown", (e) => { if (e.key === "Enter") $("btnRegister")?.click(); });

  if ($("btnSaveProfile")) $("btnSaveProfile").addEventListener("click", () => saveProfile().catch(handleErr));
  if ($("btnChangePw")) $("btnChangePw").addEventListener("click", () => changeMyPassword().catch(handleErr));

  if ($("btnJoin")) $("btnJoin").addEventListener("click", async () => {
    try {
      const r = safeRoom($("room")?.value || "lobby");
      await loadMessages(r);
      if (ws && ws.readyState === 1) ws.send(JSON.stringify({ type: "join", room: r }));
      else connectWs();
    } catch (e) { handleErr(e); }
  });

  if ($("btnSend")) $("btnSend").addEventListener("click", () => {
    const inp = $("msg");
    if (!inp) return;
    const text = inp.value;
    inp.value = "";
    sendChat(text);
  });

  if ($("msg")) $("msg").addEventListener("keydown", (e) => { if (e.key === "Enter") $("btnSend")?.click(); });

  if ($("btnAdminPanel")) $("btnAdminPanel").addEventListener("click", () => {
    openModal("modalAdmin");
    updateAdminUiState();
  });

  if ($("btnAdminClose")) $("btnAdminClose").addEventListener("click", () => closeModal("modalAdmin"));
  if ($("btnOpenUnlock")) $("btnOpenUnlock").addEventListener("click", () => openModal("modalUnlock"));

  if ($("btnSetupClose")) $("btnSetupClose").addEventListener("click", () => closeModal("modalSetup"));
  if ($("btnUnlockClose")) $("btnUnlockClose").addEventListener("click", () => closeModal("modalUnlock"));

  if ($("btnDoSetup")) $("btnDoSetup").addEventListener("click", () => adminSetup().catch(handleErr));
  if ($("btnDoUnlock")) $("btnDoUnlock").addEventListener("click", () => adminUnlock().catch(handleErr));
  if ($("btnAdminLock")) $("btnAdminLock").addEventListener("click", () => adminLock().catch(handleErr));
  if ($("btnAdmChangePw")) $("btnAdmChangePw").addEventListener("click", () => adminChangeUserPassword().catch(handleErr));

  if ($("btnAdmDo")) $("btnAdmDo").addEventListener("click", () => adminDoPunish().catch(handleErr));
  if ($("btnAdmForceRoom")) $("btnAdmForceRoom").addEventListener("click", () => adminForceRoom().catch(handleErr));
}

async function boot() {
  bindEvents();

  try {
    await refreshMe();
    if (me) await afterLogin();
    else setConnectionState("offline");
  } catch {
    setConnectionState("offline");
    showToast("Server nicht erreichbar");
  }
}

boot();
