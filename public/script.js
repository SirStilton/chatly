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
  if (!el) return;
  el.textContent = String(text);
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

function setConn(text) {
  if ($("conn")) $("conn").textContent = text;
  if ($("meStatus")) $("meStatus").textContent = text;
}

function showApp(on) {
  $("auth").classList.toggle("hidden", on);
  $("app").classList.toggle("hidden", !on);
}

function modal(on, id) {
  $("modalBackdrop").classList.toggle("hidden", !on);
  $(id).classList.toggle("hidden", !on);
}

function closeAllModals() {
  $("modalBackdrop").classList.add("hidden");
  ["modalProfile", "modalAdmin", "modalSetup", "modalUnlock"].forEach((id) => $(id).classList.add("hidden"));
}

function formatTime(ts) {
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return String(ts || "");
  }
}

function clearChat() {
  if ($("chat")) $("chat").innerHTML = "";
}

function addPost({ cls = "", title = "", meta = "", avatar = "", html = null, text = "" }) {
  const box = $("chat");
  if (!box) return;

  const el = document.createElement("div");
  el.className = `post ${cls}`.trim();

  const av = avatar ? `<img class="avatar" src="${escapeHtml(avatar)}" alt="">` : "";
  const t = `<div class="postTitle">${escapeHtml(title)}</div>`;
  const m = `<div class="postMeta">${escapeHtml(meta)}</div>`;

  el.innerHTML = `
    <div class="postTop">
      <div class="postTitleWrap">
        ${av}
        <div>
          ${t}
          ${m}
        </div>
      </div>
    </div>
    <div class="postContent"></div>
  `;

  const content = el.querySelector(".postContent");
  if (html !== null) content.innerHTML = html;
  else content.textContent = text;

  box.appendChild(el);
  box.scrollTop = box.scrollHeight;
}

function addMessage(msg) {
  addPost({
    cls: "",
    title: `${msg.author}${msg.role ? ` • ${msg.role}` : ""}`,
    meta: `${msg.created_at} • #${msg.room}`,
    avatar: msg.avatar || "",
    text: msg.content || ""
  });
}

function addSystem(text) {
  addPost({
    cls: "system",
    title: "System",
    meta: `${formatTime(Date.now())}`,
    text: text
  });
}

function addAnnouncement(mode, content, room) {
  if (mode === "html") {
    addPost({
      cls: "announce",
      title: "Announcement",
      meta: `#${room} • ${formatTime(Date.now())}`,
      html: content
    });
  } else {
    addPost({
      cls: "announce",
      title: "Announcement",
      meta: `#${room} • ${formatTime(Date.now())}`,
      text: content
    });
  }
}

async function loadMessages(room) {
  const r = safeRoom(room);
  const data = await api(`/api/messages?room=${encodeURIComponent(r)}&limit=120`, { method: "GET" });
  currentRoom = data.room || r;
  $("roomInput").value = currentRoom;
  $("roomName").textContent = currentRoom;
  $("roomTitle").textContent = currentRoom;
  clearChat();
  for (const m of data.messages || []) addMessage(m);
}

function connectWs() {
  if (!me) return;

  if (ws) {
    try { ws.onopen = ws.onmessage = ws.onclose = null; ws.close(); } catch {}
    ws = null;
  }

  setConn("connecting…");
  ws = new WebSocket(wsUrl());

  ws.addEventListener("open", () => {
    setConn("online");
    ws.send(JSON.stringify({ type: "join", room: currentRoom }));
  });

  ws.addEventListener("message", async (ev) => {
    let data;
    try { data = JSON.parse(ev.data); } catch { return; }

    if (data.type === "joined") {
      currentRoom = safeRoom(data.room || currentRoom);
      $("roomInput").value = currentRoom;
      $("roomName").textContent = currentRoom;
      $("roomTitle").textContent = currentRoom;
      return;
    }

    if (data.type === "message" && data.message) {
      addMessage(data.message);
      return;
    }

    if (data.type === "system") {
      if (data.event === "muted" || data.event === "muted_set") {
        const until = data.until_ts ? new Date(data.until_ts * 1000).toLocaleString() : "unendlich";
        addSystem(`Timeout aktiv (bis ${until})`);
        showToast(`Timeout bis ${until}`);
        return;
      }
      if (data.event === "unmuted") {
        addSystem("Timeout aufgehoben");
        showToast("Timeout aufgehoben");
        return;
      }
      if (data.event === "force_room") {
        const r = safeRoom(data.room || "lobby");
        currentRoom = r;
        $("roomInput").value = r;
        $("roomName").textContent = r;
        $("roomTitle").textContent = r;
        await loadMessages(r);
        addSystem(`Du wurdest nach #${r} verschoben`);
        showToast(`Verschoben nach #${r}`);
        return;
      }
      if (data.event === "kick") {
        addSystem("Du wurdest gekickt");
        showToast("Gekickt");
        try { ws.close(); } catch {}
        return;
      }
      if (data.event === "banned") {
        addSystem("Du bist gebannt");
        showToast("Gebannt");
        try { ws.close(); } catch {}
        return;
      }
      if (data.event === "admin_announce") {
        const room = safeRoom(data.room || currentRoom);
        const mode = data.mode === "html" ? "html" : "text";
        const content = mode === "html" ? String(data.content || "") : String(data.content || "");
        addAnnouncement(mode, mode === "html" ? content : content, room);
        showToast("Announcement");
        return;
      }
    }
  });

  ws.addEventListener("close", () => {
    setConn("offline");
    if (me) setTimeout(connectWs, 900);
  });

  ws.addEventListener("error", () => {
    setConn("offline");
  });
}

function sendChat(text) {
  const msg = String(text || "").trim();
  if (!msg) return;
  if (!ws || ws.readyState !== 1) return showToast("Nicht verbunden");
  ws.send(JSON.stringify({ type: "chat", text: msg }));
}

async function refreshMe() {
  const data = await api("/api/me", { method: "GET" });
  me = data.user || null;
  flags = data.flags || null;
  if (!me) return null;

  $("meName").textContent = me.username;
  $("meRole").textContent = me.role;
  $("meNameSide").textContent = me.username;
  $("meRoleSide").textContent = me.role;
  $("btnAdmin").classList.toggle("hidden", me.role !== "admin");

  await loadProfilePreview(me.username);
  updateAdminUiState();

  return me;
}

async function loadProfilePreview(username) {
  try {
    const data = await api(`/api/profile/${encodeURIComponent(username)}`, { method: "GET" });
    const p = data.profile || {};
    $("previewName").textContent = p.username || "-";
    $("previewBio").textContent = p.bio || "-";

    const av = p.avatar || "";
    $("previewAvatar").src = av || "";
    $("meAvatarImg").src = av || "";
    $("meAvatarImg").style.visibility = av ? "visible" : "hidden";
    $("previewAvatar").style.visibility = av ? "visible" : "hidden";
  } catch {
    $("previewName").textContent = username;
    $("previewBio").textContent = "-";
  }
}

function updateAdminUiState() {
  if (!me || me.role !== "admin") return;

  const unlocked = !!flags?.adminPanelUnlocked;
  $("adminLockState").textContent = unlocked ? "entsperrt" : "gesperrt";
  $("btnAdminLock").classList.toggle("hidden", !unlocked);

  const needsSetup = !!flags?.adminPanelNeedsSetup || !!flags?.needsPasswordChange;
  if (needsSetup) {
    modal(true, "modalSetup");
  }
}

async function doLogin() {
  const username = $("logUser").value.trim();
  const password = $("logPass").value;
  const data = await api("/api/login", {
    method: "POST",
    body: JSON.stringify({ username, password })
  });
  me = data.user;
  flags = data.flags || null;
  showApp(true);
  showToast("Eingeloggt");
  await afterLogin();
}

async function doRegister() {
  const username = $("regUser").value.trim();
  const password = $("regPass").value;
  const bio = $("regBio").value || "";
  const avatar = $("regAvatar").value || "";
  const data = await api("/api/register", {
    method: "POST",
    body: JSON.stringify({ username, password, bio, avatar })
  });
  me = data.user;
  flags = null;
  showApp(true);
  showToast("Registriert");
  await afterLogin();
}

async function doLogout() {
  try { await api("/api/logout", { method: "POST" }); } catch {}
  me = null;
  flags = null;
  if (ws) {
    try { ws.onopen = ws.onmessage = ws.onclose = null; ws.close(); } catch {}
    ws = null;
  }
  closeAllModals();
  showApp(false);
  setConn("offline");
  showToast("Logout");
}

async function afterLogin() {
  await refreshMe();
  currentRoom = safeRoom($("roomInput").value || "lobby");
  $("roomInput").value = currentRoom;
  $("roomName").textContent = currentRoom;
  $("roomTitle").textContent = currentRoom;
  await loadMessages(currentRoom);
  connectWs();
}

async function saveProfile() {
  const bio = $("meBio").value || "";
  const avatar = $("meAvatar").value || "";
  await api("/api/profile", {
    method: "POST",
    body: JSON.stringify({ bio, avatar })
  });
  showToast("Profil gespeichert");
  await loadProfilePreview(me.username);
}

async function loadMyProfileToInputs() {
  const data = await api(`/api/profile/${encodeURIComponent(me.username)}`, { method: "GET" });
  const p = data.profile || {};
  $("meBio").value = p.bio || "";
  $("meAvatar").value = p.avatar || "";
}

async function changeMyPassword() {
  const oldPassword = $("pwOld").value || "";
  const newPassword = $("pwNew").value || "";
  await api("/api/change-password", {
    method: "POST",
    body: JSON.stringify({ oldPassword, newPassword })
  });
  $("pwOld").value = "";
  $("pwNew").value = "";
  showToast("Passwort geändert");
  await refreshMe();
}

async function adminSetup() {
  const currentLoginPassword = $("setupCurrentLogin").value || "";
  const newLoginPassword = $("setupNewLogin").value || "";
  const newAdminPanelPassword = $("setupNewPanel").value || "";
  await api("/api/admin/setup", {
    method: "POST",
    body: JSON.stringify({ currentLoginPassword, newLoginPassword, newAdminPanelPassword })
  });
  $("setupCurrentLogin").value = "";
  $("setupNewLogin").value = "";
  $("setupNewPanel").value = "";
  modal(false, "modalSetup");
  showToast("Admin Setup gespeichert");
  await refreshMe();
}

async function adminUnlock() {
  const adminPanelPassword = $("unlockPw").value || "";
  await api("/api/admin/panel/unlock", {
    method: "POST",
    body: JSON.stringify({ adminPanelPassword })
  });
  $("unlockPw").value = "";
  modal(false, "modalUnlock");
  showToast("Admin entsperrt");
  await refreshMe();
}

async function adminLock() {
  await api("/api/admin/panel/lock", { method: "POST" });
  showToast("Admin gesperrt");
  await refreshMe();
}

async function adminPunish() {
  const username = $("admTarget").value.trim();
  const action = $("admAction").value;
  const durationSec = $("admDur").value || "perm";
  const reason = $("admReason").value || "";
  await api("/api/admin/punish", {
    method: "POST",
    body: JSON.stringify({ username, action, durationSec, reason })
  });
  showToast(`OK: ${action}`);
}

async function adminForceRoom() {
  const username = $("admTarget").value.trim();
  const room = $("admRoom").value.trim();
  const data = await api("/api/admin/force-room", {
    method: "POST",
    body: JSON.stringify({ username, room })
  });
  showToast(`Forced → #${data.room}`);
}

async function adminChangeUserPassword() {
  const username = $("admUser").value.trim();
  const newPassword = $("admNewPw").value || "";
  await api("/api/admin/change-user-password", {
    method: "POST",
    body: JSON.stringify({ username, newPassword })
  });
  $("admNewPw").value = "";
  showToast("Passwort gesetzt");
}

async function adminAnnounce() {
  const room = $("annRoom").value || currentRoom;
  const mode = $("annMode").value || "text";
  const content = $("annContent").value || "";
  await api("/api/admin/announce", {
    method: "POST",
    body: JSON.stringify({ room, mode, content })
  });
  showToast("Sent");
  $("annContent").value = "";
}

async function searchProfile() {
  const username = $("searchUser").value.trim();
  if (!username) return;
  $("searchResult").textContent = "loading…";
  try {
    const data = await api(`/api/profile/${encodeURIComponent(username)}`, { method: "GET" });
    const p = data.profile || {};
    const since = p.created_at ? new Date(p.created_at).toLocaleDateString() : "-";
    $("searchResult").textContent = `@${p.username}\nrole: ${p.role}\nsince: ${since}\nbio: ${p.bio || "-"}`;
  } catch (e) {
    $("searchResult").textContent = "not found";
  }
}

function setAuthTab(which) {
  $("tabLogin").classList.toggle("active", which === "login");
  $("tabRegister").classList.toggle("active", which === "register");
  $("paneLogin").classList.toggle("hidden", which !== "login");
  $("paneRegister").classList.toggle("hidden", which !== "register");
}

function setAdminTab(which) {
  document.querySelectorAll(".tabBtn").forEach((b) => b.classList.toggle("active", b.dataset.tab === which));
  $("tab_mod").classList.toggle("hidden", which !== "mod");
  $("tab_announce").classList.toggle("hidden", which !== "announce");
  $("tab_pw").classList.toggle("hidden", which !== "pw");
}

function handleErr(e) {
  const msg = String(e?.message || e || "error");
  const map = {
    not_logged_in: "Du bist nicht eingeloggt.",
    bad_login: "Login falsch (Name oder Passwort).",
    banned: "Dieser Account ist gebannt.",
    username_taken: "Username ist schon vergeben.",
    username_short: "Username zu kurz (mind. 3).",
    username_invalid: "Username hat ungültige Zeichen.",
    password_short: "Passwort zu kurz.",
    missing_fields: "Bitte alles ausfüllen.",
    not_admin: "Nur Admin.",
    admin_panel_locked: "Admin Panel ist gesperrt.",
    admin_panel_needs_setup: "Admin Panel muss zuerst eingerichtet werden.",
    admin_panel_bad_password: "Falsches Admin-Panel-Passwort.",
    setup_not_required: "Setup ist nicht nötig.",
    cannot_change_admin: "Admin-Account nicht so änderbar.",
    cannot_punish_admin: "Admin kann nicht bestraft werden.",
    cannot_force_admin: "Admin kann nicht verschoben werden.",
    bad_action: "Ungültige Aktion."
  };
  showToast(map[msg] || msg);
}

function bind() {
  $("tabLogin").addEventListener("click", () => setAuthTab("login"));
  $("tabRegister").addEventListener("click", () => setAuthTab("register"));

  $("btnLogin").addEventListener("click", () => doLogin().catch(handleErr));
  $("btnRegister").addEventListener("click", () => doRegister().catch(handleErr));
  $("btnLogout").addEventListener("click", () => doLogout().catch(handleErr));

  $("logPass").addEventListener("keydown", (e) => { if (e.key === "Enter") $("btnLogin").click(); });
  $("regPass").addEventListener("keydown", (e) => { if (e.key === "Enter") $("btnRegister").click(); });

  $("btnJoin").addEventListener("click", async () => {
    try {
      const r = safeRoom($("roomInput").value || "lobby");
      await loadMessages(r);
      if (ws && ws.readyState === 1) ws.send(JSON.stringify({ type: "join", room: r }));
      else connectWs();
      showToast(`#${r}`);
    } catch (e) { handleErr(e); }
  });

  document.querySelectorAll(".chip").forEach((btn) => {
    btn.addEventListener("click", () => {
      $("roomInput").value = btn.dataset.room || "lobby";
      $("btnJoin").click();
    });
  });

  $("btnSend").addEventListener("click", () => {
    const inp = $("msg");
    const text = inp.value;
    inp.value = "";
    sendChat(text);
  });

  $("msg").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      $("btnSend").click();
    }
  });

  $("btnProfile").addEventListener("click", async () => {
    await loadMyProfileToInputs().catch(() => {});
    modal(true, "modalProfile");
  });

  $("btnSaveProfile").addEventListener("click", () => saveProfile().catch(handleErr));
  $("btnChangePw").addEventListener("click", () => changeMyPassword().catch(handleErr));

  $("btnAdmin").addEventListener("click", () => {
    modal(true, "modalAdmin");
    setAdminTab("mod");
  });

  $("btnOpenUnlock").addEventListener("click", () => modal(true, "modalUnlock"));
  $("btnDoUnlock").addEventListener("click", () => adminUnlock().catch(handleErr));
  $("btnAdminLock").addEventListener("click", () => adminLock().catch(handleErr));

  $("btnDoSetup").addEventListener("click", () => adminSetup().catch(handleErr));

  $("btnAdmDo").addEventListener("click", () => adminPunish().catch(handleErr));
  $("btnAdmForceRoom").addEventListener("click", () => adminForceRoom().catch(handleErr));
  $("btnAdmChangePw").addEventListener("click", () => adminChangeUserPassword().catch(handleErr));
  $("btnAnnSend").addEventListener("click", () => adminAnnounce().catch(handleErr));

  document.querySelectorAll("[data-close]").forEach((b) => {
    b.addEventListener("click", () => closeAllModals());
  });
  $("modalBackdrop").addEventListener("click", () => closeAllModals());

  document.querySelectorAll(".tabBtn").forEach((b) => {
    b.addEventListener("click", () => setAdminTab(b.dataset.tab));
  });

  $("btnSearchUser").addEventListener("click", () => searchProfile().catch(handleErr));
  $("searchUser").addEventListener("keydown", (e) => { if (e.key === "Enter") $("btnSearchUser").click(); });
}

async function boot() {
  bind();
  setConn("offline");
  try {
    const data = await api("/api/me", { method: "GET" });
    if (data.user) {
      showApp(true);
      await afterLogin();
    } else {
      showApp(false);
    }
  } catch {
    showApp(false);
    showToast("Server nicht erreichbar");
  }
}

boot();
