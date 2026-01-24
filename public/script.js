const $ = (id) => document.getElementById(id);

let me = null;
let flags = null;
let ws = null;
let currentRoom = "lobby";
let lastSearchedUser = null;
let activeDmUser = null;

function escapeHtml(str) {
  return String(str ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function showToast(text, ms = 2400) {
  const el = $("toast");
  if (!el) return;
  el.textContent = String(text ?? "");
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

  if (!res.ok) {
    throw new Error(data?.error || `http_${res.status}`);
  }
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
  if ($("meStatusBadge")) {
    $("meStatusBadge").textContent = text;
    $("meStatusBadge").classList.toggle("hidden", !text);
  }
}

function showApp(on) {
  $("auth")?.classList.toggle("hidden", !!on);
  $("app")?.classList.toggle("hidden", !on);
}

function modalOpen(id) {
  $("modalBackdrop")?.classList.remove("hidden");
  $(id)?.classList.remove("hidden");
}

function modalClose(id) {
  $("modalBackdrop")?.classList.add("hidden");
  $(id)?.classList.add("hidden");
}

function closeAllModals() {
  $("modalBackdrop")?.classList.add("hidden");
  [
    "modalProfile",
    "modalAdmin",
    "modalSetup",
    "modalUnlock",
    "modalSettings",
    "modalDMs",
    "modalFriends",
    "modalRoomInfo",
    "modalTrending",
    "modalUserCard"
  ].forEach((id) => $(id)?.classList.add("hidden"));
}

function formatTime(ts) {
  try { return new Date(ts).toLocaleString(); }
  catch { return String(ts || ""); }
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
  el.innerHTML = `
    <div class="postTop">
      <div class="postTitleWrap">
        ${av}
        <div>
          <div class="postTitle">${escapeHtml(title)}</div>
          <div class="postMeta">${escapeHtml(meta)}</div>
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
    meta: formatTime(Date.now()),
    text: text
  });
}

function addAnnouncement(mode, content, room) {
  if (mode === "html") {
    addPost({
      cls: "announce",
      title: "Announcement",
      meta: `#${room} • ${formatTime(Date.now())}`,
      html: String(content || "")
    });
  } else {
    addPost({
      cls: "announce",
      title: "Announcement",
      meta: `#${room} • ${formatTime(Date.now())}`,
      text: String(content || "")
    });
  }
}

async function loadMessages(room) {
  const r = safeRoom(room);
  const data = await api(`/api/messages?room=${encodeURIComponent(r)}&limit=120`, { method: "GET" });

  currentRoom = data.room || r;
  if ($("roomInput")) $("roomInput").value = currentRoom;
  if ($("roomName")) $("roomName").textContent = currentRoom;
  if ($("roomTitle")) $("roomTitle").textContent = currentRoom;

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
    try {
      ws.send(JSON.stringify({ type: "join", room: currentRoom }));
    } catch {}
  });

  ws.addEventListener("message", async (ev) => {
    let data;
    try { data = JSON.parse(ev.data); } catch { return; }

    if (data.type === "joined") {
      currentRoom = safeRoom(data.room || currentRoom);
      if ($("roomInput")) $("roomInput").value = currentRoom;
      if ($("roomName")) $("roomName").textContent = currentRoom;
      if ($("roomTitle")) $("roomTitle").textContent = currentRoom;
      return;
    }

    if (data.type === "message" && data.message) {
      addMessage(data.message);
      return;
    }

    if (data.type === "system") {
      const evn = data.event;

      if (evn === "muted" || evn === "muted_set") {
        const until = data.until_ts ? new Date(data.until_ts * 1000).toLocaleString() : "unendlich";
        addSystem(`Timeout aktiv (bis ${until})`);
        showToast(`Timeout bis ${until}`);
        return;
      }

      if (evn === "unmuted") {
        addSystem("Timeout aufgehoben");
        showToast("Timeout aufgehoben");
        return;
      }

      if (evn === "force_room") {
        const r = safeRoom(data.room || "lobby");
        currentRoom = r;
        if ($("roomInput")) $("roomInput").value = r;
        if ($("roomName")) $("roomName").textContent = r;
        if ($("roomTitle")) $("roomTitle").textContent = r;
        await loadMessages(r);
        addSystem(`Du wurdest nach #${r} verschoben`);
        showToast(`Verschoben nach #${r}`);
        return;
      }

      if (evn === "kick") {
        addSystem("Du wurdest gekickt");
        showToast("Gekickt");
        try { ws.close(); } catch {}
        return;
      }

      if (evn === "banned") {
        addSystem("Du bist gebannt");
        showToast("Gebannt");
        try { ws.close(); } catch {}
        return;
      }

      if (evn === "admin_announce") {
        const room = safeRoom(data.room || currentRoom);
        const mode = data.mode === "html" ? "html" : "text";
        addAnnouncement(mode, data.content || "", room);
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
  try { ws.send(JSON.stringify({ type: "chat", text: msg })); } catch {}
}

/* =======================
   ME / PROFILE
======================= */

async function refreshMe() {
  const data = await api("/api/me", { method: "GET" });
  me = data.user || null;
  flags = data.flags || null;

  if (!me) return null;

  $("meName") && ($("meName").textContent = me.username);
  $("meRole") && ($("meRole").textContent = me.role);
  $("meNameSide") && ($("meNameSide").textContent = me.username);
  $("meRoleSide") && ($("meRoleSide").textContent = me.role);

  $("btnAdmin")?.classList.toggle("hidden", me.role !== "admin");

  await loadProfilePreview(me.username);
  updateAdminUiState();

  return me;
}

async function loadProfilePreview(username) {
  try {
    const data = await api(`/api/profile/${encodeURIComponent(username)}`, { method: "GET" });
    const p = data.profile || {};

    $("previewName") && ($("previewName").textContent = p.username || "-");
    $("previewBio") && ($("previewBio").textContent = p.bio || "-");

    const av = p.avatar || "";
    if ($("previewAvatar")) {
      $("previewAvatar").src = av || "";
      $("previewAvatar").style.visibility = av ? "visible" : "hidden";
    }
    if ($("meAvatarImg")) {
      $("meAvatarImg").src = av || "";
      $("meAvatarImg").style.visibility = av ? "visible" : "hidden";
    }
  } catch {
    $("previewName") && ($("previewName").textContent = username || "-");
    $("previewBio") && ($("previewBio").textContent = "-");
  }
}

async function loadMyProfileToInputs() {
  const data = await api(`/api/profile/${encodeURIComponent(me.username)}`, { method: "GET" });
  const p = data.profile || {};
  $("meBio") && ($("meBio").value = p.bio || "");
  $("meAvatar") && ($("meAvatar").value = p.avatar || "");

  // optional UI defaults for Update2 settings
  $("meStatusSelect") && ($("meStatusSelect").value = "online");
  $("dmPrivacy") && ($("dmPrivacy").value = "everyone");
}

async function saveProfile() {
  const bio = $("meBio")?.value || "";
  const avatar = $("meAvatar")?.value || "";
  await api("/api/profile", {
    method: "POST",
    body: JSON.stringify({ bio, avatar })
  });
  showToast("Profil gespeichert");
  await loadProfilePreview(me.username);
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

/* =======================
   AUTH
======================= */

function setAuthTab(which) {
  $("tabLogin")?.classList.toggle("active", which === "login");
  $("tabRegister")?.classList.toggle("active", which === "register");
  $("paneLogin")?.classList.toggle("hidden", which !== "login");
  $("paneRegister")?.classList.toggle("hidden", which !== "register");
}

async function doLogin() {
  const username = $("logUser")?.value.trim();
  const password = $("logPass")?.value || "";
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
  const username = $("regUser")?.value.trim();
  const password = $("regPass")?.value || "";
  const bio = $("regBio")?.value || "";
  const avatar = $("regAvatar")?.value || "";
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

  currentRoom = safeRoom($("roomInput")?.value || "lobby");
  $("roomInput") && ($("roomInput").value = currentRoom);
  $("roomName") && ($("roomName").textContent = currentRoom);
  $("roomTitle") && ($("roomTitle").textContent = currentRoom);

  await loadMessages(currentRoom);
  connectWs();
}

/* =======================
   ADMIN (Update 1)
======================= */

function updateAdminUiState() {
  if (!me || me.role !== "admin") return;

  const unlocked = !!flags?.adminPanelUnlocked;
  $("adminLockState") && ($("adminLockState").textContent = unlocked ? "entsperrt" : "gesperrt");
  $("btnAdminLock")?.classList.toggle("hidden", !unlocked);

  const needsSetup = !!flags?.adminPanelNeedsSetup || !!flags?.needsPasswordChange;
  if (needsSetup) {
    modalOpen("modalSetup");
  }
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
  modalClose("modalSetup");
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
  modalClose("modalUnlock");
  showToast("Admin entsperrt");
  await refreshMe();
}

async function adminLock() {
  await api("/api/admin/panel/lock", { method: "POST" });
  showToast("Admin gesperrt");
  await refreshMe();
}

async function adminPunish() {
  const username = $("admTarget")?.value.trim();
  const action = $("admAction")?.value;
  const durationSec = $("admDur")?.value || "perm";
  const reason = $("admReason")?.value || "";
  await api("/api/admin/punish", {
    method: "POST",
    body: JSON.stringify({ username, action, durationSec, reason })
  });
  showToast(`OK: ${action}`);
}

async function adminForceRoom() {
  const username = $("admTarget")?.value.trim();
  const room = $("admRoom")?.value.trim();
  const data = await api("/api/admin/force-room", {
    method: "POST",
    body: JSON.stringify({ username, room })
  });
  showToast(`Forced → #${data.room}`);
}

async function adminChangeUserPassword() {
  const username = $("admUser")?.value.trim();
  const newPassword = $("admNewPw")?.value || "";
  await api("/api/admin/change-user-password", {
    method: "POST",
    body: JSON.stringify({ username, newPassword })
  });
  if ($("admNewPw")) $("admNewPw").value = "";
  showToast("Passwort gesetzt");
}

async function adminAnnounce() {
  const room = $("annRoom")?.value || currentRoom;
  const mode = $("annMode")?.value || "text";
  const content = $("annContent")?.value || "";
  await api("/api/admin/announce", {
    method: "POST",
    body: JSON.stringify({ room, mode, content })
  });
  showToast("Sent");
  if ($("annContent")) $("annContent").value = "";
}

/* =======================
   Search / User Card (Update 2 UI)
======================= */

async function searchProfile() {
  const username = $("searchUser")?.value.trim();
  if (!username) return;

  $("searchResult") && ($("searchResult").textContent = "loading…");

  try {
    const data = await api(`/api/profile/${encodeURIComponent(username)}`, { method: "GET" });
    const p = data.profile || {};
    lastSearchedUser = p.username || username;

    const since = p.created_at ? new Date(p.created_at).toLocaleDateString() : "-";
    $("searchResult") && ($("searchResult").textContent =
      `@${p.username}\nrole: ${p.role}\nsince: ${since}\nbio: ${p.bio || "-"}`);

    showToast("User gefunden");
  } catch {
    lastSearchedUser = username;
    $("searchResult") && ($("searchResult").textContent = "not found");
    showToast("Nicht gefunden");
  }
}

async function openUserCardFromLastSearch() {
  const u = (lastSearchedUser || $("searchUser")?.value || "").trim();
  if (!u) return showToast("Kein User");

  try {
    const data = await api(`/api/profile/${encodeURIComponent(u)}`, { method: "GET" });
    const p = data.profile || {};
    $("ucName") && ($("ucName").textContent = p.username || u);
    $("ucBio") && ($("ucBio").textContent = p.bio || "-");
    $("ucMeta") && ($("ucMeta").textContent = `role: ${p.role}`);
    if ($("ucAvatar")) {
      $("ucAvatar").src = p.avatar || "";
      $("ucAvatar").style.visibility = p.avatar ? "visible" : "hidden";
    }
  } catch {
    $("ucName") && ($("ucName").textContent = u);
    $("ucBio") && ($("ucBio").textContent = "-");
    $("ucMeta") && ($("ucMeta").textContent = "role: -");
    if ($("ucAvatar")) {
      $("ucAvatar").src = "";
      $("ucAvatar").style.visibility = "hidden";
    }
  }

  modalOpen("modalUserCard");
}

/* =======================
   Tabs (Admin/Profile/Settings/Friends)
======================= */

function setAdminTab(which) {
  // only affects Admin modal tabs
  const panes = ["mod", "users", "rooms", "logs", "announce", "pw", "bots", "automod"];
  panes.forEach((p) => {
    const el = $(`tab_${p}`);
    if (el) el.classList.toggle("hidden", p !== which);
  });

  // only toggle buttons inside the admin modal
  const modal = $("modalAdmin");
  if (modal) {
    modal.querySelectorAll(".tabs .tabBtn").forEach((b) => {
      b.classList.toggle("active", b.dataset.tab === which);
    });
  }
}

function setProfileTab(which) {
  const panes = ["me", "security", "danger"];
  panes.forEach((p) => {
    const el = $(`p_tab_${p}`);
    if (el) el.classList.toggle("hidden", p !== which);
  });

  const modal = $("modalProfile");
  if (modal) {
    modal.querySelectorAll(".tabs .tabBtn").forEach((b) => {
      b.classList.toggle("active", b.dataset.tab === which);
    });
  }
}

function setSettingsTab(which) {
  const panes = ["appearance", "rooms", "smart"];
  panes.forEach((p) => {
    const el = $(`s_tab_${p}`);
    if (el) el.classList.toggle("hidden", p !== which);
  });

  const modal = $("modalSettings");
  if (modal) {
    modal.querySelectorAll(".tabs .tabBtn").forEach((b) => {
      b.classList.toggle("active", b.dataset.tab === which);
    });
  }
}

function setFriendsTab(which) {
  const panes = ["friends", "requests", "blocked"];
  panes.forEach((p) => {
    const el = $(`f_tab_${p}`);
    if (el) el.classList.toggle("hidden", p !== which);
  });

  const modal = $("modalFriends");
  if (modal) {
    modal.querySelectorAll(".tabs .tabBtn").forEach((b) => {
      b.classList.toggle("active", b.dataset.tab === which);
    });
  }
}

/* =======================
   Update 2/3 UI actions (safe placeholders)
======================= */

function uiComingSoon(name) {
  showToast(`${name}: kommt gleich (Update 2/3)`, 2200);
}

function fillPlaceholderList(elId, lines) {
  const box = $(elId);
  if (!box) return;
  box.textContent = "";
  const pre = document.createElement("div");
  pre.className = "hint";
  pre.textContent = lines.join("\n");
  box.appendChild(pre);
}

function openRoomInfo() {
  fillPlaceholderList("roomRulesBox", [
    `#${currentRoom}`,
    "Rules: (kommt aus server later)",
    "- kein Spam",
    "- respektvoll",
    "- kein Scam"
  ]);
  fillPlaceholderList("roomMembersBox", [
    "Members: (Update 2)",
    "• online list kommt später"
  ]);
  modalOpen("modalRoomInfo");
}

function openTrending() {
  fillPlaceholderList("trendingList", [
    "Trending (Update 1 UI):",
    "• #lobby (demo)",
    "• #general (demo)",
    "• #help (demo)"
  ]);
  modalOpen("modalTrending");
}

function openDMs() {
  fillPlaceholderList("dmList", [
    "DMs (Update 2)",
    "Noch keine Daten – Endpoints kommen gleich."
  ]);
  fillPlaceholderList("dmChat", [
    "DM Chat (Update 2)",
    "Wähle einen User in der Liste."
  ]);
  modalOpen("modalDMs");
}

function openFriends() {
  fillPlaceholderList("friendsList", [
    "Friends (Update 2)",
    "Noch keine Daten – Endpoints kommen gleich."
  ]);
  fillPlaceholderList("friendRequests", [
    "Requests (Update 2)",
    "Noch keine Daten."
  ]);
  fillPlaceholderList("blockedList", [
    "Blocked (Update 2)",
    "Noch keine Daten."
  ]);
  modalOpen("modalFriends");
  setFriendsTab("friends");
}

function openSettings() {
  setSettingsTab("appearance");
  modalOpen("modalSettings");
}

function applyBg() {
  const v = $("bgSelect")?.value || "glass";
  localStorage.setItem("chatly_bg", v);
  showToast(`Background: ${v}`);
}

function restoreBg() {
  const v = localStorage.getItem("chatly_bg");
  if ($("bgSelect") && v) $("bgSelect").value = v;
}

/* =======================
   Error mapping
======================= */

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

/* =======================
   Bind events
======================= */

function bindGlobalClose() {
  document.querySelectorAll("[data-close]").forEach((b) => {
    b.addEventListener("click", () => closeAllModals());
  });
  $("modalBackdrop")?.addEventListener("click", () => closeAllModals());
}

function bindAuth() {
  $("tabLogin")?.addEventListener("click", () => setAuthTab("login"));
  $("tabRegister")?.addEventListener("click", () => setAuthTab("register"));

  $("btnLogin")?.addEventListener("click", () => doLogin().catch(handleErr));
  $("btnRegister")?.addEventListener("click", () => doRegister().catch(handleErr));

  $("logPass")?.addEventListener("keydown", (e) => { if (e.key === "Enter") $("btnLogin")?.click(); });
  $("regPass")?.addEventListener("keydown", (e) => { if (e.key === "Enter") $("btnRegister")?.click(); });
}

function bindTopbar() {
  $("btnLogout")?.addEventListener("click", () => doLogout().catch(handleErr));

  $("btnProfile")?.addEventListener("click", async () => {
    await loadMyProfileToInputs().catch(() => {});
    modalOpen("modalProfile");
    setProfileTab("me");
  });

  $("btnAdmin")?.addEventListener("click", () => {
    modalOpen("modalAdmin");
    setAdminTab("mod");
  });

  $("btnSettings")?.addEventListener("click", () => openSettings());
  $("btnDMs")?.addEventListener("click", () => openDMs());
  $("btnFriends")?.addEventListener("click", () => openFriends());
}

function bindRoomsAndChat() {
  $("btnJoin")?.addEventListener("click", async () => {
    try {
      const r = safeRoom($("roomInput")?.value || "lobby");
      await loadMessages(r);
      if (ws && ws.readyState === 1) ws.send(JSON.stringify({ type: "join", room: r }));
      else connectWs();
      showToast(`#${r}`);
    } catch (e) { handleErr(e); }
  });

  document.querySelectorAll(".chip").forEach((btn) => {
    btn.addEventListener("click", () => {
      const r = btn.dataset.room || "lobby";
      if ($("roomInput")) $("roomInput").value = r;
      $("btnJoin")?.click();
    });
  });

  $("btnSend")?.addEventListener("click", () => {
    const inp = $("msg");
    const text = inp?.value || "";
    if (inp) inp.value = "";
    sendChat(text);
  });

  $("msg")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      $("btnSend")?.click();
    }
  });

  $("btnClearLocal")?.addEventListener("click", () => {
    clearChat();
    showToast("Cleared");
  });

  $("btnRoomInfo")?.addEventListener("click", () => openRoomInfo());
  $("btnTrending")?.addEventListener("click", () => openTrending());

  $("btnEmoji")?.addEventListener("click", () => uiComingSoon("Emoji"));
  $("btnAttach")?.addEventListener("click", () => uiComingSoon("Attach"));
}

function bindProfileModal() {
  // Profile modal tabs
  const modal = $("modalProfile");
  if (modal) {
    modal.querySelectorAll(".tabs .tabBtn").forEach((b) => {
      b.addEventListener("click", () => setProfileTab(b.dataset.tab));
    });
  }

  $("btnSaveProfile")?.addEventListener("click", () => saveProfile().catch(handleErr));
  $("btnChangePw")?.addEventListener("click", () => changeMyPassword().catch(handleErr));

  // Update2 placeholders
  $("btnSaveStatus")?.addEventListener("click", () => uiComingSoon("Status speichern"));
  $("btnSavePrivacy")?.addEventListener("click", () => uiComingSoon("Privacy speichern"));

  // Delete account placeholder (endpoint kommt später)
  $("btnDeleteAccount")?.addEventListener("click", () => {
    showToast("Account löschen: kommt gleich (Update 1 server)", 2600);
  });
}

function bindSettingsModal() {
  const modal = $("modalSettings");
  if (modal) {
    modal.querySelectorAll(".tabs .tabBtn").forEach((b) => {
      b.addEventListener("click", () => setSettingsTab(b.dataset.tab));
    });
  }

  $("btnSaveBg")?.addEventListener("click", () => applyBg());
  $("btnJoinWithPw")?.addEventListener("click", () => uiComingSoon("Join mit Passwort"));
  $("btnSaveAutomod")?.addEventListener("click", () => uiComingSoon("Automod Save"));
}

function bindSearchAndUserCard() {
  $("btnSearchUser")?.addEventListener("click", () => searchProfile().catch(handleErr));
  $("searchUser")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") $("btnSearchUser")?.click();
  });

  $("btnOpenUserCard")?.addEventListener("click", () => openUserCardFromLastSearch().catch(handleErr));

  // User card buttons (Update 2/1 placeholders)
  $("btnUcDM")?.addEventListener("click", () => {
    activeDmUser = $("ucName")?.textContent?.trim() || null;
    showToast(activeDmUser ? `DM: ${activeDmUser}` : "DM");
    openDMs();
  });
  $("btnUcFriend")?.addEventListener("click", () => uiComingSoon("Add Friend"));
  $("btnUcBlock")?.addEventListener("click", () => uiComingSoon("Block"));

  $("btnUcMute")?.addEventListener("click", () => uiComingSoon("Mute (use Admin tab mod)"));
  $("btnUcBan")?.addEventListener("click", () => uiComingSoon("Ban (use Admin tab mod)"));
  $("btnUcKick")?.addEventListener("click", () => uiComingSoon("Kick (use Admin tab mod)"));
  $("btnUcForce")?.addEventListener("click", () => uiComingSoon("Force room (use Admin tab mod)"));
}

function bindFriendsModal() {
  const modal = $("modalFriends");
  if (modal) {
    modal.querySelectorAll(".tabs .tabBtn").forEach((b) => {
      b.addEventListener("click", () => setFriendsTab(b.dataset.tab));
    });
  }

  $("btnAddFriend")?.addEventListener("click", () => uiComingSoon("Add Friend"));
}

function bindDMsModal() {
  $("btnDmRefresh")?.addEventListener("click", () => uiComingSoon("DM refresh"));
  $("btnDmSend")?.addEventListener("click", () => uiComingSoon("DM send"));
}

function bindRoomQuickCreate() {
  $("btnCreateRoomQuick")?.addEventListener("click", () => uiComingSoon("Create room"));
  $("btnRefreshOnline")?.addEventListener("click", () => uiComingSoon("Online refresh"));
}

function bindAdminModal() {
  const modal = $("modalAdmin");
  if (modal) {
    modal.querySelectorAll(".tabs .tabBtn").forEach((b) => {
      b.addEventListener("click", () => setAdminTab(b.dataset.tab));
    });
  }

  $("btnOpenUnlock")?.addEventListener("click", () => modalOpen("modalUnlock"));
  $("btnDoUnlock")?.addEventListener("click", () => adminUnlock().catch(handleErr));
  $("btnAdminLock")?.addEventListener("click", () => adminLock().catch(handleErr));

  $("btnDoSetup")?.addEventListener("click", () => adminSetup().catch(handleErr));

  $("btnAdmDo")?.addEventListener("click", () => adminPunish().catch(handleErr));
  $("btnAdmForceRoom")?.addEventListener("click", () => adminForceRoom().catch(handleErr));
  $("btnAdmChangePw")?.addEventListener("click", () => adminChangeUserPassword().catch(handleErr));
  $("btnAnnSend")?.addEventListener("click", () => adminAnnounce().catch(handleErr));

  // Tabs with no endpoints yet
  $("btnAdmLoadUsers")?.addEventListener("click", () => uiComingSoon("Admin Users list"));
  $("btnLoadRooms")?.addEventListener("click", () => uiComingSoon("Admin rooms list"));
  $("btnSaveRoom")?.addEventListener("click", () => uiComingSoon("Save room"));
  $("btnLoadLogs")?.addEventListener("click", () => uiComingSoon("Admin logs"));

  $("btnBotSave")?.addEventListener("click", () => uiComingSoon("Save bot"));
  $("btnBotList")?.addEventListener("click", () => uiComingSoon("List bots"));
  $("btnAutomodSave")?.addEventListener("click", () => uiComingSoon("Automod save"));
}

/* =======================
   Boot
======================= */

function bindAll() {
  bindGlobalClose();
  bindAuth();
  bindTopbar();
  bindRoomsAndChat();
  bindProfileModal();
  bindSettingsModal();
  bindSearchAndUserCard();
  bindFriendsModal();
  bindDMsModal();
  bindRoomQuickCreate();
  bindAdminModal();
}

async function boot() {
  bindAll();
  setConn("offline");
  restoreBg();

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
