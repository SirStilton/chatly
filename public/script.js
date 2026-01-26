/* Chatly client script
   - Works with the provided index.html IDs
   - Talks to server.js REST endpoints + Socket.IO
   - No new features beyond what UI already exposes; mainly wires everything correctly.
*/
(() => {
  'use strict';

  // ---------------------------
  // helpers
  // ---------------------------
  const $ = (sel, root=document) => root.querySelector(sel);
  const $$ = (sel, root=document) => Array.from(root.querySelectorAll(sel));

  const sleep = (ms) => new Promise(r => setTimeout(r, ms));

  const esc = (s) => String(s ?? '')
    .replaceAll('&','&amp;')
    .replaceAll('<','&lt;')
    .replaceAll('>','&gt;')
    .replaceAll('"','&quot;')
    .replaceAll("'","&#39;");

  function toast(msg, type='info') {
    const el = $('#toast');
    if (!el) { console.log(`[${type}]`, msg); return; }
    el.textContent = msg;
    el.dataset.type = type;
    el.classList.add('show');
    clearTimeout(toast._t);
    toast._t = setTimeout(() => el.classList.remove('show'), 2600);
  }

  async function fetchJSON(url, opts={}) {
    const res = await fetch(url, {
      credentials: 'include',
      headers: { 'Content-Type': 'application/json', ...(opts.headers||{}) },
      ...opts
    });
    let data = null;
    const ct = res.headers.get('content-type') || '';
    if (ct.includes('application/json')) data = await res.json().catch(() => null);
    if (!res.ok) {
      const msg = (data && (data.error || data.message)) ? (data.error || data.message) : `HTTP ${res.status}`;
      const err = new Error(msg);
      err.status = res.status;
      err.data = data;
      throw err;
    }
    return data;
  }

  function show(el, on=true) {
    if (!el) return;
    el.hidden = !on;
    el.classList.toggle('hidden', !on);
  }

  function setBusy(on=true) {
    document.documentElement.classList.toggle('busy', on);
  }

  // ---------------------------
  // state
  // ---------------------------
  const state = {
    me: null,
    rooms: [],
    activeRoom: null,
    socket: null,
    lastHistoryCursor: null,
    loadingHistory: false,
    roomSwitchTimes: [],
    msgSendTimes: [],
  };

  // limits (match your wishes; server also enforces where applicable)
  const LIMITS = {
    USERNAME_MAX: 10,
    PASSWORD_MIN: 6,
    MESSAGE_MAX: 100,
  };

  // ---------------------------
  // elements (IDs from index.html)
  // ---------------------------
  const el = {
    // auth
    authCard: $('#authCard'),
    appCard: $('#appCard'),
    authForm: $('#authForm'),
    tabLogin: $('#tabLogin'),
    tabRegister: $('#tabRegister'),
    btnAuth: $('#btnAuth'),
    authMsg: $('#authMsg'),
    agreeRules: $('#agreeRules'),
    username: $('#username'),
    password: $('#password'),

    // header
    whoami: $('#whoami'),
    btnLogout: $('#btnLogout'),
    btnProfile: $('#btnProfile'),
    btnAdmin: $('#btnAdmin'),

    // room lists
    roomList: $('#roomList'),
    trendingList: $('#trendingList'),
    roomSearch: $('#roomSearch'),
    btnRefreshRooms: $('#btnRefreshRooms'),
    btnCreateRoom: $('#btnCreateRoom'),
    btnJoinRoom: $('#btnJoinRoom'),

    // chat
    roomTitle: $('#roomTitle'),
    roomMeta: $('#roomMeta'),
    msgList: $('#msgList'),
    msgForm: $('#msgForm'),
    msgInput: $('#msgInput'),
    msgType: $('#msgType'),
    btnSend: $('#btnSend'),
    btnLoadMore: $('#btnLoadMore'),

    // overlays
    joinOverlay: $('#joinOverlay'),
    joinForm: $('#joinForm'),
    joinSlug: $('#joinSlug'),
    joinCode: $('#joinCode'),
    joinMsg: $('#joinMsg'),
    btnCloseJoin: $('#btnCloseJoin'),

    createOverlay: $('#createOverlay'),
    createForm: $('#createForm'),
    createTitle: $('#createTitle'),
    createSlug: $('#createSlug'),
    createDesc: $('#createDesc'),
    createPrivate: $('#createPrivate'),
    createAdminOnly: $('#createAdminOnly'),
    createMsg: $('#createMsg'),
    btnCloseCreate: $('#btnCloseCreate'),

    profileOverlay: $('#profileOverlay'),
    profileForm: $('#profileForm'),
    profUsername: $('#profUsername'),
    profBio: $('#profBio'),
    profAvatar: $('#profAvatar'),
    profOldPass: $('#profOldPass'),
    profNewPass: $('#profNewPass'),
    profMsg: $('#profMsg'),
    btnDeleteAccount: $('#btnDeleteAccount'),
    btnCloseProfile: $('#btnCloseProfile'),

    adminOverlay: $('#adminOverlay'),
    adminTabs: $$('#adminOverlay [data-tab]'),
    adminViews: $$('#adminOverlay [data-view]'),
    btnCloseAdmin: $('#btnCloseAdmin'),

    // admin: users
    admUsersBody: $('#admUsersBody'),
    admRefreshUsers: $('#admRefreshUsers'),
    admUserSearch: $('#admUserSearch'),

    // admin: rooms
    admRoomsBody: $('#admRoomsBody'),
    admRefreshRooms: $('#admRefreshRooms'),

    // admin: system message
    admSysForm: $('#admSysForm'),
    admSysRoom: $('#admSysRoom'),
    admSysType: $('#admSysType'),
    admSysContent: $('#admSysContent'),
    admSysMsg: $('#admSysMsg'),

    // admin: logs
    admLogsBody: $('#admLogsBody'),
    admRefreshLogs: $('#admRefreshLogs'),

    // admin: bots
    admBotsBody: $('#admBotsBody'),
    admRefreshBots: $('#admRefreshBots'),

    // misc
    hamburger: $('#hamburger'),
    sidebar: $('#sidebar'),
    backdrop: $('#backdrop'),
  };

  // ---------------------------
  // UI binding (safe)
  // ---------------------------
  function bindUI() {
    // auth mode tabs
    el.tabLogin?.addEventListener('click', () => setAuthMode('login'));
    el.tabRegister?.addEventListener('click', () => setAuthMode('register'));

    el.authForm?.addEventListener('submit', async (e) => {
      e.preventDefault();
      await doAuth();
    });

    el.btnLogout?.addEventListener('click', async () => {
      try { await fetchJSON('/api/auth/logout', { method: 'POST', body: '{}' }); } catch {}
      await setMe(null);
      toast('Abgemeldet.', 'ok');
    });

    el.btnProfile?.addEventListener('click', () => openProfile());
    el.btnAdmin?.addEventListener('click', () => openAdmin());

    el.btnRefreshRooms?.addEventListener('click', () => refreshRooms(true));
    el.roomSearch?.addEventListener('input', () => renderRooms());

    el.btnCreateRoom?.addEventListener('click', () => openCreate());
    el.btnJoinRoom?.addEventListener('click', () => openJoin());

    el.btnCloseJoin?.addEventListener('click', () => show(el.joinOverlay, false));
    el.btnCloseCreate?.addEventListener('click', () => show(el.createOverlay, false));
    el.btnCloseProfile?.addEventListener('click', () => show(el.profileOverlay, false));
    el.btnCloseAdmin?.addEventListener('click', () => show(el.adminOverlay, false));

    el.joinForm?.addEventListener('submit', async (e) => {
      e.preventDefault();
      await joinRoomBySlug();
    });

    el.createForm?.addEventListener('submit', async (e) => {
      e.preventDefault();
      await createRoom();
    });

    el.profileForm?.addEventListener('submit', async (e) => {
      e.preventDefault();
      await saveProfile();
    });

    el.btnDeleteAccount?.addEventListener('click', async () => {
      if (!confirm('Account wirklich löschen? Das kann man nicht rückgängig machen.')) return;
      try {
        setBusy(true);
        await fetchJSON('/api/profile/delete', { method: 'POST', body: '{}' });
        await setMe(null);
        toast('Account gelöscht.', 'ok');
      } catch (err) {
        toast(err.message || 'Fehler', 'err');
      } finally {
        setBusy(false);
      }
    });

    el.msgForm?.addEventListener('submit', async (e) => {
      e.preventDefault();
      await sendMessage();
    });

    el.btnLoadMore?.addEventListener('click', async () => {
      await loadHistory({ older: true });
    });

    // admin tabs
    el.adminTabs.forEach(btn => {
      btn.addEventListener('click', () => {
        el.adminTabs.forEach(b => b.classList.toggle('active', b===btn));
        const tab = btn.dataset.tab;
        el.adminViews.forEach(v => show(v, v.dataset.view === tab));
      });
    });

    el.admRefreshUsers?.addEventListener('click', () => adminLoadUsers());
    el.admUserSearch?.addEventListener('input', () => adminRenderUsers());

    el.admRefreshRooms?.addEventListener('click', () => adminLoadRooms());
    el.admRefreshLogs?.addEventListener('click', () => adminLoadLogs());
    el.admRefreshBots?.addEventListener('click', () => adminLoadBots());

    el.admSysForm?.addEventListener('submit', async (e) => {
      e.preventDefault();
      await adminSendSystem();
    });

    // mobile sidebar
    el.hamburger?.addEventListener('click', () => toggleSidebar(true));
    el.backdrop?.addEventListener('click', () => toggleSidebar(false));
    window.addEventListener('resize', () => {
      if (window.innerWidth >= 900) toggleSidebar(false, true);
    });

    // disable system/bot types for non-admin
    el.msgType?.addEventListener('change', () => {
      if (!state.me) return;
      if (state.me.role !== 'admin' && el.msgType.value !== 'text') {
        el.msgType.value = 'text';
        toast('System/Bot nur für Admins.', 'warn');
      }
    });
  }

  function toggleSidebar(open, force=false) {
    if (!el.sidebar) return;
    el.sidebar.classList.toggle('open', open);
    if (el.backdrop) show(el.backdrop, open);
    if (!force && open) el.sidebar.focus?.();
  }

  function setAuthMode(mode) {
    const isLogin = mode === 'login';
    el.tabLogin?.classList.toggle('active', isLogin);
    el.tabRegister?.classList.toggle('active', !isLogin);
    if (el.btnAuth) el.btnAuth.textContent = isLogin ? 'Login' : 'Registrieren';
    if (el.agreeRules) {
      // rules checkbox only needed for register
      el.agreeRules.closest('.check')?.classList.toggle('dim', isLogin);
      el.agreeRules.required = !isLogin;
      if (isLogin) el.agreeRules.checked = true; // don't block login
      else el.agreeRules.checked = false;
    }
    el.authMsg && (el.authMsg.textContent = '');
    el.authForm && (el.authForm.dataset.mode = mode);
  }

  // ---------------------------
  // auth
  // ---------------------------
  async function doAuth() {
    const mode = el.authForm?.dataset.mode || 'login';
    const username = (el.username?.value || '').trim();
    const password = el.password?.value || '';

    // client validation
    if (username.length < 1 || username.length > LIMITS.USERNAME_MAX) {
      return setAuthMsg(`Username: 1–${LIMITS.USERNAME_MAX} Zeichen.`);
    }
    if (password.length < LIMITS.PASSWORD_MIN) {
      return setAuthMsg(`Passwort: mind. ${LIMITS.PASSWORD_MIN} Zeichen.`);
    }
    if (mode === 'register' && el.agreeRules && !el.agreeRules.checked) {
      return setAuthMsg('Bitte Regeln akzeptieren.');
    }

    try {
      setBusy(true);
      const url = mode === 'register' ? '/api/auth/register' : '/api/auth/login';
      const data = await fetchJSON(url, {
        method: 'POST',
        body: JSON.stringify({ username, password })
      });
      await setMe(data.user || data.me || data);
      toast(mode === 'register' ? 'Registriert ✅' : 'Eingeloggt ✅', 'ok');
    } catch (err) {
      setAuthMsg(err.message || 'Fehler');
    } finally {
      setBusy(false);
    }
  }

  function setAuthMsg(t) {
    if (el.authMsg) el.authMsg.textContent = t;
    toast(t, 'warn');
  }

  async function setMe(me) {
    state.me = me;
    const loggedIn = !!me;

    show(el.authCard, !loggedIn);
    show(el.appCard, loggedIn);

    if (el.whoami) el.whoami.textContent = loggedIn ? `@${me.username} (${me.role})` : 'nicht angemeldet';

    // admin button
    show(el.btnAdmin, loggedIn && me.role === 'admin');

    // message type options
    if (el.msgType) {
      // keep the select but disable non-admin options
      $$('#msgType option').forEach(opt => {
        if (opt.value === 'text') return;
        opt.disabled = !(loggedIn && me.role === 'admin');
      });
      el.msgType.value = 'text';
    }

    // reset state + socket
    if (!loggedIn) {
      disconnectSocket();
      state.rooms = [];
      state.activeRoom = null;
      renderRooms();
      renderMessages([]);
      return;
    }

    await refreshRooms(true);
    await connectSocket();
  }

  async function bootMe() {
    try {
      const data = await fetchJSON('/api/auth/me', { method: 'GET' });
      await setMe(data.user || data.me || data);
    } catch {
      await setMe(null);
    }
  }

  // ---------------------------
  // rooms
  // ---------------------------
  async function refreshRooms(first=false) {
    if (!state.me) return;
    try {
      setBusy(true);
      const [list, trending] = await Promise.all([
        fetchJSON('/api/rooms/list', { method: 'GET' }).catch(() => ({ rooms: [] })),
        fetchJSON('/api/rooms/trending', { method: 'GET' }).catch(() => ({ rooms: [] })),
      ]);
      state.rooms = list.rooms || [];
      renderRooms(trending.rooms || []);
      // auto join first room if none
      if (!state.activeRoom) {
        const initial = state.rooms[0] || null;
        if (initial) await switchRoom(initial.id);
      } else if (first) {
        // ensure active still exists
        const still = state.rooms.find(r => r.id === state.activeRoom.id);
        if (!still && state.rooms[0]) await switchRoom(state.rooms[0].id);
      }
    } catch (err) {
      toast(err.message || 'Räume laden fehlgeschlagen', 'err');
    } finally {
      setBusy(false);
    }
  }

  function renderRooms(trending=[]) {
    const q = (el.roomSearch?.value || '').trim().toLowerCase();

    const filtered = state.rooms.filter(r => {
      if (!q) return true;
      return String(r.slug||'').toLowerCase().includes(q) ||
             String(r.title||'').toLowerCase().includes(q) ||
             String(r.description||'').toLowerCase().includes(q);
    });

    // main list
    if (el.roomList) {
      el.roomList.innerHTML = '';
      if (!filtered.length) {
        const li = document.createElement('li');
        li.className = 'muted';
        li.textContent = 'Keine Räume gefunden.';
        el.roomList.appendChild(li);
      } else {
        filtered.forEach(r => {
          const li = document.createElement('li');
          li.className = 'roomItem' + (state.activeRoom?.id === r.id ? ' active' : '');
          li.innerHTML = `
            <button class="roomBtn" type="button" data-room-id="${r.id}">
              <span class="tag">#${esc(r.slug)}</span>
              <span class="title">${esc(r.title)}</span>
              ${r.admin_only ? '<span class="pill admin">ADMIN</span>' : ''}
              ${r.visibility === 'private' ? '<span class="pill">privat</span>' : ''}
            </button>
          `;
          li.querySelector('button')?.addEventListener('click', () => switchRoom(r.id));
          el.roomList.appendChild(li);
        });
      }
    }

    // trending
    if (el.trendingList) {
      el.trendingList.innerHTML = '';
      const list = (trending && trending.length) ? trending : [];
      if (!list.length) {
        el.trendingList.innerHTML = `<li class="muted">Noch nichts trending.</li>`;
      } else {
        list.slice(0, 10).forEach(r => {
          const li = document.createElement('li');
          li.className = 'roomItem';
          li.innerHTML = `
            <button class="roomBtn" type="button" data-room-id="${r.id}">
              <span class="tag">#${esc(r.slug)}</span>
              <span class="title">${esc(r.title)}</span>
            </button>
          `;
          li.querySelector('button')?.addEventListener('click', () => switchRoom(r.id));
          el.trendingList.appendChild(li);
        });
      }
    }

    // admin room select
    if (el.admSysRoom) {
      el.admSysRoom.innerHTML = '';
      state.rooms.forEach(r => {
        const opt = document.createElement('option');
        opt.value = String(r.id);
        opt.textContent = `#${r.slug} — ${r.title}`;
        el.admSysRoom.appendChild(opt);
      });
      if (state.activeRoom) el.admSysRoom.value = String(state.activeRoom.id);
    }
  }

  async function switchRoom(roomId) {
    if (!state.me) return;

    const room = state.rooms.find(r => r.id === roomId);
    if (!room) { toast('Raum nicht gefunden', 'warn'); return; }

    // small client-side anti-spam
    const now = Date.now();
    state.roomSwitchTimes = state.roomSwitchTimes.filter(t => now - t < 10_000);
    state.roomSwitchTimes.push(now);

    try {
      setBusy(true);

      // Join via slug (server expects slug + optional join_code)
      const data = await fetchJSON('/api/rooms/join', {
        method: 'POST',
        body: JSON.stringify({ slug: room.slug, join_code: null })
      });

      state.activeRoom = data.room || data;
      renderRooms();
      await joinSocketRoom(state.activeRoom.id);

      // load history fresh
      state.lastHistoryCursor = null;
      el.msgList && (el.msgList.innerHTML = '');
      await loadHistory({ older: false });

      // UI header
      if (el.roomTitle) el.roomTitle.textContent = `#${state.activeRoom.slug} — ${state.activeRoom.title}`;
      if (el.roomMeta) el.roomMeta.textContent = state.activeRoom.description || '';

      toggleSidebar(false, true);
    } catch (err) {
      toast(err.message || 'Raum beitreten fehlgeschlagen', 'err');
    } finally {
      setBusy(false);
    }
  }


  async function joinRoomBySlug() {
    const slug = (el.joinSlug?.value || '').trim().toLowerCase();
    const code = (el.joinCode?.value || '').trim();
    if (!slug) { el.joinMsg && (el.joinMsg.textContent = 'Slug fehlt.'); return; }

    try {
      setBusy(true);
      const data = await fetchJSON('/api/rooms/join', {
        method: 'POST',
        body: JSON.stringify({ slug, join_code: code || null })
      });
      show(el.joinOverlay, false);
      // refresh rooms list because you might now have access
      await refreshRooms(true);
      // go to the room
      const rid = (data.room && data.room.id) ? data.room.id : data.id;
      if (rid) await switchRoom(rid);
      toast('Beigetreten ✅', 'ok');
    } catch (err) {
      if (el.joinMsg) el.joinMsg.textContent = err.message || 'Fehler';
      toast(err.message || 'Fehler', 'err');
    } finally {
      setBusy(false);
    }
  }

  async function createRoom() {
    const title = (el.createTitle?.value || '').trim();
    const slug = (el.createSlug?.value || '').trim().toLowerCase();
    const description = (el.createDesc?.value || '').trim();
    const visibility = el.createPrivate?.checked ? 'private' : 'public';
    const admin_only = !!el.createAdminOnly?.checked;

    if (!title) {
      el.createMsg && (el.createMsg.textContent = 'Titel ist Pflicht.');
      return;
    }

    try {
      setBusy(true);
      const data = await fetchJSON('/api/rooms/create', {
        method: 'POST',
        body: JSON.stringify({ title, description, visibility, admin_only })
      });
      show(el.createOverlay, false);
      el.createForm?.reset();
      await refreshRooms(true);
      const rid = (data.room && data.room.id) ? data.room.id : data.id;
      if (rid) await switchRoom(rid);
      toast('Raum erstellt ✅', 'ok');
    } catch (err) {
      el.createMsg && (el.createMsg.textContent = err.message || 'Fehler');
      toast(err.message || 'Fehler', 'err');
    } finally {
      setBusy(false);
    }
  }

  function openJoin() {
    if (!state.me) return;
    el.joinMsg && (el.joinMsg.textContent = '');
    show(el.joinOverlay, true);
    el.joinSlug?.focus();
  }

  function openCreate() {
    if (!state.me) return;
    el.createMsg && (el.createMsg.textContent = '');
    // non-admin can't create admin-only rooms
    if (state.me.role !== 'admin' && el.createAdminOnly) {
      el.createAdminOnly.checked = false;
      el.createAdminOnly.disabled = true;
    } else if (el.createAdminOnly) {
      el.createAdminOnly.disabled = false;
    }
    show(el.createOverlay, true);
    el.createTitle?.focus();
  }

  // ---------------------------
  // messages
  // ---------------------------
  async function loadHistory({ older }) {
    if (!state.me || !state.activeRoom || state.loadingHistory) return;
    state.loadingHistory = true;
    try {
      const url = new URL('/api/messages/history', window.location.origin);
      url.searchParams.set('room_id', String(state.activeRoom.id));
      if (older && state.lastHistoryCursor) url.searchParams.set('before', String(state.lastHistoryCursor));
      const data = await fetchJSON(url.pathname + url.search, { method: 'GET' });
      const msgs = data.messages || [];
      state.lastHistoryCursor = data.next_cursor || null;

      if (older) {
        prependMessages(msgs);
      } else {
        renderMessages(msgs);
      }

      show(el.btnLoadMore, !!state.lastHistoryCursor);
    } catch (err) {
      toast(err.message || 'History laden fehlgeschlagen', 'err');
    } finally {
      state.loadingHistory = false;
    }
  }

  function renderMessages(msgs) {
    if (!el.msgList) return;
    el.msgList.innerHTML = '';
    msgs.forEach(m => el.msgList.appendChild(renderMsg(m)));
    scrollToBottom();
  }

  function prependMessages(msgs) {
    if (!el.msgList || !msgs.length) return;
    const atTop = el.msgList.scrollTop < 10;
    const first = el.msgList.firstChild;
    msgs.forEach(m => {
      el.msgList.insertBefore(renderMsg(m), first);
    });
    if (!atTop) el.msgList.scrollTop = 40; // small nudge to avoid jump
  }

  function appendMessage(m) {
    if (!el.msgList) return;
    el.msgList.appendChild(renderMsg(m));
    // only autoscroll if you're near bottom
    const nearBottom = (el.msgList.scrollHeight - el.msgList.scrollTop - el.msgList.clientHeight) < 120;
    if (nearBottom) scrollToBottom();
  }

  function scrollToBottom() {
    if (!el.msgList) return;
    el.msgList.scrollTop = el.msgList.scrollHeight;
  }

  function canDeleteMsg(m) {
    if (!state.me) return false;
    const authorId = m.author_id ?? m.authorId ?? null;
    return state.me.role === 'admin' || (authorId && state.me.id === authorId);
  }

  function renderMsg(m) {
    const li = document.createElement('div');
    li.className = 'msg';

    const type = String(m.type || 'text');
    li.dataset.type = type;

    const author = m.author_name || m.author || 'System';
    const ts = m.created_at ? new Date(m.created_at).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'}) : '';
    const deleted = !!m.is_deleted;

    const content = deleted ? '<em class="muted">Nachricht gelöscht</em>' : esc(m.content);

    li.innerHTML = `
      <div class="msgTop">
        <span class="msgAuthor">${esc(author)}</span>
        <span class="msgMeta">${esc(ts)}${type !== 'text' ? ` · ${esc(type)}` : ''}</span>
        <span class="msgActions"></span>
      </div>
      <div class="msgBody">${content}</div>
    `;

    const act = li.querySelector('.msgActions');
    if (act && canDeleteMsg(m) && !deleted) {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'btn tiny danger';
      btn.textContent = 'Löschen';
      btn.addEventListener('click', () => deleteMessage(m.id));
      act.appendChild(btn);
    }
    return li;
  }

  async function sendMessage() {
    if (!state.me || !state.activeRoom) return;

    const content = (el.msgInput?.value || '').trim();
    if (!content) return;

    if (content.length > LIMITS.MESSAGE_MAX) {
      toast(`Max. ${LIMITS.MESSAGE_MAX} Zeichen.`, 'warn');
      return;
    }

    let type = el.msgType?.value || 'text';
    if (state.me.role !== 'admin') type = 'text';

    // anti-spam client side (server has automod too)
    const now = Date.now();
    state.msgSendTimes = state.msgSendTimes.filter(t => now - t < 10_000);
    state.msgSendTimes.push(now);

    try {
      el.msgInput && (el.msgInput.value = '');
      await sendSocketMessage({ room_id: state.activeRoom.id, type, content });
    } catch (err) {
      toast(err.message || 'Senden fehlgeschlagen', 'err');
    }
  }

  async function deleteMessage(messageId) {
    try {
      await fetchJSON('/api/messages/delete', {
        method: 'POST',
        body: JSON.stringify({ message_id: messageId })
      });
      // server will broadcast via socket; but if not, refresh small
      toast('Gelöscht.', 'ok');
    } catch (err) {
      toast(err.message || 'Löschen fehlgeschlagen', 'err');
    }
  }

  // ---------------------------
  // socket.io
  // ---------------------------
  function connectSocket() {
    if (!window.io) {
      toast('Socket.IO fehlt. Prüfe <script src="/socket.io/socket.io.js">', 'err');
      return;
    }
    if (state.socket) return;

    state.socket = window.io({
      withCredentials: true,
      transports: ['websocket', 'polling'],
    });

    state.socket.on('connect', () => {
      // join active room if present
      if (state.activeRoom) joinSocketRoom(state.activeRoom.id);
    });

    state.socket.on('disconnect', () => {
      // silent
    });

    state.socket.on('message:new', (m) => {
      // ignore other rooms
      if (!state.activeRoom || m.room_id !== state.activeRoom.id) return;
      appendMessage(m);
    });

    state.socket.on('message:deleted', (payload) => {
      // simplest: reload history for current room
      if (!state.activeRoom || payload.room_id !== state.activeRoom.id) return;
      // small refresh
      loadHistory({ older: false });
    });

    state.socket.on('room:updated', () => refreshRooms(false));
    state.socket.on('punishment', (p) => {
      if (p && p.kind) toast(`Moderation: ${p.kind}`, 'warn');
    });
  }

  function disconnectSocket() {
    if (state.socket) {
      try { state.socket.disconnect(); } catch {}
      state.socket = null;
    }
  }

  function joinSocketRoom(roomId) {
    if (!state.socket || !state.socket.connected) return;
    state.socket.emit('room:join', { room_id: roomId });
  }

  function sendSocketMessage({ room_id, type, content }) {
    return new Promise((resolve, reject) => {
      if (!state.socket || !state.socket.connected) {
        return reject(new Error('Socket nicht verbunden'));
      }
      state.socket.emit('message:send', { room_id, type, content }, (ack) => {
        if (!ack || !ack.ok) return reject(new Error((ack && ack.error) || 'Senden fehlgeschlagen'));
        resolve(ack);
      });
    });
  }

  // ---------------------------
  // profile
  // ---------------------------
  function openProfile() {
    if (!state.me) return;
    el.profMsg && (el.profMsg.textContent = '');
    if (el.profUsername) el.profUsername.value = state.me.username || '';
    if (el.profBio) el.profBio.value = state.me.bio || '';
    if (el.profAvatar) el.profAvatar.value = state.me.avatar_url || '';
    if (el.profOldPass) el.profOldPass.value = '';
    if (el.profNewPass) el.profNewPass.value = '';
    show(el.profileOverlay, true);
  }

  async function saveProfile() {
    if (!state.me) return;
    const newUsername = (el.profUsername?.value || '').trim();
    const bio = (el.profBio?.value || '').trim();
    const avatar_url = (el.profAvatar?.value || '').trim() || null;
    const old_password = el.profOldPass?.value || '';
    const new_password = el.profNewPass?.value || '';

    if (newUsername.length < 1 || newUsername.length > LIMITS.USERNAME_MAX) {
      el.profMsg && (el.profMsg.textContent = `Username: 1–${LIMITS.USERNAME_MAX} Zeichen.`);
      return;
    }
    if (new_password && new_password.length < LIMITS.PASSWORD_MIN) {
      el.profMsg && (el.profMsg.textContent = `Neues Passwort: mind. ${LIMITS.PASSWORD_MIN} Zeichen.`);
      return;
    }

    try {
      setBusy(true);
      const data = await fetchJSON('/api/profile/update', {
        method: 'POST',
        body: JSON.stringify({ username: newUsername, bio, avatar_url, old_password: old_password || null, new_password: new_password || null })
      });
      state.me = data.user || data.me || data;
      if (el.whoami) el.whoami.textContent = `@${state.me.username} (${state.me.role})`;
      show(el.profileOverlay, false);
      toast('Profil gespeichert ✅', 'ok');
    } catch (err) {
      el.profMsg && (el.profMsg.textContent = err.message || 'Fehler');
      toast(err.message || 'Fehler', 'err');
    } finally {
      setBusy(false);
    }
  }

  // ---------------------------
  // admin panel
  // ---------------------------
  function openAdmin() {
    if (!state.me || state.me.role !== 'admin') return;
    show(el.adminOverlay, true);
    // default tab
    const firstTab = el.adminTabs[0];
    firstTab?.click();
    // load all (lazy-ish)
    adminLoadUsers();
    adminLoadRooms();
    adminLoadLogs();
    adminLoadBots();
  }

  let adminCache = { users: [], rooms: [], logs: [], bots: [] };

  async function adminLoadUsers() {
    if (!state.me || state.me.role !== 'admin') return;
    try {
      const data = await fetchJSON('/api/admin/users', { method: 'GET' });
      adminCache.users = data.users || [];
      adminRenderUsers();
    } catch (err) {
      toast(err.message || 'Admin Users laden fehlgeschlagen', 'err');
    }
  }

  function adminRenderUsers() {
    if (!el.admUsersBody) return;
    const q = (el.admUserSearch?.value || '').trim().toLowerCase();
    const list = adminCache.users.filter(u => !q || String(u.username||'').toLowerCase().includes(q));
    el.admUsersBody.innerHTML = '';
    list.forEach(u => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${esc(u.id)}</td>
        <td>@${esc(u.username)}</td>
        <td>${esc(u.role)}</td>
        <td>${esc(u.status || '')}</td>
        <td class="actions"></td>
      `;
      const act = tr.querySelector('.actions');
      if (act) {
        // quick actions
        const mkBtn = (label, cls, fn) => {
          const b = document.createElement('button');
          b.type = 'button';
          b.className = `btn tiny ${cls||''}`.trim();
          b.textContent = label;
          b.addEventListener('click', fn);
          act.appendChild(b);
        };

        mkBtn('Timeout 5m', 'warn', () => adminPunish(u.id, 'timeout', 5));
        mkBtn('Mute 10m', 'warn', () => adminPunish(u.id, 'mute', 10));
        mkBtn('Ban 1d', 'danger', () => adminPunish(u.id, 'ban', 24*60));
        mkBtn('Reset', '', () => adminPunish(u.id, 'reset', 0));
      }
      el.admUsersBody.appendChild(tr);
    });
  }

  async function adminPunish(userId, kind, minutes) {
    if (!state.me || state.me.role !== 'admin') return;
    try {
      const reason = prompt('Grund (optional):') || null;
      await fetchJSON('/api/admin/punish', {
        method: 'POST',
        body: JSON.stringify({ user_id: userId, kind, minutes, reason })
      });
      toast('OK', 'ok');
      await adminLoadUsers();
    } catch (err) {
      toast(err.message || 'Fehler', 'err');
    }
  }

  async function adminLoadRooms() {
    // Server has no /api/admin/rooms yet.
    adminCache.rooms = state.rooms || [];
    adminRenderRooms();
  }

  function adminRenderRooms() {
    if (!el.admRoomsBody) return;
    el.admRoomsBody.innerHTML = '';
    (adminCache.rooms || []).forEach(r => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${esc(r.id)}</td>
        <td>#${esc(r.slug)}</td>
        <td>${esc(r.title)}</td>
        <td>${esc(r.visibility)}</td>
        <td>${r.admin_only ? 'ADMIN' : ''}</td>
        <td class="actions"></td>
      `;
      const act = tr.querySelector('.actions');
      if (act) {
        const kick = document.createElement('button');
        kick.type = 'button';
        kick.className = 'btn tiny danger';
        kick.textContent = 'Kick User…';
        kick.addEventListener('click', async () => {
          const uname = prompt('Username zum Kicken aus diesem Raum:');
          if (!uname) return;
          try {
            await fetchJSON('/api/rooms/kick', { method: 'POST', body: JSON.stringify({ room_id: r.id, username: uname.trim() }) });
            toast('Gekickt.', 'ok');
          } catch (err) {
            toast(err.message || 'Fehler', 'err');
          }
        });
        act.appendChild(kick);
      }
      el.admRoomsBody.appendChild(tr);
    });
  }

  async function adminSendSystem() {
    if (!state.me || state.me.role !== 'admin') return;
    const room_id = Number(el.admSysRoom?.value || 0);
    const type = el.admSysType?.value || 'system';
    const content = (el.admSysContent?.value || '').trim();
    if (!room_id || !content) {
      el.admSysMsg && (el.admSysMsg.textContent = 'Raum + Text fehlen.');
      return;
    }
    if (content.length > LIMITS.MESSAGE_MAX) {
      el.admSysMsg && (el.admSysMsg.textContent = `Max. ${LIMITS.MESSAGE_MAX} Zeichen.`);
      return;
    }
    try {
      setBusy(true);
      await fetchJSON('/api/admin/system-message', {
        method: 'POST',
        body: JSON.stringify({ room_id, type, content })
      });
      el.admSysContent && (el.admSysContent.value = '');
      el.admSysMsg && (el.admSysMsg.textContent = 'Gesendet ✅');
      toast('Systemnachricht gesendet', 'ok');
    } catch (err) {
      el.admSysMsg && (el.admSysMsg.textContent = err.message || 'Fehler');
      toast(err.message || 'Fehler', 'err');
    } finally {
      setBusy(false);
    }
  }

  async function adminLoadLogs() {
    adminCache.logs = [];
    adminRenderLogs();
  }

  function adminRenderLogs() {
    if (!el.admLogsBody) return;
    el.admLogsBody.innerHTML = '';
    if (!adminCache.logs.length) {
      el.admLogsBody.innerHTML = `<tr><td colspan="5" class="muted">Keine Logs (Server-Endpoint fehlt noch).</td></tr>`;
      return;
    }
    adminCache.logs.slice(0, 100).forEach(l => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${esc(l.created_at ? new Date(l.created_at).toLocaleString() : '')}</td>
        <td>${esc(l.action || '')}</td>
        <td>${esc(l.by_admin_name || l.by_admin || '')}</td>
        <td>${esc(l.target_user_name || l.target_user || '')}</td>
        <td>${esc(l.target_room_slug || l.target_room || '')}</td>
      `;
      el.admLogsBody.appendChild(tr);
    });
  }

  async function adminLoadBots() {
    adminCache.bots = [];
    adminRenderBots();
  }

  function adminRenderBots() {
    if (!el.admBotsBody) return;
    el.admBotsBody.innerHTML = '';
    if (!adminCache.bots.length) {
      el.admBotsBody.innerHTML = `<tr><td colspan="5" class="muted">Keine Bots (Server-Endpoint fehlt noch).</td></tr>`;
      return;
    }
    adminCache.bots.forEach(b => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${esc(b.id)}</td>
        <td>${esc(b.name)}</td>
        <td>${esc(b.room_slug || b.room_id || '')}</td>
        <td>${b.enabled ? 'an' : 'aus'}</td>
        <td class="actions"></td>
      `;
      el.admBotsBody.appendChild(tr);
    });
  }

  // ---------------------------
  // boot
  // ---------------------------
  async function boot() {
    bindUI();
    setAuthMode('login');
    await bootMe();
  }

  // start
  boot();
})();