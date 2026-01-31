/* Chatly client script – FINAL
   Compatible with:
   - server_final.js (REST send, Socket receive)
   - index.html (current structure)
   - style.css (improved)
*/

(() => {
  'use strict';

  /* =========================
     Helpers
  ========================= */
  const $ = (s, r = document) => r.querySelector(s);

  const esc = (v) =>
    String(v ?? '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#39;');

  async function fetchJSON(url, opts = {}) {
    const res = await fetch(url, {
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      ...opts
    });
    let data = {};
    try {
      data = await res.json();
    } catch {}
    if (!res.ok) {
      throw new Error(data.error || 'Request failed');
    }
    return data;
  }

  function show(el, on) {
    if (!el) return;
    el.hidden = !on;
  }

  /* =========================
     State
  ========================= */
  const state = {
    me: null,
    rooms: [],
    activeRoom: null,
    socket: null
  };

  /* =========================
     Elements
  ========================= */
  const el = {
    authCard: $('#authCard'),
    appCard: $('#appCard'),
    authForm: $('#authForm'),
    tabLogin: $('#tabLogin'),
    tabRegister: $('#tabRegister'),
    btnAuth: $('#btnAuth'),
    authMsg: $('#authMsg'),
    username: $('#username'),
    password: $('#password'),
    agreeRules: $('#agreeRules'),

    btnLogout: $('#btnLogout'),
    btnAdmin: $('#btnAdmin'),

    roomList: $('#roomList'),
    trendingList: $('#trendingList'),

    roomTitle: $('#roomTitle'),
    roomDesc: $('#roomDesc'),
    msgs: $('#msgs'),

    sendForm: $('#sendForm'),
    msgInput: $('#msgInput'),
    msgType: $('#msgType')
  };

  /* =========================
     Auth
  ========================= */
  function setAuthMode(mode) {
    const login = mode === 'login';
    el.tabLogin?.classList.toggle('active', login);
    el.tabRegister?.classList.toggle('active', !login);
    el.btnAuth.textContent = login ? 'Login' : 'Registrieren';
    el.agreeRules.required = !login;
    if (login) el.agreeRules.checked = true;
    el.authForm.dataset.mode = mode;
    el.authMsg.textContent = '';
  }

  async function doAuth() {
    const mode = el.authForm.dataset.mode;
    const username = el.username.value.trim();
    const password = el.password.value;

    if (!username || !password) {
      el.authMsg.textContent = 'Bitte alle Felder ausfüllen.';
      return;
    }

    try {
      const data = await fetchJSON(`/api/auth/${mode}`, {
        method: 'POST',
        body: JSON.stringify({ username, password })
      });
      await setMe(data.user);
    } catch (e) {
      el.authMsg.textContent = e.message;
    }
  }

  async function setMe(me) {
    state.me = me;
    const loggedIn = !!me;

    show(el.authCard, !loggedIn);
    show(el.appCard, loggedIn);
    show(el.btnLogout, loggedIn);
    show(el.btnAdmin, loggedIn && me?.role === 'admin');

    if (!loggedIn) {
      disconnectSocket();
      return;
    }

    await loadRooms();
    connectSocket();
  }

  async function boot() {
    try {
      const data = await fetchJSON('/api/auth/me');
      await setMe(data.user);
    } catch {
      await setMe(null);
    }
  }

  /* =========================
     Rooms
  ========================= */
  async function loadRooms() {
    const data = await fetchJSON('/api/rooms/list');
    state.rooms = data.rooms || [];
    renderRooms();
    if (state.rooms[0]) switchRoom(state.rooms[0].id);
  }

  function renderRooms() {
    el.roomList.innerHTML = '';
    state.rooms.forEach(r => {
      const b = document.createElement('button');
      b.className = 'btn ghost small';
      b.textContent = '#' + r.slug;
      b.onclick = () => switchRoom(r.id);
      el.roomList.appendChild(b);
    });
  }

  async function switchRoom(id) {
    const room = state.rooms.find(r => r.id === id);
    if (!room) return;

    state.activeRoom = room;
    el.roomTitle.textContent = '#' + room.slug;
    el.roomDesc.textContent = room.description || '';
    el.msgs.innerHTML = '';

    await loadHistory();
    joinSocketRoom(room.id);
  }

  /* =========================
     Messages
  ========================= */
  async function loadHistory() {
    const data = await fetchJSON(`/api/messages/history?room_id=${state.activeRoom.id}`);
    data.messages.forEach(addMsg);
    scrollDown();
  }

  function addMsg(m) {
    const div = document.createElement('div');
    div.className = 'msg';
    const user = esc(m.author_name || 'System');
    const body = m.is_deleted
      ? '<em class="muted">gelöscht</em>'
      : esc(m.content);

    div.innerHTML = `<div class="msgHead"><span>${user}</span></div><div class="msgBody">${body}</div>`;
    el.msgs.appendChild(div);
  }

  async function sendMessage() {
    const content = el.msgInput.value.trim();
    if (!content || !state.activeRoom) return;

    const type = state.me.role === 'admin' ? el.msgType.value : 'text';
    el.msgInput.value = '';

    try {
      await fetchJSON('/api/messages/send', {
        method: 'POST',
        body: JSON.stringify({
          room_id: state.activeRoom.id,
          content,
          type
        })
      });
    } catch (e) {
      alert(e.message);
    }
  }

  function scrollDown() {
    el.msgs.scrollTop = el.msgs.scrollHeight;
  }

  /* =========================
     Socket.IO
  ========================= */
  function connectSocket() {
    if (state.socket || !window.io) return;
    state.socket = io({ withCredentials: true });

    state.socket.on('message:new', msg => {
      if (msg.room_id !== state.activeRoom?.id) return;
      addMsg(msg);
      scrollDown();
    });
  }

  function disconnectSocket() {
    try { state.socket?.disconnect(); } catch {}
    state.socket = null;
  }

  function joinSocketRoom(id) {
    state.socket?.emit('room:join', { room_id: id });
  }

  /* =========================
     Bind UI
  ========================= */
  el.tabLogin.onclick = () => setAuthMode('login');
  el.tabRegister.onclick = () => setAuthMode('register');

  el.authForm.onsubmit = e => {
    e.preventDefault();
    doAuth();
  };

  el.btnLogout.onclick = async () => {
    await fetchJSON('/api/auth/logout', { method: 'POST' });
    setMe(null);
  };

  el.sendForm.onsubmit = e => {
    e.preventDefault();
    sendMessage();
  };

  /* =========================
     Start
  ========================= */
  setAuthMode('login');
  boot();

})();