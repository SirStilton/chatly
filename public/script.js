/* Chatly script.js – ADMIN READY (FINAL)
   Compatible with:
   - index_final_admin.html
   - server_final.js
   - Supabase admin schema
*/

(() => {
  'use strict';

  /* ---------- helpers ---------- */
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
    try { data = await res.json(); } catch {}
    if (!res.ok) throw new Error(data.error || 'Request failed');
    return data;
  }

  function show(el, on) {
    if (el) el.hidden = !on;
  }

  /* ---------- state ---------- */
  const state = {
    me: null,
    rooms: [],
    activeRoom: null,
    socket: null
  };

  let el = {};

  /* ---------- auth ---------- */
  function setAuthMode(mode) {
    el.tabLogin.classList.toggle('active', mode === 'login');
    el.tabRegister.classList.toggle('active', mode === 'register');
    el.btnAuth.textContent = mode === 'login' ? 'Login' : 'Registrieren';
    el.authForm.dataset.mode = mode;
    el.agreeRules.required = mode === 'register';
    if (mode === 'login') el.agreeRules.checked = true;
    el.authMsg.textContent = '';
  }

  async function doAuth() {
    const mode = el.authForm.dataset.mode || 'login';
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

    el.mePill.textContent = loggedIn ? me.username : 'nicht angemeldet';

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

  /* ---------- rooms ---------- */
  async function loadRooms() {
    const data = await fetchJSON('/api/rooms/list');
    state.rooms = data.rooms || [];
    el.roomList.innerHTML = '';
    state.rooms.forEach(r => {
      const b = document.createElement('button');
      b.className = 'btn ghost small';
      b.textContent = '#' + r.slug;
      b.onclick = () => switchRoom(r.id);
      el.roomList.appendChild(b);
    });
    if (state.rooms[0]) switchRoom(state.rooms[0].id);
  }

  async function switchRoom(id) {
    const room = state.rooms.find(r => r.id === id);
    if (!room) return;
    state.activeRoom = room;

    el.roomTitle.textContent = '#' + room.slug;
    el.roomDesc.textContent = room.description || '';
    el.msgs.innerHTML = '';

    const data = await fetchJSON(`/api/messages/history?room_id=${room.id}`);
    data.messages.forEach(addMsg);
    joinSocketRoom(room.id);
  }

  /* ---------- messages ---------- */
  function addMsg(m) {
    const d = document.createElement('div');
    d.className = 'msg';
    const body = m.is_deleted
      ? '<em class="muted">gelöscht</em>'
      : esc(m.content);

    d.innerHTML = `<div class="msgHead">
        <span>${esc(m.author_name || 'System')}</span>
      </div>
      <div class="msgBody">${body}</div>`;

    el.msgs.appendChild(d);
    el.msgs.scrollTop = el.msgs.scrollHeight;
  }

  async function sendMessage() {
    const content = el.msgInput.value.trim();
    if (!content || !state.activeRoom) return;

    el.msgInput.value = '';
    const type = state.me.role === 'admin' ? el.msgType.value : 'text';

    await fetchJSON('/api/messages/send', {
      method: 'POST',
      body: JSON.stringify({
        room_id: state.activeRoom.id,
        content,
        type
      })
    });
  }

  /* ---------- socket ---------- */
  function connectSocket() {
    if (state.socket || !window.io) return;
    state.socket = io({ withCredentials: true });
    state.socket.on('message:new', msg => {
      if (msg.room_id === state.activeRoom?.id) addMsg(msg);
    });
  }

  function disconnectSocket() {
    try { state.socket?.disconnect(); } catch {}
    state.socket = null;
  }

  function joinSocketRoom(id) {
    state.socket?.emit('room:join', { room_id: id });
  }

  /* ---------- admin ---------- */
  function openAdmin() {
    show(el.adminOverlay, true);
  }

  function closeAdmin() {
    show(el.adminOverlay, false);
  }

  async function adminAction(kind) {
    const username = el.adminUserSearch.value.trim();
    if (!username) return alert('Username fehlt');

    await fetchJSON(`/api/admin/${kind}`, {
      method: 'POST',
      body: JSON.stringify({ username })
    });

    alert(`${kind} ausgeführt`);
  }

  /* ---------- DOM ---------- */
  document.addEventListener('DOMContentLoaded', () => {
    el = {
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

      mePill: $('#mePill'),
      btnLogout: $('#btnLogout'),
      btnAdmin: $('#btnAdmin'),

      roomList: $('#roomList'),
      roomTitle: $('#roomTitle'),
      roomDesc: $('#roomDesc'),
      msgs: $('#msgs'),

      sendForm: $('#sendForm'),
      msgInput: $('#msgInput'),
      msgType: $('#msgType'),

      adminOverlay: $('#adminOverlay'),
      adminUserSearch: $('#adminUserSearch'),
      btnAdminBan: $('#btnAdminBan'),
      btnAdminMute: $('#btnAdminMute'),
      btnAdminTimeout: $('#btnAdminTimeout'),
      btnAdminClose: $('#btnAdminClose')
    };

    /* auth */
    el.tabLogin.onclick = () => setAuthMode('login');
    el.tabRegister.onclick = () => setAuthMode('register');
    el.authForm.onsubmit = e => { e.preventDefault(); doAuth(); };
    el.btnLogout.onclick = async () => {
      await fetchJSON('/api/auth/logout', { method: 'POST' });
      setMe(null);
    };

    /* chat */
    el.sendForm.onsubmit = e => { e.preventDefault(); sendMessage(); };

    /* admin */
    el.btnAdmin.onclick = openAdmin;
    el.btnAdminClose.onclick = closeAdmin;
    el.btnAdminBan.onclick = () => adminAction('ban');
    el.btnAdminMute.onclick = () => adminAction('mute');
    el.btnAdminTimeout.onclick = () => adminAction('timeout');

    setAuthMode('login');
    boot();
  });
})();