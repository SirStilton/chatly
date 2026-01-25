
// === Chatly script.js (FIXED for new authForm) ===
const $ = (id) => document.getElementById(id);

const state = { me: null, socket: null, room: null };

async function api(url, opts = {}) {
  const res = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    ...opts,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw data;
  return data;
}

function setLoggedInUI(on) {
  $("authCard").style.display = on ? "none" : "";
  $("appCard").style.display = on ? "" : "none";
  $("btnLogout").style.display = on ? "" : "none";
}

async function handleAuth(e) {
  e.preventDefault();
  const msg = $("authMsg");
  msg.textContent = "";

  const username = $("username").value.trim();
  const password = $("password").value;
  const agree = $("agreeRules").checked;

  if (!agree) {
    msg.textContent = "Bitte akzeptiere die Regeln.";
    return;
  }

  try {
    const r = await api("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
    state.me = r.user;
    $("mePill").textContent = `${state.me.username} (${state.me.role})`;
    if (state.me.role === "admin") $("btnAdmin").style.display = "";
    setLoggedInUI(true);
  } catch (err) {
    msg.textContent = err.error || "Login fehlgeschlagen";
  }
}

function bindUI() {
  const authForm = $("authForm");
  if (authForm) authForm.addEventListener("submit", handleAuth);

  const logout = $("btnLogout");
  if (logout) logout.addEventListener("click", async () => {
    await api("/api/auth/logout", { method: "POST" });
    location.reload();
  });

  const btnAdmin = $("btnAdmin");
  if (btnAdmin) btnAdmin.addEventListener("click", () => {
    $("adminOverlay").style.display = "flex";
  });

  document.querySelectorAll("[data-close]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const id = btn.getAttribute("data-close");
      const el = $(id);
      if (el) el.style.display = "none";
    });
  });
}

async function boot() {
  bindUI();
  try {
    const r = await api("/api/me");
    state.me = r.user;
    $("mePill").textContent = `${state.me.username} (${state.me.role})`;
    if (state.me.role === "admin") $("btnAdmin").style.display = "";
    setLoggedInUI(true);
  } catch {
    setLoggedInUI(false);
  }
}

boot();
