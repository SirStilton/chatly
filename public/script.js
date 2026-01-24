const $ = (id) => document.getElementById(id);

let state = {
  me: null,
  ws: null,
  currentRoom: "lobby"
};

// UI Hilfsfunktionen
function showModal(id) {
  $('modalBackdrop').classList.remove('hidden');
  $(id).classList.remove('hidden');
}

function hideModals() {
  document.querySelectorAll('.modal').forEach(m => m.classList.add('hidden'));
  $('modalBackdrop').classList.add('hidden');
}

// Events binden
function bindEvents() {
  // Tabs Login/Register
  $('tabLogin').onclick = () => {
    $('paneLogin').classList.remove('hidden');
    $('paneRegister').classList.add('hidden');
    $('tabLogin').classList.add('active');
    $('tabRegister').classList.remove('active');
  };

  $('tabRegister').onclick = () => {
    $('paneLogin').classList.add('hidden');
    $('paneRegister').classList.remove('hidden');
    $('tabRegister').classList.add('active');
    $('tabLogin').classList.remove('active');
  };

  // Login & Register (Dummys für die Logik)
  $('btnLogin').onclick = () => login();
  $('btnRegister').onclick = () => register();

  // Modal Steuerung
  document.querySelectorAll('[data-close]').forEach(b => b.onclick = hideModals);
  $('btnProfile').onclick = () => showModal('modalProfile');
  
  if($('btnAdmin')) {
    $('btnAdmin').onclick = () => showModal('modalAdmin');
  }

  // Nachricht senden
  $('btnSend').onclick = sendMessage;
  $('msgInput').onkeydown = (e) => {
    if(e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };
}

async function login() {
  console.log("Login Versuch...");
  // Hier deine fetch("/api/login") Logik einfügen
  // Nach Erfolg: $('auth').classList.add('hidden'); $('app').classList.remove('hidden');
}

function sendMessage() {
  const text = $('msgInput').value.trim();
  if(!text) return;
  console.log("Sende:", text);
  // WebSocket Logik hier
  $('msgInput').value = "";
}

async function boot() {
  console.log("Chatly initialisiert...");
  bindEvents();
}

// Start der App
window.addEventListener('DOMContentLoaded', boot);