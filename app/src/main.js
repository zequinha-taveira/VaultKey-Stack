const { invoke } = window.__TAURI__.core;

let statusTextEl;
let statusDotEl;

async function updateStatus() {
  try {
    const status = await invoke("get_device_status");
    statusTextEl.textContent = status;

    if (status.includes("Connected")) {
      statusDotEl.classList.add("online");
    } else {
      statusDotEl.classList.remove("online");
    }
  } catch (err) {
    console.error(err);
    statusTextEl.textContent = "Error";
  }
}

async function pingHardware() {
  try {
    // Protocol Ping: Version 1, MsgType 0, Payload "PING"
    const response = await invoke("send_command", {
      msgType: 0,
      payload: Array.from(new TextEncoder().encode("PING"))
    });

    const text = new TextDecoder().decode(new Uint8Array(response));
    alert("Hardware Response: " + text);
  } catch (err) {
    console.error(err);
    alert("Ping Failed: " + err);
  }
}

async function fetchTotp() {
  try {
    const code = await invoke("get_totp");
    document.querySelector("#totp-code").textContent = code;
  } catch (err) {
    console.error(err);
  }
}

function startTotpTimer() {
  const timerEl = document.querySelector("#totp-timer");
  setInterval(() => {
    const now = Math.floor(Date.now() / 1000);
    const remains = 30 - (now % 30);
    timerEl.textContent = remains;
    if (remains === 30) fetchTotp();
  }, 1000);
}

window.addEventListener("DOMContentLoaded", () => {
  statusTextEl = document.querySelector("#status-text");
  statusDotEl = document.querySelector("#status-dot");

  const dashboardView = document.querySelector("#dashboard-view");
  const totpView = document.querySelector("#totp-view");
  const mainTitle = document.querySelector("#main-title");

  document.querySelector("#nav-dashboard").addEventListener("click", (e) => {
    dashboardView.style.display = "block";
    totpView.style.display = "none";
    mainTitle.textContent = "My Vault";
    e.target.parentElement.querySelectorAll(".nav-item").forEach(i => i.classList.remove("active"));
    e.target.classList.add("active");
  });

  document.querySelector("#nav-totp").addEventListener("click", (e) => {
    dashboardView.style.display = "none";
    totpView.style.display = "block";
    mainTitle.textContent = "Authenticators";
    e.target.parentElement.querySelectorAll(".nav-item").forEach(i => i.classList.remove("active"));
    e.target.classList.add("active");
    fetchTotp();
  });

  document.querySelector("#ping-btn").addEventListener("click", () => pingHardware());
  document.querySelector("#refresh-btn").addEventListener("click", () => updateStatus());

  // Initial update
  updateStatus();
  startTotpTimer();
  fetchTotp();

  // Poll status every 5 seconds
  setInterval(updateStatus, 5000);
});
