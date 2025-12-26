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

async function updateSecurityStatus() {
  try {
    const [fails, locked] = await invoke("get_security_status");
    const feedback = document.querySelector("#auth-feedback");
    const input = document.querySelector("#pin-input");
    const btn = document.querySelector("#auth-btn");

    if (locked) {
      feedback.textContent = "DEVICE LOCKED: Too many failed attempts.";
      input.disabled = true;
      btn.disabled = true;
      btn.style.opacity = "0.5";
    } else if (fails > 0) {
      feedback.textContent = `Attempts remaining: ${5 - fails}/5`;
    } else {
      feedback.textContent = "";
    }
  } catch (err) {
    console.error(err);
  }
}

async function unlockVault() {
  const pin = document.querySelector("#pin-input").value;
  if (!pin) return;

  try {
    const key = await invoke("derive_key", { pin });
    // VK_MSG_AUTH_REQ = 4
    const response = await invoke("send_command", { msgType: 4, payload: Array.from(key) });
    const status = new TextDecoder().decode(new Uint8Array(response));

    if (status === "OK") {
      document.querySelector("#login-screen").classList.add("hidden");
      document.querySelector("#app-shell").classList.remove("hidden");
      updateStatus();
    } else {
      await updateSecurityStatus();
    }
  } catch (err) {
    if (err.toString().includes("LOCKED")) {
      await updateSecurityStatus();
    } else {
      alert("Error: " + err);
    }
  }
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
    document.querySelectorAll(".sidebar .nav-item").forEach(i => i.classList.remove("active"));
    e.target.classList.add("active");
  });

  document.querySelector("#nav-totp").addEventListener("click", (e) => {
    dashboardView.style.display = "none";
    totpView.style.display = "block";
    mainTitle.textContent = "Authenticators";
    document.querySelectorAll(".sidebar .nav-item").forEach(i => i.classList.remove("active"));
    e.target.classList.add("active");
    fetchTotp();
  });

  document.querySelector("#auth-btn").addEventListener("click", () => unlockVault());
  document.querySelector("#pin-input").addEventListener("keypress", (e) => {
    if (e.key === "Enter") unlockVault();
  });

  document.querySelector("#ping-btn").addEventListener("click", () => pingHardware());
  document.querySelector("#refresh-btn").addEventListener("click", () => updateStatus());

  document.querySelectorAll(".type-btn").forEach(btn => {
    btn.addEventListener("click", async (e) => {
      const text = e.target.getAttribute("data-text");
      try {
        await invoke("type_text", { text });
      } catch (err) {
        console.error(err);
      }
    });
  });

  // Initial update
  updateStatus();
  updateSecurityStatus();
  startTotpTimer();

  // Poll status every 5 seconds
  setInterval(updateStatus, 5000);
});
