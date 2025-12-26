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

async function renderVault() {
  const vaultList = document.querySelector("#vault-list");
  // Keep the 'Add New' card, but clear others if needed
  // For simplicity, we regenerate all but the add card
  const addCard = document.querySelector("#add-new-card");

  try {
    const names = await invoke("list_vault");

    // Clear existing dynamic cards
    const existingCards = vaultList.querySelectorAll(".vault-card:not(#add-new-card)");
    existingCards.forEach(c => c.remove());

    names.forEach(name => {
      const card = document.createElement("div");
      card.className = "vault-card";
      card.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 16px;">
          <div class="card-icon" style="margin-bottom: 0;">${name[0].toUpperCase()}</div>
          <div style="display: flex; gap: 8px;">
            <button class="edit-btn" title="Edit entry" style="background: none; border: none; cursor: pointer; color: var(--text-secondary); opacity: 0.5; transition: opacity 0.2s;">✏️</button>
            <button class="delete-btn" title="Delete entry" style="background: none; border: none; cursor: pointer; color: var(--text-secondary); opacity: 0.5; transition: opacity 0.2s;">🗑️</button>
          </div>
        </div>
        <div class="card-title">${name}</div>
        <div class="card-desc">Hardware Protected</div>
        <button class="btn-micro type-btn" data-text="${name}">⌨️ Type</button>
      `;

      // Edit logic
      card.querySelector(".edit-btn").addEventListener("click", (e) => {
        e.stopPropagation();
        document.querySelector("#add-modal").classList.remove("hidden");
        document.querySelector("#add-name").value = name;
        document.querySelector("#add-name").disabled = true; // Cannot rename yet
        document.querySelector("#save-add-btn").textContent = "Update Entry";
      });

      // Delete logic
      card.querySelector(".delete-btn").addEventListener("click", async (e) => {
        e.stopPropagation();
        if (confirm(`Delete "${name}"? This cannot be undone.`)) {
          try {
            await invoke("delete_vault_entry", { name });
            await renderVault();
          } catch (err) {
            alert("Delete failed: " + err);
          }
        }
      });

      // Auto-type logic
      card.querySelector(".type-btn").addEventListener("click", async (e) => {
        e.stopPropagation();
        try {
          // 1. Fetch real secret from hardware
          const secret = await invoke("get_vault_secret", { name });
          // 2. Send secret to hardware to type it
          await invoke("type_text", { text: secret });
        } catch (err) {
          alert("Typing failed: " + err);
          console.error(err);
        }
      });

      vaultList.insertBefore(card, addCard);
    });
  } catch (err) {
    console.error("Failed to list vault:", err);
  }
}

async function renderFidoKeys() {
  const fidoList = document.querySelector("#fido-list");
  try {
    const response = await invoke("send_command", { msgType: 40, payload: [] });
    const data = new Uint8Array(response);
    fidoList.innerHTML = "";

    let offset = 0;
    while (offset < data.length) {
      const rpLen = data[offset++];
      const rpId = new TextDecoder().decode(data.slice(offset, offset + rpLen));
      offset += rpLen;
      const credIdLen = data[offset++];
      const credId = Array.from(data.slice(offset, offset + credIdLen));
      offset += credIdLen;

      const card = document.createElement("div");
      card.className = "vault-card";
      card.innerHTML = `
        <div class="card-icon">🛡️</div>
        <div class="card-title">${rpId}</div>
        <div class="card-desc">FIDO2 Resident Key</div>
        <button class="btn-micro del-fido-btn" style="background: var(--surface-color); border: 1px solid #ff4444; color: #ff4444; margin-top: 8px;">Delete</button>
      `;
      card.querySelector(".del-fido-btn").onclick = () => deleteFidoKey(credId, rpId);
      fidoList.appendChild(card);
    }
  } catch (err) {
    console.error(err);
  }
}

async function deleteFidoKey(credId, rpId) {
  if (!confirm(`Delete FIDO2 key for ${rpId}?`)) return;
  try {
    await invoke("send_command", { msgType: 42, payload: credId });
    renderFidoKeys();
  } catch (err) {
    alert("Delete failed: " + err);
  }
}

async function saveVaultEntry() {
  const name = document.querySelector("#add-name").value;
  const secret = document.querySelector("#add-secret").value;

  if (!name || !secret) {
    alert("Please fill all fields");
    return;
  }

  try {
    await invoke("add_vault_entry", { name, secret });
    document.querySelector("#add-modal").classList.add("hidden");
    document.querySelector("#add-name").value = "";
    document.querySelector("#add-secret").value = "";
    await renderVault();
  } catch (err) {
    alert("Failed to save: " + err);
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
    document.querySelector("#fido-view").style.display = "none";
    mainTitle.textContent = "My Vault";
    document.querySelectorAll(".sidebar .nav-item").forEach(i => i.classList.remove("active"));
    e.target.classList.add("active");
    renderVault();
  });

  document.querySelector("#nav-totp").addEventListener("click", (e) => {
    dashboardView.style.display = "none";
    totpView.style.display = "block";
    document.querySelector("#fido-view").style.display = "none";
    mainTitle.textContent = "Authenticators";
    document.querySelectorAll(".sidebar .nav-item").forEach(i => i.classList.remove("active"));
    e.target.classList.add("active");
    fetchTotp();
  });

  document.querySelector("#nav-fido").addEventListener("click", (e) => {
    dashboardView.style.display = "none";
    totpView.style.display = "none";
    document.querySelector("#fido-view").style.display = "block";
    mainTitle.textContent = "FIDO2 Resident Keys";
    document.querySelectorAll(".sidebar .nav-item").forEach(i => i.classList.remove("active"));
    e.target.classList.add("active");
    renderFidoKeys();
  });

  document.querySelector("#auth-btn").addEventListener("click", () => unlockVault());
  document.querySelector("#pin-input").addEventListener("keypress", (e) => {
    if (e.key === "Enter") unlockVault();
  });

  document.querySelector("#ping-btn").addEventListener("click", () => pingHardware());
  document.querySelector("#refresh-btn").addEventListener("click", () => updateStatus());

  // Modal handlers
  document.querySelector("#add-new-card").addEventListener("click", () => {
    document.querySelector("#add-modal").classList.remove("hidden");
  });

  document.querySelector("#cancel-add-btn").addEventListener("click", () => {
    closeModal();
  });

  document.querySelector("#save-add-btn").addEventListener("click", () => saveVaultEntry());

  // Initial update
  updateStatus();
  updateSecurityStatus();
  startTotpTimer();

  // Render vault if disconnected but we want to show it when connected
  // For now Just call it
  renderVault();

  // Poll status every 5 seconds
  setInterval(updateStatus, 5000);
});
