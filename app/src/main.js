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

window.addEventListener("DOMContentLoaded", () => {
  statusTextEl = document.querySelector("#status-text");
  statusDotEl = document.querySelector("#status-dot");

  document.querySelector("#ping-btn").addEventListener("click", () => pingHardware());
  document.querySelector("#refresh-btn").addEventListener("click", () => updateStatus());

  // Initial update
  updateStatus();
  
  // Poll every 5 seconds
  setInterval(updateStatus, 5000);
});
