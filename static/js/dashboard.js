async function fetchJSON(url, opts) {
  const res = await fetch(url, opts);
  return res.json();
}

function timeAgo(isoString) {
  return new Date(isoString).toLocaleString();
}

async function loadStats() {
  const stats = await fetchJSON("/api/stats");
  document.getElementById("stat-known").textContent = stats.known_devices;
  document.getElementById("stat-connected").textContent = stats.connected_now;
  document.getElementById("stat-rules").textContent = stats.active_block_rules;
  document.getElementById("stat-blocked").textContent = stats.blocked_requests;
}

async function loadDevices() {
  const devices = await fetchJSON("/api/devices");
  const body = document.getElementById("devices-body");
  body.innerHTML = "";

  if (devices.length === 0) {
    body.innerHTML = '<tr><td colspan="7" class="muted">No devices seen yet</td></tr>';
    return;
  }

  devices.forEach(d => {
    const tr = document.createElement("tr");

    const statusHTML = d.connected
      ? `<span class="status-pill connected"><span class="dot"></span>connected</span>`
      : `<span class="status-pill disconnected"><span class="dot"></span>disconnected</span>`;

    tr.innerHTML = `
      <td>${statusHTML}</td>
      <td>${d.hostname}</td>
      <td class="mono">${d.ip_address}</td>
      <td class="mono">${d.mac_address || "—"}</td>
      <td class="mono">${timeAgo(d.last_seen)}</td>
      <td><button class="device-toggle-btn ${d.is_blocked ? "is-blocked" : "is-allowed"}" data-id="${d.id}">${d.is_blocked ? "Blocked" : "Allowed"}</button></td>
      <td><a href="#" class="history-link" data-id="${d.id}" data-name="${d.hostname}">View history</a></td>
    `;
    body.appendChild(tr);
  });

  document.querySelectorAll(".device-toggle-btn").forEach(btn => {
    btn.onclick = async () => {
      const id = btn.dataset.id;
      const action = btn.classList.contains("is-blocked") ? "unblock" : "block";
      btn.disabled = true;
      await fetchJSON(`/api/devices/${id}/${action}`, { method: "POST" });
      loadDevices();
      loadStats();
      loadAuditLog();
    };
  });

  document.querySelectorAll(".history-link").forEach(link => {
    link.onclick = (e) => {
      e.preventDefault();
      openHistoryModal(link.dataset.id, link.dataset.name);
    };
  });
}

async function loadBlocklist() {
  const entries = await fetchJSON("/api/blocklist");
  const list = document.getElementById("blocklist-items");
  list.innerHTML = "";

  if (entries.length === 0) {
    list.innerHTML = '<li class="muted">No rules yet</li>';
    return;
  }

  entries.forEach(e => {
    const li = document.createElement("li");
    li.innerHTML = `
      <span class="entry-value">${e.value}</span>
      <button data-id="${e.id}" class="remove-btn">remove</button>
    `;
    li.querySelector(".remove-btn").onclick = async () => {
      await fetch(`/api/blocklist/${e.id}`, { method: "DELETE" });
      loadBlocklist();
      loadStats();
      loadAuditLog();
    };
    list.appendChild(li);
  });
}

async function loadAuditLog() {
  const entries = await fetchJSON("/api/audit-log?limit=30");
  const list = document.getElementById("audit-log-items");
  list.innerHTML = "";

  if (entries.length === 0) {
    list.innerHTML = '<li class="muted">No activity yet</li>';
    return;
  }

  entries.forEach(e => {
    const li = document.createElement("li");
    li.className = "audit-item";
    li.innerHTML = `
      <span class="audit-text">${e.actor} — ${e.action}</span>
      <span class="audit-time">${timeAgo(e.timestamp)}</span>
    `;
    list.appendChild(li);
  });
}

// ---- Device history modal ----
async function openHistoryModal(deviceId, hostname) {
  const modal = document.getElementById("history-modal");
  const body = document.getElementById("history-modal-body");
  document.getElementById("history-modal-title").textContent = `${hostname} — history`;
  body.innerHTML = '<tr><td colspan="3" class="muted">loading…</td></tr>';
  modal.style.display = "flex";

  const logs = await fetchJSON(`/api/activity?device_id=${deviceId}&limit=100`);
  body.innerHTML = "";
  if (logs.length === 0) {
    body.innerHTML = '<tr><td colspan="3" class="muted">No activity for this device yet</td></tr>';
    return;
  }
  logs.forEach(log => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="mono">${timeAgo(log.timestamp)}</td>
      <td class="mono">${log.domain}</td>
      <td><span class="badge ${log.status}">${log.status}</span></td>
    `;
    body.appendChild(tr);
  });
}

document.getElementById("history-modal-close").onclick = () => {
  document.getElementById("history-modal").style.display = "none";
};
document.getElementById("history-modal").addEventListener("click", (e) => {
  if (e.target.id === "history-modal") e.target.style.display = "none";
});

// ---- Block a Website form ----
document.getElementById("block-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const valueInput = document.getElementById("block-value");
  const value = valueInput.value.trim();
  if (!value) return;

  await fetchJSON("/api/blocklist", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ value, entry_type: "domain", reason: "" })
  });

  valueInput.value = "";
  loadBlocklist();
  loadStats();
  loadAuditLog();
});

function refreshAll() {
  loadStats();
  loadDevices();
  loadBlocklist();
  loadAuditLog();
}

refreshAll();
setInterval(refreshAll, 4000);
