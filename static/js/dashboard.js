function escapeHTML(value) {
  return String(value ?? "").replace(/[&<>'"]/g, ch => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;"
  }[ch]));
}

async function fetchJSON(url, opts = {}) {
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content;
  opts.headers = { ...(opts.headers || {}) };
  if (csrf && opts.method && opts.method !== "GET") opts.headers["X-CSRFToken"] = csrf;
  const res = await fetch(url, opts);
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.error || `HTTP ${res.status}`);
  }
  return res.json();
}

function timeAgo(isoString) {
  if (!isoString) return "—";
  return new Date(isoString).toLocaleString();
}

let currentModalDevice = null;

async function loadStats() {
  try {
    const stats = await fetchJSON("/api/stats");
    const elKnown = document.getElementById("stat-known");
    const elConnected = document.getElementById("stat-connected");
    const elRules = document.getElementById("stat-rules");
    if (elKnown) elKnown.textContent = stats.known_devices;
    if (elConnected) elConnected.textContent = stats.connected_now;
    if (elRules) elRules.textContent = stats.active_block_rules;
  } catch (err) {
    console.error("Error loading stats:", err);
  }
}


async function loadDevices() {
  try {
    const devices = await fetchJSON("/api/devices");
    const body = document.getElementById("devices-body");
    body.innerHTML = "";

    if (devices.length === 0) {
      body.innerHTML = '<tr><td colspan="7" class="muted">No devices seen yet</td></tr>';
      return;
    }

    devices.forEach(d => {
      const tr = document.createElement("tr");
      if (d.is_blocked) {
        tr.classList.add("device-blocked-row");
      }

      const statusHTML = d.is_blocked
        ? `<span class="status-pill blocked"><span class="dot"></span>Blocked</span>`
        : d.connected
        ? `<span class="status-pill connected"><span class="dot"></span>Online</span>`
        : `<span class="status-pill disconnected"><span class="dot"></span>Offline</span>`;

      const vpnBadge = d.vpn_detected
        ? `<span class="badge vpn-badge" title="VPN/Proxy detected: ${escapeHTML(d.vpn_type || 'Active')}"><span class="vpn-dot"></span>${escapeHTML(d.vpn_type || 'VPN ACTIVE')}</span>`
        : "";

      tr.innerHTML = `
        <td>${statusHTML}</td>
        <td>
          <div class="device-name-wrap">
            <strong>${escapeHTML(d.hostname)}</strong>
            ${vpnBadge}
          </div>
        </td>
        <td class="mono">${escapeHTML(d.ip_address)}</td>
        <td class="mono">${escapeHTML(d.mac_address || "—")}</td>
        <td class="mono">${escapeHTML(timeAgo(d.last_seen))}</td>
        <td>
          <button class="device-toggle-btn ${d.is_blocked ? "is-blocked" : "is-allowed"}" data-id="${d.id}">
            ${d.is_blocked ? "Blocked" : "Allowed"}
          </button>
        </td>
        <td><a href="#" class="history-link" data-id="${d.id}">View history</a></td>
      `;


      // Attach event listeners
      const toggleBtn = tr.querySelector(".device-toggle-btn");
      toggleBtn.onclick = async () => {
        const isBlocked = toggleBtn.classList.contains("is-blocked");
        const action = isBlocked ? "unblock" : "block";
        toggleBtn.disabled = true;
        toggleBtn.textContent = isBlocked ? "Unblocking..." : "Blocking...";

        try {
          await fetchJSON(`/api/devices/${d.id}/${action}`, { method: "POST" });
          await refreshAll();
          // Update modal device if currently open
          if (currentModalDevice && currentModalDevice.id === d.id) {
            d.is_blocked = !isBlocked;
            updateModalDeviceToggle(d);
          }
        } catch (err) {
          alert(`Failed to ${action} device: ${err.message}`);
          toggleBtn.disabled = false;
          toggleBtn.textContent = isBlocked ? "Blocked" : "Allowed";
        }
      };

      const histLink = tr.querySelector(".history-link");
      histLink.onclick = (e) => {
        e.preventDefault();
        openHistoryModal(d);
      };

      body.appendChild(tr);
    });
  } catch (err) {
    console.error("Error loading devices:", err);
  }
}

async function loadBlocklist() {
  try {
    const entries = await fetchJSON("/api/blocklist");
    const list = document.getElementById("blocklist-items");
    list.innerHTML = "";

    if (entries.length === 0) {
      list.innerHTML = '<li class="muted">No rules yet</li>';
      return;
    }

    entries.forEach(e => {
      const li = document.createElement("li");
      const isDevice = e.entry_type === "device";
      li.innerHTML = `
        <div style="display: flex; align-items: center; gap: 8px; min-width: 0; overflow: hidden;">
          <span class="badge ${escapeHTML(e.entry_type)}">${escapeHTML(e.entry_type)}</span>
          <span class="entry-value" title="${escapeHTML(e.value)}">${escapeHTML(e.value)}</span>
        </div>
        <button data-id="${e.id}" class="remove-btn" title="Unblock ${escapeHTML(e.value)}">${isDevice ? "unblock" : "remove"}</button>
      `;
      li.querySelector(".remove-btn").onclick = async () => {
        try {
          if (isDevice && e.device_id) {
            await fetchJSON(`/api/devices/${e.device_id}/unblock`, { method: "POST" });
          } else {
            await fetchJSON(`/api/blocklist/${e.id}`, { method: "DELETE" });
          }
          refreshAll();
        } catch (err) {
          console.error("Failed to remove rule:", err);
        }
      };
      list.appendChild(li);
    });
  } catch (err) {
    console.error("Error loading blocklist:", err);
  }
}

async function loadMostUsed() {
  try {
    const list = document.getElementById("most-used-items");
    if (!list) return;
    const [items, activeBlocklist] = await Promise.all([
      fetchJSON("/api/most-used"),
      fetchJSON("/api/blocklist")
    ]);
    list.innerHTML = "";

    if (!items || items.length === 0) {
      list.innerHTML = '<li class="muted">No activity yet</li>';
      return;
    }

    const blockedDomainValues = new Set(
      activeBlocklist.filter(b => b.entry_type === "domain").map(b => b.value.toLowerCase())
    );

    function isDomainBlocked(domain) {
      const clean = domain.toLowerCase().replace(/^\.+|\.+$/g, "");
      const parts = clean.split(".");
      for (let i = 0; i < parts.length - 1; i++) {
        const parent = parts.slice(i).join(".");
        if (blockedDomainValues.has(parent)) return true;
      }
      return false;
    }

    items.forEach(item => {
      const isBlocked = isDomainBlocked(item.domain);
      const li = document.createElement("li");
      li.className = "most-used-item";
      li.innerHTML = `
        <div class="most-used-info">
          <span class="most-used-domain" title="${escapeHTML(item.domain)}">${escapeHTML(item.domain)}</span>
        <span class="most-used-hits">${escapeHTML(item.hits)} request${item.hits === 1 ? '' : 's'}</span>
        </div>
        ${isBlocked
          ? `<span class="badge blocked">blocked</span>`
          : `<button class="most-used-block-btn" data-domain="${escapeHTML(item.domain)}">Block</button>`}
      `;

      const btn = li.querySelector(".most-used-block-btn");
      if (btn) {
        btn.onclick = async () => {
          btn.disabled = true;
          btn.textContent = "Blocking...";
          try {
            await fetchJSON("/api/blocklist", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                value: item.domain,
                entry_type: "domain",
                reason: "Blocked from Most Visited list"
              })
            });
            refreshAll();
          } catch (err) {
            alert(`Failed to block ${item.domain}: ${err.message}`);
            btn.disabled = false;
            btn.textContent = "Block";
          }
        };
      }

      list.appendChild(li);
    });
  } catch (err) {
    console.error("Error loading most used:", err);
  }
}

async function loadAuditLog() {
  try {
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
        <span class="audit-text">${escapeHTML(e.actor)} — ${escapeHTML(e.action)}</span>
        <span class="audit-time">${timeAgo(e.timestamp)}</span>
      `;
      list.appendChild(li);
    });
  } catch (err) {
    console.error("Error loading audit log:", err);
  }
}

// ---- Device history modal with domain block and device block ----

function updateModalDeviceToggle(device) {
  const modalToggleBtn = document.getElementById("modal-device-toggle-btn");
  if (!modalToggleBtn || !device) return;

  modalToggleBtn.style.display = "inline-block";
  if (device.is_blocked) {
    modalToggleBtn.className = "modal-action-btn unblock-dev";
    modalToggleBtn.textContent = "Unblock Entire Device";
  } else {
    modalToggleBtn.className = "modal-action-btn block-dev";
    modalToggleBtn.textContent = "Block Entire Device";
  }

  modalToggleBtn.onclick = async () => {
    const action = device.is_blocked ? "unblock" : "block";
    modalToggleBtn.disabled = true;
    modalToggleBtn.textContent = device.is_blocked ? "Unblocking..." : "Blocking...";
    try {
      const updated = await fetchJSON(`/api/devices/${device.id}/${action}`, { method: "POST" });
      currentModalDevice = updated;
      updateModalDeviceToggle(updated);
      refreshAll();
    } catch (err) {
      alert(`Failed to ${action} device: ${err.message}`);
      updateModalDeviceToggle(device);
    } finally {
      modalToggleBtn.disabled = false;
    }
  };
}

async function openHistoryModal(device) {
  stopModalLive();
  currentModalDevice = device;
  const modal = document.getElementById("history-modal");
  const body = document.getElementById("history-modal-body");
  const title = document.getElementById("history-modal-title");
  const subtitle = document.getElementById("history-modal-subtitle");

  title.innerHTML = `${escapeHTML(device.hostname)} — History <span class="live-pill">&#9679; LIVE</span>`;
  subtitle.textContent = `IP: ${device.ip_address} | MAC: ${device.mac_address || "—"}`;
  body.innerHTML = '<tr><td colspan="5" class="muted">loading…</td></tr>';
  modal.style.display = "flex";
  updateModalDeviceToggle(device);

  let seenIds = new Set();
  let activeBlocklist = [];

  async function fetchBlocklist() {
    try { activeBlocklist = await fetchJSON("/api/blocklist"); } catch (_) {}
  }

  function isDomainInBlocklist(domain) {
    const blockedVals = new Set(
      activeBlocklist.filter(b => b.entry_type === "domain").map(b => b.value.toLowerCase())
    );
    const clean = domain.toLowerCase().replace(/^\.+|\.+$/g, "");
    const parts = clean.split(".");
    for (let i = 0; i < parts.length - 1; i++) {
      if (blockedVals.has(parts.slice(i).join("."))) return true;
    }
    return false;
  }

  function makeRow(log, isNew) {
    const isAlreadyBlocked = log.status === "blocked" || isDomainInBlocklist(log.domain);
    const tr = document.createElement("tr");
    if (isNew) tr.classList.add("live-new-row");
    tr.innerHTML = `
      <td class="mono">${timeAgo(log.timestamp)}</td>
      <td><strong>${escapeHTML(log.application || "Other/Unknown")}</strong></td>
      <td class="mono"><strong>${escapeHTML(log.domain)}</strong></td>
      <td><span class="badge ${isAlreadyBlocked ? "blocked" : "allowed"}">${isAlreadyBlocked ? "blocked" : "allowed"}</span></td>
      <td>
        ${isAlreadyBlocked
          ? `<span class="muted">already blocked</span>`
          : `<button class="block-domain-btn" data-domain="${escapeHTML(log.domain)}">Block</button>`}
      </td>
    `;
    const blockBtn = tr.querySelector(".block-domain-btn");
    if (blockBtn) {
      blockBtn.onclick = async () => {
        const domain = blockBtn.dataset.domain;
        blockBtn.disabled = true;
        blockBtn.textContent = "Blocking...";
        try {
          await fetchJSON("/api/blocklist", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ value: domain, entry_type: "domain", reason: `Blocked from ${device.hostname} history` })
          });
          refreshAll();
          await fetchBlocklist();
          // Re-render all rows to update their block status
          openHistoryModal(device);
        } catch (err) {
          alert(`Failed to block ${domain}: ${err.message}`);
          blockBtn.disabled = false;
          blockBtn.textContent = "Block";
        }
      };
    }
    return tr;
  }

  // Initial full load
  try {
    await fetchBlocklist();
    const logs = await fetchJSON(`/api/activity?device_id=${device.id}&limit=100`);
    body.innerHTML = "";
    if (logs.length === 0) {
      body.innerHTML = '<tr><td colspan="5" class="muted">No activity for this device yet</td></tr>';
    } else {
      logs.forEach(log => {
        seenIds.add(log.id);
        body.appendChild(makeRow(log, false));
      });
    }
  } catch (err) {
    body.innerHTML = `<tr><td colspan="5" class="muted error">Failed to load history: ${escapeHTML(err.message)}</td></tr>`;
    return;
  }

  // Live polling: every 3 seconds fetch the latest 20 rows and prepend any new ones
  _modalLiveInterval = setInterval(async () => {
    if (!currentModalDevice || currentModalDevice.id !== device.id) {
      stopModalLive();
      return;
    }
    try {
      await fetchBlocklist();
      const fresh = await fetchJSON(`/api/activity?device_id=${device.id}&limit=20`);
      const newRows = fresh.filter(log => !seenIds.has(log.id));
      if (newRows.length > 0) {
        // Remove placeholder if present
        const placeholder = body.querySelector("td[colspan]");
        if (placeholder) body.innerHTML = "";
        newRows.forEach(log => {
          seenIds.add(log.id);
          const tr = makeRow(log, true);
          body.insertBefore(tr, body.firstChild);
          // Remove the flash class after animation
          setTimeout(() => tr.classList.remove("live-new-row"), 1800);
        });
      }
      // Refresh device block status in header if changed
      const devices = await fetchJSON("/api/devices");
      const updated = devices.find(d => d.id === device.id);
      if (updated && updated.is_blocked !== currentModalDevice.is_blocked) {
        currentModalDevice = updated;
        updateModalDeviceToggle(updated);
      }
    } catch (_) {}
  }, 3000);
}

let _modalLiveInterval = null;

function stopModalLive() {
  if (_modalLiveInterval) {
    clearInterval(_modalLiveInterval);
    _modalLiveInterval = null;
  }
}

document.getElementById("history-modal-close").onclick = () => {
  stopModalLive();
  document.getElementById("history-modal").style.display = "none";
  currentModalDevice = null;
};

document.getElementById("history-modal").addEventListener("click", (e) => {
  if (e.target.id === "history-modal") {
    stopModalLive();
    document.getElementById("history-modal").style.display = "none";
    currentModalDevice = null;
  }
});

// ---- Block a Website / App Form ----
document.getElementById("block-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const valueInput = document.getElementById("block-value");
  const value = valueInput.value.trim();
  if (!value) return;

  const submitBtn = e.target.querySelector("button[type='submit']");
  submitBtn.disabled = true;
  submitBtn.textContent = "Blocking...";

  try {
    await fetchJSON("/api/blocklist", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ value, entry_type: "domain", reason: "Blocked from dashboard form" })
    });
    valueInput.value = "";
    refreshAll();
  } catch (err) {
    alert(`Could not block '${value}': ${err.message}`);
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = "Block";
  }
});

function refreshAll() {
  loadStats();
  loadDevices();
  loadBlocklist();
  loadMostUsed();
  loadAuditLog();
}

// Initial load
refreshAll();

// Auto-refresh every 4 seconds
setInterval(refreshAll, 4000);

// ---- Profile Dropdown Interactions ----
const profileBtn = document.getElementById("profile-btn");
const profileDropdown = document.getElementById("profile-dropdown");
const profileRefreshBtn = document.getElementById("profile-refresh-btn");

if (profileBtn && profileDropdown) {
  profileBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    const isHidden = profileDropdown.style.display === "none";
    profileDropdown.style.display = isHidden ? "block" : "none";
    profileBtn.classList.toggle("active", isHidden);
    profileBtn.setAttribute("aria-expanded", isHidden ? "true" : "false");
  });

  document.addEventListener("click", (e) => {
    if (!profileDropdown.contains(e.target) && !profileBtn.contains(e.target)) {
      profileDropdown.style.display = "none";
      profileBtn.classList.remove("active");
      profileBtn.setAttribute("aria-expanded", "false");
    }
  });

  if (profileRefreshBtn) {
    profileRefreshBtn.addEventListener("click", () => {
      refreshAll();
      profileRefreshBtn.innerHTML = `
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg>
        Refreshed!
      `;
      setTimeout(() => {
        profileRefreshBtn.innerHTML = `
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg>
          Refresh Dashboard
        `;
      }, 1200);
    });
  }
}
