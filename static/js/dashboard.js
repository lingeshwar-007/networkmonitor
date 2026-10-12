async function fetchJSON(url, opts) {
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

function escapeHtml(v) {
  return String(v == null ? "" : v).replace(/[&<>"']/g, c => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// Show firewall enforcement warnings returned by block/unblock calls.
function showEnforcementWarnings(res) {
  if (res && Array.isArray(res.warnings) && res.warnings.length) {
    alert("Saved, but the firewall reported problems:\n\n- " + res.warnings.join("\n- "));
  }
  loadFirewallStatus();
}

// ---- Firewall health banner: tells you WHY a block is not being enforced ----
async function loadFirewallStatus() {
  const box = document.getElementById("fw-banner");
  if (!box) return;
  try {
    const st = await fetchJSON("/api/firewall/status");
    const bad = st.checks.filter(c => !c.ok);
    if (st.ok) {
      box.className = "fw-banner ok";
      box.innerHTML = `<div class="fw-banner-head"><strong>Firewall active</strong>` +
        `<button id="fw-resync" type="button">Re-apply rules</button></div>`;
    } else {
      box.className = "fw-banner";
      const items = bad.map(c =>
        `<li><strong>${escapeHtml(c.name)}</strong>${c.detail ? " — " + escapeHtml(c.detail) : ""}` +
        `${c.fix ? `<div class="fw-fix">Fix: ${escapeHtml(c.fix)}</div>` : ""}</li>`).join("");
      const warns = (st.last_apply && st.last_apply.warnings || [])
        .map(w => `<li>${escapeHtml(w)}</li>`).join("");
      box.innerHTML = `<div class="fw-banner-head"><strong>Firewall is NOT fully enforcing blocks</strong>` +
        `<button id="fw-resync" type="button">Re-apply rules</button></div><ul>${items}${warns}</ul>`;
    }
    box.style.display = "block";
    const btn = document.getElementById("fw-resync");
    if (btn) {
      btn.onclick = async () => {
        btn.disabled = true;
        btn.textContent = "Applying...";
        try {
          await fetchJSON("/api/firewall/resync", { method: "POST" });
        } catch (err) {
          alert("Re-apply failed: " + err.message);
        }
        loadFirewallStatus();
      };
    }
  } catch (err) {
    console.error("Error loading firewall status:", err);
  }
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

      const statusHTML = d.connected
        ? `<span class="status-pill connected"><span class="dot"></span>Online</span>`
        : `<span class="status-pill disconnected"><span class="dot"></span>Offline</span>`;

      const vpnBadge = d.vpn_detected
        ? `<span class="badge vpn-badge" title="VPN/Proxy detected: ${escapeHtml(d.vpn_type || 'Active')}"><span class="vpn-dot"></span>${escapeHtml(d.vpn_type || 'VPN ACTIVE')}</span>`
        : "";

      tr.innerHTML = `
        <td>${statusHTML}</td>
        <td>
          <div class="device-name-wrap">
            <strong>${escapeHtml(d.hostname)}</strong>
            ${vpnBadge}
          </div>
        </td>
        <td class="mono">${escapeHtml(d.ip_address)}</td>
        <td class="mono">${escapeHtml(d.mac_address) || "—"}</td>
        <td class="mono">${timeAgo(d.last_seen)}</td>
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
          showEnforcementWarnings(await fetchJSON(`/api/devices/${d.id}/${action}`, { method: "POST" }));
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
      li.innerHTML = `
        <span class="entry-value">${escapeHtml(e.value)}</span>
        <button data-id="${e.id}" class="remove-btn">remove</button>
      `;
      li.querySelector(".remove-btn").onclick = async () => {
        try {
          await fetch(`/api/blocklist/${e.id}`, { method: "DELETE" });
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
          <span class="most-used-domain" title="${escapeHtml(item.domain)}">${escapeHtml(item.domain)}</span>
          <span class="most-used-hits">${item.hits} request${item.hits === 1 ? '' : 's'}</span>
        </div>
        ${isBlocked
          ? `<span class="badge blocked">blocked</span>`
          : `<button class="most-used-block-btn" data-domain="${escapeHtml(item.domain)}">Block</button>`}
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
        <span class="audit-text">${escapeHtml(e.actor)} — ${escapeHtml(e.action)}</span>
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
      showEnforcementWarnings(updated);
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
  currentModalDevice = device;
  const modal = document.getElementById("history-modal");
  const body = document.getElementById("history-modal-body");
  const title = document.getElementById("history-modal-title");
  const subtitle = document.getElementById("history-modal-subtitle");

  title.textContent = `${device.hostname} — History`;
  subtitle.textContent = `IP: ${device.ip_address} | MAC: ${device.mac_address || "—"}`;
  body.innerHTML = '<tr><td colspan="4" class="muted">loading…</td></tr>';
  modal.style.display = "flex";

  updateModalDeviceToggle(device);

  try {
    const [logs, activeBlocklist] = await Promise.all([
      fetchJSON(`/api/activity?device_id=${device.id}&limit=100`),
      fetchJSON("/api/blocklist")
    ]);

    body.innerHTML = "";
    if (logs.length === 0) {
      body.innerHTML = '<tr><td colspan="4" class="muted">No activity for this device yet</td></tr>';
      return;
    }

    const blockedDomainValues = new Set(
      activeBlocklist.filter(b => b.entry_type === "domain").map(b => b.value.toLowerCase())
    );

    function isDomainInBlocklist(domain) {
      const clean = domain.toLowerCase().replace(/^\.+|\.+$/g, "");
      const parts = clean.split(".");
      for (let i = 0; i < parts.length - 1; i++) {
        const parent = parts.slice(i).join(".");
        if (blockedDomainValues.has(parent)) return true;
      }
      return false;
    }

    logs.forEach(log => {
      const isAlreadyBlocked = log.status === "blocked" || isDomainInBlocklist(log.domain);
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td class="mono">${timeAgo(log.timestamp)}</td>
        <td class="mono"><strong>${escapeHtml(log.domain)}</strong></td>
        <td><span class="badge ${isAlreadyBlocked ? "blocked" : "allowed"}">${isAlreadyBlocked ? "blocked" : "allowed"}</span></td>
        <td>
          ${isAlreadyBlocked
            ? `<span class="muted">already blocked</span>`
            : `<button class="block-domain-btn" data-domain="${escapeHtml(log.domain)}">Block</button>`}
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
              body: JSON.stringify({
                value: domain,
                entry_type: "domain",
                reason: `Blocked from ${device.hostname} history`
              })
            });
            refreshAll();
            // Re-render history modal with updated block status
            openHistoryModal(device);
          } catch (err) {
            alert(`Failed to block ${domain}: ${err.message}`);
            blockBtn.disabled = false;
            blockBtn.textContent = "Block";
          }
        };
      }

      body.appendChild(tr);
    });
  } catch (err) {
    body.innerHTML = `<tr><td colspan="4" class="muted error">Failed to load history: ${err.message}</td></tr>`;
  }
}

document.getElementById("history-modal-close").onclick = () => {
  document.getElementById("history-modal").style.display = "none";
  currentModalDevice = null;
};

document.getElementById("history-modal").addEventListener("click", (e) => {
  if (e.target.id === "history-modal") {
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
    const added = await fetchJSON("/api/blocklist", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ value, entry_type: "domain", reason: "Blocked from dashboard form" })
    });
    showEnforcementWarnings(added);
    valueInput.value = "";
    refreshAll();
  } catch (err) {
    alert(`Could not block '${value}': ${err.message}`);
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = "Block";
  }
});

let _fwTick = 0;
function refreshAll() {
  loadStats();
  loadDevices();
  loadBlocklist();
  loadMostUsed();
  loadAuditLog();
  // firewall health runs iptables + a DNS self-test, so check it every ~30s, not every 4s
  if (_fwTick++ % 8 === 0) loadFirewallStatus();
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

