function toggleSlideNav() {
  const nav = document.getElementById("slide-nav");
  const ov = document.getElementById("slide-nav-overlay");
  const btn = document.getElementById("hamburger-btn");

  nav.classList.add("open");
  ov.classList.add("visible");
  btn.classList.add("open");
  document.body.style.overflow = "hidden";
}

function closeSlideNav() {
  document.getElementById("slide-nav")?.classList.remove("open");
  document.getElementById("slide-nav-overlay")?.classList.remove("visible");
  document.getElementById("hamburger-btn")?.classList.remove("open");
  document.body.style.overflow = "";
}

document.addEventListener("DOMContentLoaded", () => {
  const nav = document.getElementById("slide-nav");
  if (!nav) return;

  let sx = 0;

  nav.addEventListener("touchstart", e => {
    sx = e.touches[0].clientX;
  }, { passive: true });

  nav.addEventListener("touchend", e => {
    if (sx - e.changedTouches[0].clientX > 60) closeSlideNav();
  }, { passive: true });

  const search = document.getElementById("vault-search");
  if (search) {
    let timeout;
    search.addEventListener("input", () => {
      clearTimeout(timeout);
      timeout = setTimeout(loadVault, 120);
    });
  }
});

window.showSection = function (name) {
  document.querySelectorAll(".view-section").forEach(sec => {
    sec.classList.remove("active");
    sec.style.display = "none";
  });

  const target = document.getElementById(name + "-view");

  if (target) {
    target.classList.add("active");
    target.style.display = "block";
  }

  document.querySelectorAll(".s-item").forEach(el => el.classList.remove("active"));
  document.getElementById("btn-" + name)?.classList.add("active");

  document.querySelectorAll(".slide-nav-item").forEach(el => el.classList.remove("active"));
  document.getElementById("mob-btn-" + name)?.classList.add("active");

  const titles = {
    generator: "Generator",
    vault: "Vault",
    backup: "Backup",
    about: "Security",
    settings: "Settings"
  };

  const tb = document.getElementById("topbar-title");
  if (tb) tb.textContent = titles[name] || name;

  if (name === "vault" && typeof loadVault === "function") {
    loadVault();
  }
};

function _modal(id, html) {
  const old = document.getElementById(id);
  if (old) old.remove();

  const overlay = document.createElement("div");
  overlay.id = id;
  overlay.className = "modal-overlay";
  overlay.innerHTML = html;

  document.body.appendChild(overlay);
  return overlay;
}

window.loadVault = async function () {
  const container = document.getElementById("vault-list");
  const countEl = document.getElementById("vault-count");
  const searchVal = document.getElementById("vault-search")?.value.toLowerCase() || "";

  if (!container) return;

  try {
    const vault = await getVault();

    window.cachedVault = vault;

    const filtered = vault.filter(item =>
      (item.domain || "").toLowerCase().includes(searchVal) ||
      (item.user || "").toLowerCase().includes(searchVal)
    );

    if (countEl) {
      countEl.textContent = filtered.length + " bullet" + (filtered.length !== 1 ? "s" : "");
    }

    if (filtered.length === 0) {
      container.innerHTML = `<div class="vault-empty">No bullets found…</div>`;
      return;
    }

    const groups = {};

    filtered.forEach(item => {
      const domain = item.domain || "Unknown";
      if (!groups[domain]) groups[domain] = [];
      groups[domain].push(item);
    });

    container.replaceChildren();

    const frag = document.createDocumentFragment();

    for (const [domain, accounts] of Object.entries(groups)) {
      const group = document.createElement("div");
      group.className = "vault-group";

      group.innerHTML = `
        <div class="vault-group-header">
          <img src="${safe(accounts[0].logo || "assets/gun.png")}" onerror="this.src='assets/gun.png'">
          <span class="vault-group-name">${safe(domain)}</span>
          <span class="vault-group-count">${accounts.length}</span>
        </div>
        <div class="vault-group-entries"></div>
      `;

      const entriesEl = group.querySelector(".vault-group-entries");

      accounts.forEach(acc => {
        const entry = document.createElement("div");
        entry.className = "vault-entry-wrapper";

        entry.innerHTML = `
          <div class="entry-main-tile">
            <div class="entry-left">
              <div class="entry-user">${safe(acc.user)}</div>
              <div class="entry-status safe">✓ Local encrypted</div>
            </div>
          </div>

          <div class="entry-side-actions">
            <button class="side-btn copy-btn" title="Copy">COPY</button>
            <button class="side-btn delete-btn" title="Delete">DEL</button>
          </div>
        `;

        entry.querySelector(".entry-main-tile").addEventListener("click", () => {
          openEditTile(acc.id);
        });

        entry.querySelector(".copy-btn").addEventListener("click", e => {
          e.stopPropagation();
          copyVaultPass(acc.pass);
        });

        entry.querySelector(".delete-btn").addEventListener("click", e => {
          e.stopPropagation();
          deleteVaultEntry(acc.id);
        });

        entriesEl.appendChild(entry);
      });

      frag.appendChild(group);
    }

    container.appendChild(frag);

  } catch (e) {
    console.error(e);

    window.cachedVault = null;

    container.innerHTML = `
      <div class="vault-empty">
        Session locked or wrong password.<br>
        Please unlock your vault again.
      </div>
    `;

    if (countEl) countEl.textContent = "";

    bulletAlert("SESSION LOCKED", "Vault was not loaded. Your data was not overwritten.");
  }
};

window.openEditTile = async function (id) {
  try {
    const vault = await getVault();
    const acc = vault.find(item => item.id === id);

    if (!acc) {
      bulletAlert("ERROR", "Entry not found.");
      return;
    }

    const overlay = _modal("edit-overlay", `
      <div class="custom-modal">
        <h3>EDIT ENTRY</h3>

        <p style="color:var(--text-dim);margin-bottom:20px;">
          ${safe(acc.domain)} · ${safe(acc.url)}
        </p>

        <label>USERNAME</label>
        <input type="text" id="edit-user" value="${safe(acc.user)}">

        <label>PASSWORD</label>
        <div style="position:relative;">
          <input type="password" id="edit-pass" value="${safe(acc.pass)}">
          <button type="button" onclick="togglePassView()" style="position:absolute;right:10px;top:8px;">
            SHOW
          </button>
        </div>

        <div class="modal-actions">
          <button class="btn-ghost" onclick="closeEditTile()">Cancel</button>
          <button class="btn-white" onclick="saveVaultEntry(${acc.id})">Save</button>
        </div>
      </div>
    `);

    setTimeout(() => {
      document.getElementById("edit-user")?.focus();
    }, 100);

  } catch (e) {
    console.error(e);
    bulletAlert("ERROR", e.message || "Unable to open entry.");
  }
};

window.closeEditTile = function () {
  document.getElementById("edit-overlay")?.remove();
};

window.bulletAlert = function (title, message = "") {
  const overlay = _modal("bullet-modal-container", `
    <div class="custom-modal" style="text-align:center;">
      <h3>${safe(title)}</h3>

      <div style="background:rgba(255,255,255,.03);border:.5px solid var(--border);border-radius:var(--radius-md);padding:16px 20px;margin-bottom:24px;font-size:13px;font-weight:300;color:var(--text-dim);line-height:1.7;text-align:left;">
        ${safe(message)}
      </div>

      <div class="modal-actions" style="justify-content:center;">
        <button class="btn-white" id="confirm-bullet-btn" style="min-width:120px;">OK</button>
      </div>
    </div>
  `);

  overlay.querySelector("#confirm-bullet-btn").onclick = () => overlay.remove();

  overlay.addEventListener("click", e => {
    if (e.target === overlay) overlay.remove();
  });
};

window.copyVaultPass = function (password) {
  navigator.clipboard.writeText(password).then(() => {
    const toast = document.createElement("div");
    toast.className = "toast";
    toast.textContent = "Copied to clipboard";
    document.body.appendChild(toast);

    setTimeout(() => toast.remove(), 2200);
  });
};

function togglePassView() {
  const input = document.getElementById("edit-pass");
  if (!input) return;

  input.type = input.type === "password" ? "text" : "password";
}

function updateLength(value) {
  const label = document.getElementById("length-val");
  if (label) label.textContent = value;
}

function generatePassword() {
  const length = parseInt(document.getElementById("length-slider").value, 10);

  const useLetters = document.getElementById("check-letters").checked;
  const useNumbers = document.getElementById("check-numbers").checked;
  const useSymbols = document.getElementById("check-symbols").checked;
  const excludeSimilar = document.getElementById("exclude-similar").checked;

  let chars = "";

  if (useLetters) chars += "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
  if (useNumbers) chars += "0123456789";
  if (useSymbols) chars += "!@#$%^&*()_+[]{}<>?";

  if (excludeSimilar) {
    const similar = ["0", "O", "o", "1", "l", "I"];
    chars = chars.split("").filter(c => !similar.includes(c)).join("");
  }

  if (!chars) {
    bulletAlert("ERROR", "Select at least one option.");
    return;
  }

  let password = "";

  const random = new Uint32Array(length);
  crypto.getRandomValues(random);

  for (let i = 0; i < length; i++) {
    password += chars[random[i] % chars.length];
  }

  document.getElementById("pass-display").value = password;
}

function copyGenerated() {
  const input = document.getElementById("pass-display");

  if (!input || !input.value) return;

  navigator.clipboard.writeText(input.value).then(() => {
    const btn = document.getElementById("copy-btn");
    if (!btn) return;

    const old = btn.textContent;
    btn.textContent = "COPIED";

    setTimeout(() => {
      btn.textContent = old;
    }, 1200);
  });
}