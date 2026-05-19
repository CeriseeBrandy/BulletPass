// ==========================================
// NAVIGATION
// ==========================================
function showSection(name) {
    document.querySelectorAll(".view-section").forEach(sec => {
        sec.style.display = "none";
        sec.classList.remove("active");
    });

    const target = document.getElementById(name + "-view");

    if (target) {
        target.style.display = "block";
        target.classList.add("active");
    }

    const titles = {
        generator: "Generator",
        vault: "Vault",
        backup: "Backup",
        about: "Security",
        settings: "Settings"
    };

    const tb = document.getElementById("topbar-title");
    if (tb) tb.textContent = titles[name] || name;
}

// ==========================================
// GENERATOR
// ==========================================
function updateLength(val) {
    document.getElementById("length-val").innerText = val;
}

function askPythonPassword() {
    const length = parseInt(document.getElementById("length-slider").value, 10);
    const useSymbols = document.getElementById("check-symbols").checked;
    const useNumbers = document.getElementById("check-numbers").checked;

    let chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

    if (useNumbers) chars += "0123456789";
    if (useSymbols) chars += "!@#$%^&*()_+-=[]{}|;:,.<>?";

    let password = "";

    for (let i = 0; i < length; i++) {
        const randomIndex = crypto.getRandomValues(new Uint32Array(1))[0] % chars.length;
        password += chars[randomIndex];
    }

    document.getElementById("pass-display").value = password;
}

function copyToClipboard() {
    const passInput = document.getElementById("pass-display");
    if (!passInput.value) return;

    navigator.clipboard.writeText(passInput.value).then(() => {
        const copyBtn = document.getElementById("copy-btn");
        const original = copyBtn.innerHTML;

        copyBtn.innerHTML = '<i class="fa-solid fa-check" style="color: #00ff00;"></i>';

        setTimeout(() => {
            copyBtn.innerHTML = original;
        }, 2000);
    });
}

// ==========================================
// EDIT TILE
// ==========================================
function openEditTile(id) {
    const overlay = document.createElement("div");
    overlay.className = "edit-overlay";

    const vault = window.cachedVault || [];
    const entry = vault.find(e => e.id === id);

    if (!entry) return;

    overlay.innerHTML = `
        <div class="edit-modal">
            <div class="edit-header">
                <img src="${entry.logo}">
                <span>${entry.domain}</span>
            </div>

            <div class="edit-body">
                <label>USERNAME</label>
                <input id="edit-user" value="${safe(entry.user)}">

                <label>PASSWORD</label>
                <input id="edit-pass" value="${safe(entry.pass)}">
            </div>

            <div class="edit-actions">
                <button class="btn-cancel">CANCEL</button>
                <button class="btn-save">SAVE</button>
            </div>
        </div>
    `;

    document.body.appendChild(overlay);

    requestAnimationFrame(() => {
        overlay.querySelector(".edit-modal").classList.add("open");
    });

    overlay.querySelector(".btn-cancel").onclick = () => overlay.remove();
    overlay.querySelector(".btn-save").onclick = () => saveVaultEntry(id);
}

function closeEditTile() {
    const overlay = document.querySelector(".edit-overlay");
    if (overlay) overlay.remove();
}

// ==========================================
// COPY PASSWORD
// ==========================================
function copyVaultPass(password) {
    navigator.clipboard.writeText(password);

    const notification = document.createElement("div");
    notification.innerText = "AMMO COPIED";
    notification.style = `
        position:fixed;
        bottom:30px;
        left:50%;
        transform:translateX(-50%);
        background:#fff;
        color:#000;
        padding:10px 20px;
        border-radius:20px;
        font-weight:900;
        font-size:0.75rem;
        letter-spacing:1px;
        z-index:11000;
        box-shadow:0 0 10px rgba(255,255,255,0.6),0 0 20px rgba(255,255,255,0.3);
    `;

    document.body.appendChild(notification);

    setTimeout(() => notification.remove(), 2000);
}

// ==========================================
// ALERT
// ==========================================
function bulletAlert(title, message = "") {
    const old = document.getElementById("bullet-modal-container");
    if (old) old.remove();

    const overlay = document.createElement("div");
    overlay.id = "bullet-modal-container";
    overlay.className = "modal-overlay";

    const messageHTML = message
        ? `<p style="color:#eee;margin:0 0 20px 0;font-family:'Segoe UI',sans-serif;font-size:0.75rem;">${message}</p>`
        : "";

    overlay.innerHTML = `
        <div class="custom-modal" style="background:#050505;">
            <h3 style="color:#fff;margin-bottom:30px;font-size:1.4rem;letter-spacing:6px;text-shadow:0 0 10px #fff,0 0 20px rgba(255,255,255,0.6);">
                ${title}
            </h3>

            <div style="background:rgba(255,255,255,0.05);border-radius:20px;padding:25px;margin-bottom:35px;border:1px solid rgba(255,255,255,0.1);font-family:monospace;font-size:0.85rem;color:#ddd;">
                ${messageHTML}
            </div>

            <div style="display:flex;justify-content:center;gap:25px;">
                <button id="close-bullet-btn" style="background:#1a1a1a;color:#aaa;border:1px solid rgba(255,255,255,0.2);padding:14px 30px;border-radius:15px;font-weight:900;cursor:pointer;">
                    CANCEL
                </button>

                <button id="confirm-bullet-btn" style="background:#fff;color:#000;border:none;padding:14px 30px;border-radius:15px;font-weight:900;cursor:pointer;box-shadow:0 0 15px rgba(255,255,255,0.6);">
                    OK
                </button>
            </div>
        </div>
    `;

    document.body.appendChild(overlay);

    document.getElementById("close-bullet-btn").onclick = () => overlay.remove();
    document.getElementById("confirm-bullet-btn").onclick = () => overlay.remove();
}

// ==========================================
// RESET SECURE
// ==========================================
function resetApplication() {
    const overlay = document.createElement("div");
    overlay.className = "modal-overlay";

    overlay.innerHTML = `
        <div style="background:#050505;border-radius:25px;padding:40px;width:450px;border:2px solid #fff;text-align:center;">
            <h3 style="color:#fff;margin-bottom:20px;letter-spacing:3px;">RESET COMPLET</h3>

            <div style="color:#aaa;margin-bottom:25px;">
                Cette action supprimera le coffre local.<br><br>
                Une backup de sécurité sera créée avant suppression.
            </div>

            <input id="reset-confirm-input" placeholder="Type DELETE MY VAULT"
                style="width:100%;padding:12px;margin-bottom:20px;border-radius:12px;">

            <div style="display:flex;gap:15px;justify-content:center;">
                <button id="cancel-reset">CANCEL</button>
                <button id="confirm-reset">RESET</button>
            </div>
        </div>
    `;

    document.body.appendChild(overlay);

    document.getElementById("cancel-reset").onclick = () => overlay.remove();

    document.getElementById("confirm-reset").onclick = () => {
        const confirmText = document.getElementById("reset-confirm-input").value;

        if (confirmText !== "DELETE MY VAULT") {
            bulletAlert("ERROR", "Confirmation text is incorrect.");
            return;
        }

        safeBackupCurrentVault("before_reset");

        localStorage.removeItem("bullet_vault");
        localStorage.removeItem("bullet_nickname");
        localStorage.removeItem("isLogged");
        localStorage.removeItem("masterPass");

        sessionStorage.removeItem("masterPass");
        sessionStorage.removeItem("bullet_session_unlocked");

        window.cachedVault = null;
        window.location.href = "login.html";
    };
}

// ==========================================
// EXPORT SECURE
// ==========================================
async function exportVault() {
    const overlay = document.createElement("div");
    overlay.className = "modal-overlay";

    overlay.innerHTML = `
        <div style="background:#050505;border-radius:25px;padding:40px 30px;width:100%;max-width:420px;text-align:center;">
            <h3 style="color:#fff;margin-bottom:25px;">CONFIRMATION EXPORT</h3>

            <input type="password" id="export-pass" placeholder="Master Password"
                style="width:100%;padding:12px;margin-bottom:20px;border-radius:12px;">

            <div style="display:flex;justify-content:center;gap:15px;">
                <button id="cancel-export">CANCEL</button>
                <button id="confirm-export">EXPORT</button>
            </div>
        </div>
    `;

    document.body.appendChild(overlay);

    document.getElementById("cancel-export").onclick = () => overlay.remove();

    document.getElementById("confirm-export").onclick = async () => {
        const inputPass = document.getElementById("export-pass").value;
        const data = localStorage.getItem("bullet_vault");

        if (!data) {
            bulletAlert("ERROR", "No vault found.");
            return;
        }

        try {
            const vault = await decryptVault(data, inputPass);

            if (!Array.isArray(vault)) {
                bulletAlert("ERROR", "Invalid vault.");
                return;
            }

            if (vault.length === 0) {
                bulletAlert("EXPORT BLOCKED", "Vault is empty. Export cancelled to avoid saving an empty backup.");
                return;
            }

            downloadFile(data, `bullet-backup-${Date.now()}.bullet`);

            overlay.remove();
            bulletAlert("EXPORT", "Backup ready!");
        } catch (e) {
            console.error(e);
            bulletAlert("ERROR", "Session locked / wrong password.");
        }
    };
}

// ==========================================
// IMPORT SECURE
// ==========================================
function importVault() {
    const fileInput = document.getElementById("import-file");

    if (!fileInput.files.length) {
        return bulletAlert("ERROR", "Select a file.");
    }

    const file = fileInput.files[0];
    const reader = new FileReader();

    reader.onload = function (e) {
        const encryptedData = e.target.result;
        openImportModal(encryptedData);
    };

    reader.readAsText(file);
}

function openImportModal(encryptedData) {
    const overlay = document.createElement("div");
    overlay.className = "modal-overlay";

    overlay.innerHTML = `
        <div style="background:#050505;border-radius:25px;padding:50px 40px;width:500px;border:2px solid #fff;text-align:center;">
            <h3 style="color:#fff;margin-bottom:30px;font-size:1.2rem;letter-spacing:4px;">
                IMPORT BACKUP
            </h3>

            <input type="password" id="import-pass" placeholder="Backup Master Password"
                style="width:90%;padding:15px;border-radius:20px;border:1px solid rgba(255,255,255,0.15);background:rgba(255,255,255,0.05);color:#fff;outline:none;margin:0 auto 20px auto;display:block;">

            <p style="color:#aaa;font-size:12px;margin-bottom:25px;">
                Import will replace the current vault. A safety backup will be created first.
            </p>

            <div style="display:flex;justify-content:center;gap:20px;">
                <button id="cancel-import">CANCEL</button>
                <button id="confirm-import">IMPORT</button>
            </div>
        </div>
    `;

    document.body.appendChild(overlay);

    document.getElementById("cancel-import").onclick = () => overlay.remove();

    document.getElementById("confirm-import").onclick = async () => {
        const inputPass = document.getElementById("import-pass").value;

        try {
            const importedVault = await decryptVault(encryptedData, inputPass);

            if (!Array.isArray(importedVault)) {
                throw new Error("Invalid vault structure");
            }

            if (importedVault.length === 0) {
                bulletAlert("IMPORT BLOCKED", "This backup contains an empty vault. Import cancelled.");
                return;
            }

            safeBackupCurrentVault("before_import");

            localStorage.setItem("bullet_vault", encryptedData);
            sessionStorage.setItem("masterPass", inputPass);
            sessionStorage.setItem("bullet_session_unlocked", "true");

            window.cachedVault = null;

            await loadVault();

            overlay.remove();
            bulletAlert("SUCCESS", "Backup imported!");
        } catch (err) {
            console.error(err);
            bulletAlert("ERROR", "Invalid password or corrupted backup.");
        }
    };
}

function triggerImport() {
    document.getElementById("import-file").click();
}

// ==========================================
// LOCAL ONLY — ONLINE PWNED CHECK DISABLED
// ==========================================
async function checkPasswordPwned(password) {
    return null;
}

// ==========================================
// SERVICE WORKER WEB ONLY
// ==========================================
if ("serviceWorker" in navigator && !navigator.userAgent.toLowerCase().includes("electron")) {
    navigator.serviceWorker.register("sw.js").catch(err => {
        console.log("SW error:", err);
    });
}

// ==========================================
// DOWNLOAD BACKUP
// ==========================================
function downloadFile(content, filename) {
    const blob = new Blob([content], { type: "application/json" });
    const isIOS = /iPhone|iPad|iPod/i.test(navigator.userAgent);

    if (isIOS) {
        const reader = new FileReader();

        reader.onload = function () {
            const dataUrl = reader.result;

            const a = document.createElement("a");
            a.href = dataUrl;
            a.download = filename;

            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);

            setTimeout(() => {
                window.open(dataUrl, "_blank");
            }, 300);
        };

        reader.readAsDataURL(blob);
    } else {
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");

        a.href = url;
        a.download = filename;

        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);

        setTimeout(() => URL.revokeObjectURL(url), 1000);
    }
}

// ==========================================
// LOGOUT
// ==========================================
function logout() {
    sessionStorage.removeItem("masterPass");
    sessionStorage.removeItem("bullet_session_unlocked");

    localStorage.removeItem("isLogged");
    localStorage.removeItem("masterPass");

    window.cachedVault = null;
    window.location.href = "login.html";
}