const requestIdleCallback = window.requestIdleCallback || function (cb) {
    return setTimeout(cb, 200);
};

let isVaultLoading = false;
window.cachedVault = null;
let isRefreshing = false;

class VaultError extends Error {
    constructor(code, message) {
        super(message);
        this.name = "VaultError";
        this.code = code;
    }
}

function getMasterPassOrThrow() {
    const pass = sessionStorage.getItem("masterPass");

    if (!pass) {
        throw new VaultError(
            "SESSION_LOCKED",
            "Session locked. Please unlock your vault again."
        );
    }

    return pass;
}

async function safeBackupCurrentVault(reason = "auto") {
    const encrypted = localStorage.getItem("bullet_vault");

    if (!encrypted) return null;

    try {
        if (window.bulletBackup) {
            await window.bulletBackup.saveBackup("auto", encrypted);
        }
    } catch (e) {
        console.error("AUTO BACKUP DISK FAILED:", e);
    }

    try {
        const backup = {
            createdAt: new Date().toISOString(),
            reason,
            encryptedVault: encrypted
        };

        const key = `bullet_vault_backup_${Date.now()}`;
        localStorage.setItem(key, JSON.stringify(backup));

        return key;
    } catch (e) {
        console.error("AUTO BACKUP LOCALSTORAGE FAILED:", e);
        return null;
    }
}

async function getVault() {
    const encrypted = localStorage.getItem("bullet_vault");

    if (!encrypted) {
        return [];
    }

    const pass = getMasterPassOrThrow();

    let vault;

    try {
        vault = await decryptVault(encrypted, pass);
    } catch (e) {
        console.error("Vault decrypt failed:", e);
        throw new VaultError(
            "DECRYPT_FAILED",
            "Session locked or wrong password. Vault was not loaded."
        );
    }

    if (!Array.isArray(vault)) {
        throw new VaultError(
            "VAULT_CORRUPTED",
            "Vault data is corrupted. Vault was not loaded."
        );
    }

    return vault;
}

async function saveVault(vault, reason = "save") {
    if (!Array.isArray(vault)) {
        throw new VaultError("INVALID_VAULT", "Invalid vault format.");
    }

    const masterPass = getMasterPassOrThrow();

    await safeBackupCurrentVault(reason);

    const encrypted = await encryptVault(vault, masterPass);
    localStorage.setItem("bullet_vault", encrypted);

    window.cachedVault = null;
}

async function addEntryToVault() {
    try {
        let site = document.getElementById("vault-site").value.trim();
        const user = document.getElementById("vault-user").value;
        const password = document.getElementById("vault-pass").value;

        if (!site || !user || !password) return;

        let domain = site;
        let finalUrl = site;
        let logo = "assets/gun.png";

        try {
            const urlObj = new URL(site.startsWith("http") ? site : "https://" + site);

            domain = urlObj.hostname.replace("www.", "");
            finalUrl = urlObj.href;
            logo = "assets/gun.png";
        } catch {
            domain = site;
            finalUrl = site;
        }

        const entry = {
            id: Date.now(),
            url: finalUrl.toLowerCase(),
            domain,
            user,
            pass: password,
            logo
        };

        const vault = await getVault();
        vault.push(entry);

        await saveVault(vault, "before_add_entry");

        document.getElementById("vault-site").value = "";
        document.getElementById("vault-user").value = "";
        document.getElementById("vault-pass").value = "";

        loadVault();

    } catch (e) {
        console.error(e);
        bulletAlert("ERROR", e.message || "Unable to add entry.");
    }
}

async function saveVaultEntry(id) {
    try {
        const newUser = document.getElementById("edit-user").value;
        const newPass = document.getElementById("edit-pass").value;

        const vault = window.cachedVault || await getVault();
        const index = vault.findIndex(item => item.id === id);

        if (index === -1) {
            bulletAlert("ERROR", "Entry not found.");
            return;
        }

        vault[index].user = newUser;
        vault[index].pass = newPass;

        await saveVault(vault, "before_edit_entry");

        closeEditTile();
        loadVault();

    } catch (e) {
        console.error(e);
        bulletAlert("ERROR", e.message || "Unable to save entry.");
    }
}

function getDomainName(url) {
    try {
        let domain = url.replace("https://", "").replace("http://", "").split("/")[0];
        domain = domain.replace("www.", "");
        return domain.split(".")[0].charAt(0).toUpperCase() + domain.split(".")[0].slice(1);
    } catch (e) {
        return url;
    }
}

async function deleteVaultEntry(id) {
    const overlay = document.createElement("div");
    overlay.className = "modal-overlay";

    overlay.innerHTML = `
        <div style="background:#050505;border-radius:25px;padding:40px;width:400px;text-align:center;border:2px solid #fff;">
            <h3 style="color:#fff;margin-bottom:20px;letter-spacing:3px;">DELETE ?</h3>

            <p style="color:#aaa;margin-bottom:25px;">
                Are you sure you want to remove this entry?
            </p>

            <div style="display:flex;gap:15px;justify-content:center;">
                <button id="cancel-delete" style="background:#222;color:#aaa;padding:10px 20px;border-radius:10px;border:none;">
                    CANCEL
                </button>

                <button id="confirm-delete" style="background:#fff;color:#000;padding:10px 20px;border-radius:10px;border:none;font-weight:900;">
                    DELETE
                </button>
            </div>
        </div>
    `;

    document.body.appendChild(overlay);

    document.getElementById("cancel-delete").onclick = () => overlay.remove();

    document.getElementById("confirm-delete").onclick = async () => {
        try {
            let vault = await getVault();

            const oldLength = vault.length;
            vault = vault.filter(item => item.id !== id);

            if (vault.length === oldLength) {
                bulletAlert("ERROR", "Entry not found.");
                return;
            }

            await saveVault(vault, "before_delete_entry");

            overlay.remove();
            loadVault();

        } catch (e) {
            console.error(e);
            bulletAlert("ERROR", e.message || "Unable to delete entry.");
        }
    };
}