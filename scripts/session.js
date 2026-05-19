let inactivityTimer;
let INACTIVITY_TIME = 2 * 60 * 1000;

function getSessionMasterPass() {
    return sessionStorage.getItem("masterPass");
}

function isSessionUnlocked() {
    return sessionStorage.getItem("bullet_session_unlocked") === "true"
        && !!getSessionMasterPass();
}

function unlockSession(masterPass) {
    sessionStorage.setItem("masterPass", masterPass);
    sessionStorage.setItem("bullet_session_unlocked", "true");
}

function lockApp() {
    sessionStorage.removeItem("masterPass");
    sessionStorage.removeItem("bullet_session_unlocked");
    window.cachedVault = null;
    window.location.href = "login.html";
}

function resetInactivityTimer() {
    clearTimeout(inactivityTimer);

    inactivityTimer = setTimeout(() => {
        lockApp();
    }, INACTIVITY_TIME);
}

window.addEventListener("DOMContentLoaded", async () => {
    const pass = getSessionMasterPass();

    if (!isSessionUnlocked()) {
        lockApp();
        return;
    }

    try {
        await loadCryptoKey(pass);
    } catch (e) {
        console.error("Session restore failed:", e);
        lockApp();
        return;
    }

    loadInactivitySetting();
    setupInactivityInput();

    ["click", "keydown", "mousemove", "scroll"].forEach(event => {
        document.addEventListener(event, resetInactivityTimer, { passive: true });
    });

    resetInactivityTimer();

    if (!window.__vaultLoaded) {
        window.__vaultLoaded = true;

        setTimeout(() => {
            loadVault();
        }, 50);
    }
});

function loadInactivitySetting() {
    const saved = localStorage.getItem("bullet_inactivity");

    if (saved) {
        const minutes = parseInt(saved, 10);

        if (!Number.isNaN(minutes) && minutes > 0) {
            INACTIVITY_TIME = minutes * 60 * 1000;
        }

        const input = document.getElementById("inactivity-time");
        if (input) input.value = saved;
    }
}

function setupInactivityInput() {
    const input = document.getElementById("inactivity-time");

    if (!input) return;

    input.addEventListener("change", (e) => {
        const minutes = parseInt(e.target.value, 10);

        if (Number.isNaN(minutes) || minutes <= 0) {
            bulletAlert("ERROR", "Invalid inactivity time.");
            return;
        }

        localStorage.setItem("bullet_inactivity", String(minutes));
        INACTIVITY_TIME = minutes * 60 * 1000;

        resetInactivityTimer();
    });
}