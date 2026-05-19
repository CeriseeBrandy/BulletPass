document.addEventListener("DOMContentLoaded", () => {
    const isElectron = navigator.userAgent.toLowerCase().includes("electron");

    if (isElectron) {
        document.body.classList.add("electron");

        document.querySelector(".landing-nav")?.remove();
        document.querySelector(".install-btn")?.remove();
    }
});

function safe(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

async function checkPasswordPwned(password) {
    return null;
}