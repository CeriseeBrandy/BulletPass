// ==============================
// 🔐 CONFIG
// ==============================
const ITERATIONS = 150000;

// ==============================
// 🔑 UTILS
// ==============================
function toBase64(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function fromBase64(str) {
    return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}

// ==============================
// 🧂 SALT / IV
// ==============================
function generateSalt() {
    return crypto.getRandomValues(new Uint8Array(16));
}

function generateIV() {
    return crypto.getRandomValues(new Uint8Array(12));
}

// ==============================
// 🔑 DERIVE KEY (PBKDF2)
// ==============================
async function deriveKey(password, salt) {
    const enc = new TextEncoder();

    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        "PBKDF2",
        false,
        ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: ITERATIONS,
            hash: "SHA-256"
        },
        keyMaterial,
        {
            name: "AES-GCM",
            length: 256
        },
        false,
        ["encrypt", "decrypt"]
    );
}