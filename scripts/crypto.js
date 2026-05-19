const ITERATIONS = 150000;

function toBase64(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function fromBase64(str) {
    return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}

function generateSalt() {
    return crypto.getRandomValues(new Uint8Array(16));
}

function generateIV() {
    return crypto.getRandomValues(new Uint8Array(12));
}

function parseEncryptedVault(encryptedData) {
    let parsed;

    try {
        parsed = JSON.parse(encryptedData);
    } catch {
        throw new Error("Invalid encrypted vault format");
    }

    if (!parsed || !parsed.salt || !parsed.iv || !parsed.data) {
        throw new Error("Invalid encrypted vault structure");
    }

    return parsed;
}

async function deriveKey(password, salt) {
    if (!password) {
        throw new Error("Missing master password");
    }

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
            salt,
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

async function loadCryptoKey(password) {
    const encrypted = localStorage.getItem("bullet_vault");

    if (!encrypted) {
        return null;
    }

    const parsed = parseEncryptedVault(encrypted);
    const salt = fromBase64(parsed.salt);

    return deriveKey(password, salt);
}

async function encryptVault(vault, password) {
    if (!Array.isArray(vault)) {
        throw new Error("Vault must be an array");
    }

    const salt = generateSalt();
    const iv = generateIV();
    const key = await deriveKey(password, salt);

    const enc = new TextEncoder();
    const data = enc.encode(JSON.stringify(vault));

    const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        data
    );

    return JSON.stringify({
        version: 1,
        kdf: "PBKDF2",
        iterations: ITERATIONS,
        cipher: "AES-GCM",
        salt: toBase64(salt),
        iv: toBase64(iv),
        data: toBase64(encrypted),
        createdAt: new Date().toISOString()
    });
}

async function decryptVault(encryptedData, password) {
    const parsed = parseEncryptedVault(encryptedData);

    const salt = fromBase64(parsed.salt);
    const iv = fromBase64(parsed.iv);
    const data = fromBase64(parsed.data);

    const key = await deriveKey(password, salt);

    let decrypted;

    try {
        decrypted = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv },
            key,
            data
        );
    } catch {
        throw new Error("Session locked / wrong password");
    }

    let result;

    try {
        const dec = new TextDecoder();
        result = JSON.parse(dec.decode(decrypted));
    } catch {
        throw new Error("Vault decrypted but content is invalid");
    }

    if (!Array.isArray(result)) {
        throw new Error("Vault content is invalid");
    }

    return result;
}