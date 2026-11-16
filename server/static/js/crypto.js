// server/static/js/crypto.js
// --- Utils for ArrayBuffer <-> Base64 ---
function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  const chunkSize = 0x8000; 

  for (let i = 0; i < len; i += chunkSize) {
    binary += String.fromCharCode.apply(
      null,
      bytes.subarray(i, Math.min(i + chunkSize, len))
    );
  }
  return btoa(binary);
}

function base64ToArrayBuffer(b64) {
  const bin = atob(b64);
  const len = bin.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

// --- Utils for Hex <-> Buffer ---
function hexToBuf(hex) {
    const bytes = new Uint8Array(Math.ceil(hex.length / 2));
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    return bytes.buffer;
}

/** Computes SHA-256 fingerprint (Hex) for TOFU pinning */
async function sha256Hex(buf) {
  const hash = await crypto.subtle.digest("SHA-256", buf);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("");
}

// --- Import Keys (Used for Login/Encryption) ---
// We import as ECDH here to allow file encryption later
async function importPrivateKeyFromB64(b64Pkcs8) {
  const bytes = base64ToArrayBuffer(b64Pkcs8);
  return crypto.subtle.importKey(
    "pkcs8", bytes, 
    { name: "ECDH", namedCurve: "P-256" }, 
    true, 
    ["deriveKey"]
  );
}

async function importPublicKeyFromSpkiB64(b64Spki) {
  const bytes = base64ToArrayBuffer(b64Spki);
  return crypto.subtle.importKey(
    "spki", bytes, 
    { name: "ECDH", namedCurve: "P-256" }, 
    true, 
    []
  );
}

// --- Generate Key Pair (THE FIX) ---
// We generate as ECDSA to satisfy Forge during CSR creation.
// The bytes are compatible with ECDH, which we use after login.
async function generateKeyPair() {
  return await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, 
    true,
    ["sign"] 
  );
}

// --- Derive Shared Secret ---
async function deriveSharedKey(priv, pub) {
  // 1. Convert Private Key (ECDSA -> ECDH) if needed
  let ecdhPriv = priv;
  if (priv.algorithm.name !== "ECDH") {
    const exported = await crypto.subtle.exportKey("pkcs8", priv);
    ecdhPriv = await crypto.subtle.importKey(
      "pkcs8", exported,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveKey"]
    );
  }

  // 2. Convert Public Key (ECDSA -> ECDH) if needed
  let ecdhPub = pub;
  if (pub.algorithm.name !== "ECDH") {
    const exported = await crypto.subtle.exportKey("spki", pub);
    ecdhPub = await crypto.subtle.importKey(
      "spki", exported,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      []
    );
  }

  // 3. Derive the AES-GCM Key
  return await crypto.subtle.deriveKey(
    { name: "ECDH", public: ecdhPub },
    ecdhPriv,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}
// --- Generate Random AES-GCM Key ---
async function generateFileKey() {
  return await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

// --- AES-GCM Encrypt ---
async function encryptAes(key, data, iv) {
  return await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    key,
    data
  );
}

// --- AES-GCM Decrypt ---
async function decryptAes(key, data, iv) {
  return await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv },
    key,
    data
  );
}

// --- Signing ---
// Robust signing that re-imports the key as ECDSA to be safe
async function signData(privKey, data) {
  const exported = await crypto.subtle.exportKey("pkcs8", privKey);
  const signKey = await crypto.subtle.importKey(
    "pkcs8", exported,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: { name: "SHA-256" } },
    signKey,
    data
  );
  return new Uint8Array(signature);
}

/** Verify signature */
async function verifySignature(pubKey, signature, data) {
  const exported = await crypto.subtle.exportKey("spki", pubKey);
  const verifyKey = await crypto.subtle.importKey(
    "spki", exported,
    { name: "ECDSA", namedCurve: "P-256" }, 
    false,
    ["verify"]
  );
  return await crypto.subtle.verify(
    { name: "ECDSA", hash: { name: "SHA-256" } }, 
    verifyKey,
    signature,
    data
  );
}

// --- Key Export/Import Helpers ---
async function exportKeyRaw(key) {
  return await crypto.subtle.exportKey("raw", key);
}

async function importKeyRaw(rawBytes) {
  return await crypto.subtle.importKey("raw", rawBytes, "AES-GCM", false, ["decrypt"]);
}

async function exportKeySpki(key) {
  return await crypto.subtle.exportKey("spki", key);
}

async function exportKeyPkcs8(key) {
  return await crypto.subtle.exportKey("pkcs8", key);
}

// --- Key Wrapping for Sync ---
async function deriveKeyFromPassword(password, saltHex) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw", enc.encode(password), {name: "PBKDF2"}, false, ["deriveKey"]
    );
    return window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: hexToBuf(saltHex),
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

async function wrapPrivateKey(privKeyBytes, password, saltHex) {
    const key = await deriveKeyFromPassword(password, saltHex);
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        privKeyBytes
    );
    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(encrypted), iv.length);
    return arrayBufferToBase64(combined.buffer);
}

async function unwrapPrivateKey(encryptedB64, password, saltHex) {
    const combined = base64ToArrayBuffer(encryptedB64);
    const iv = combined.slice(0, 12);
    const data = combined.slice(12);
    const key = await deriveKeyFromPassword(password, saltHex);
    const decrypted = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        key,
        data
    );
    return new Uint8Array(decrypted);
}

async function encryptTextWithPassword(text, password, saltHex) {
    const enc = new TextEncoder();
    const bytes = enc.encode(text);
    // Reuse existing wrap logic
    return await wrapPrivateKey(bytes, password, saltHex);
}
