// static/js/srp_client.js

// SRP Constants
const N_HEX = `AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB37861602790CA1094383`;
const g_HEX = "02";

// BigInt Utils
function hexToBigInt(hex) { return BigInt("0x" + hex); }
// padding added
function bigIntToHex(bi) { 
    let s = bi.toString(16);
    // if length is odd, prepend '0' to make even-length
    if (s.length % 2 !== 0) {
        s = '0' + s;
    }
    return s;
}

async function sha256(...args) {
    const encoder = new TextEncoder();
    let data = new Uint8Array(0);
    for (const arg of args) {
        let chunk;
        if (typeof arg === 'string') chunk = encoder.encode(arg);
        else if (arg instanceof Uint8Array) chunk = arg;
        else throw new Error("Invalid type for SHA256");
        
        const merged = new Uint8Array(data.length + chunk.length);
        merged.set(data);
        merged.set(chunk, data.length);
        data = merged;
    }
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return new Uint8Array(hashBuffer);
}

// Hash function that matches Python's new implementation
async function H(...args) {
    const hash = await sha256(...args);
    // Convert buffer to hex string
    const hex = Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('');
    return hexToBigInt(hex);
}

// Calculate k consistently: H(N, g) -> using hex representations
async function calculateK() {
    const N = hexToBigInt(N_HEX);
    const g = hexToBigInt(g_HEX);
    return await H(bigIntToHex(N), bigIntToHex(g));
}

// Client-side SRP Registration
async function generateVerifier(username, password) {
    const N = hexToBigInt(N_HEX);
    const g = hexToBigInt(g_HEX);
    
    // Salt
    const saltBytes = crypto.getRandomValues(new Uint8Array(16));
    const saltHex = Array.from(saltBytes).map(b => b.toString(16).padStart(2, '0')).join('');

    // x = H(salt, password)
    const x = await H(saltHex, password);
    
    // v = g^x % N
    const v = modPow(g, x, N);
    
    return {
        salt: saltHex,
        verifier: bigIntToHex(v)
    };
}

// Modular Exponentiation: (base^exp) % mod
function modPow(base, exp, mod) {
    let res = 1n;
    base = base % mod;
    while (exp > 0n) {
        if (exp % 2n === 1n) res = (res * base) % mod;
        exp = exp / 2n;
        base = (base * base) % mod;
    }
    return res;
}