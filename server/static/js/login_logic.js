// static/js/login_logic.js

document.getElementById("login-btn").addEventListener("click", login);

async function login() {
  const btn = document.getElementById("login-btn");
  const resEl = document.getElementById("result");
  btn.disabled = true;
  resEl.textContent = "Starting Secure Handshake...";

  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value;
  const totp     = document.getElementById("totp").value.trim();

  if (!username || !password) {
    resEl.textContent = "Missing username or password.";
    btn.disabled = false;
    return;
  }

  try {
    // Setup SRP
    const N = hexToBigInt(N_HEX);
    const g = hexToBigInt(g_HEX);
    const k = await calculateK();

    // Generate random 'a'
    const aBytes = crypto.getRandomValues(new Uint8Array(32));
    const aHex = Array.from(aBytes).map(b => b.toString(16).padStart(2,'0')).join('');
    const a = hexToBigInt(aHex);

    // A = g^a % N
    const A = modPow(g, a, N);
    const A_hex = bigIntToHex(A);

    // Init Request
    const initResp = await fetch("/auth/login/init", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, A: A_hex })
    });

    if (!initResp.ok) throw new Error(await initResp.text());
    const initData = await initResp.json();

    // Compute Session Key
    const saltHex = initData.salt;
    const B_hex = initData.B;
    const B = hexToBigInt(B_hex);

    if (B % N === 0n) throw new Error("Server sent invalid B (0)");

    // u = H(A, B)
    const u = await H(A_hex, bigIntToHex(B));
    
    // x = H(salt, password)
    const x = await H(saltHex, password);

    // S = (B - k * g^x) ^ (a + u * x) % N
    let base = (B - (k * modPow(g, x, N)) % N) % N;
    if (base < 0n) base += N;
    
    const exp = a + u * x;
    const S = modPow(base, exp, N);
    const K = await H(bigIntToHex(S)); 

    // Verify Request (Send M1)
    // M1 = H(A, B, K)
    const M1 = await H(A_hex, bigIntToHex(B), bigIntToHex(K));
    const M1_hex = bigIntToHex(M1);

    const verifyResp = await fetch("/auth/login/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ 
        username, 
        M1: M1_hex,
        totp_code: totp || null 
      })
    });

    if (!verifyResp.ok) {
        // If 401, it's likely a wrong password or math mismatch
        throw new Error("Login Failed: Invalid credentials or server error.");
    }

    const verifyData = await verifyResp.json();

    // Server Auth (Verify M2)
    // M2 = H(A, M1, K)
    const expectedM2 = await H(A_hex, M1_hex, bigIntToHex(K));
    const expectedM2_hex = bigIntToHex(expectedM2);

    if (verifyData.M2 !== expectedM2_hex) {
        throw new Error("Server authentication failed! Possible Man-in-the-Middle.");
    }

    resEl.textContent = "Login Successful!";
    setTokenCookie(verifyData.token);
    window.location.href = "/index.html";

  } catch (e) {
    console.error(e);
    resEl.textContent = e.message;
  } finally {
    btn.disabled = false;
  }
}