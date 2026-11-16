// server/static/js/register_logic.js

function showResult(msg, type, isHtml=false) {
  const el = document.getElementById("result");
  el.textContent = "";
  el.className = `result ${type}`;
  if(isHtml) el.innerHTML = msg;
  else el.textContent = msg;
}

// Keep in sync with server-side MIN_PASSWORD_LENGTH
const MIN_PASSWORD_LENGTH = 12;
const SPECIAL_CHARS_REGEX = /[!@#$%^&*()\-_=+\[\]{}|;:,.<>?]/;

function validatePasswordPolicy(password) {
  if (password.length < MIN_PASSWORD_LENGTH) {
    return `Password must be at least ${MIN_PASSWORD_LENGTH} characters long.`;
  }
  if (!SPECIAL_CHARS_REGEX.test(password)) {
    return "Password must contain at least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)";
  }
  return null;
}

// --- 1. UI Logic: Toggle fields based on Role ---
document.addEventListener("DOMContentLoaded", function() {
  const roleSelect = document.getElementById("role");
  const patientFields = document.getElementById("patient-fields");
  const doctorFields = document.getElementById("doctor-fields");

  if (roleSelect && patientFields && doctorFields) {
    function updateFields() {
      if (roleSelect.value === 'patient') {
        patientFields.style.display = 'block';
        doctorFields.style.display = 'none';
      } else {
        patientFields.style.display = 'none';
        doctorFields.style.display = 'block';
      }
    }
    roleSelect.addEventListener("change", updateFields);
    updateFields();
  }
});

// --- 2. Registration Logic ---
document.getElementById("register-btn").addEventListener("click", register);

async function register() {
  const btn = document.getElementById("register-btn");
  btn.disabled = true;

  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value;
  const role     = document.getElementById("role").value;
  
  const dob = document.getElementById("dob").value;
  const organization = document.getElementById("organization").value.trim();

  if (!username || !password) {
    showResult("Please fill username and password.", "error");
    btn.disabled = false;
    return;
  }

  const passwordError = validatePasswordPolicy(password);
  if (passwordError) {
    showResult(passwordError, "error");
    btn.disabled = false;
    return;
  }

  if (role === 'patient' && !dob) {
    showResult("Patients must enter a Date of Birth.", "error");
    btn.disabled = false;
    return;
  }
  if (role === 'doctor' && !organization) {
    showResult("Doctors must enter a Medical Organization.", "error");
    btn.disabled = false;
    return;
  }

  try {
    showResult("Generating secure keys...", "info");

    // A. Generate SRP Verifier & Salt
    const srpData = await generateVerifier(username, password);
    
    // B. Generate Key Pair & CSR (PKI Flow)
    const keyPair = await generateKeyPair();
    
    // --- NEW: Generate CSR ---
    const csrPem = await generateCSR(keyPair, username);

    // Encrypt Private Key for Backup
    const privPkcs8 = await exportKeyPkcs8(keyPair.privateKey);
    const privB64   = arrayBufferToBase64(privPkcs8);
    const encryptedPrivKey = await wrapPrivateKey(privPkcs8, password, srpData.salt);

    // Client-Side Encrypt DOB
    let encryptedDob = null;
    if (role === 'patient' && dob) {
        encryptedDob = await encryptTextWithPassword(dob, password, srpData.salt);
    }

    // Calculate Fingerprint for UI (Optional visual verification)
    const pubSpki = await exportKeySpki(keyPair.publicKey);
    const pubFpr = await sha256Hex(pubSpki);
    localStorage.setItem(`${username}_pub_fpr`, pubFpr);

    // D. Send Registration Request (Sending CSR)
    const resp = await fetch('/auth/register', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ 
          username: username, 
          role: role, 
          csr: csrPem,           // <--- Sending CSR instead of raw key
          salt: srpData.salt,
          verifier: srpData.verifier,
          password_length: password.length,
          //password: password,    // For server-side validation
          encrypted_priv_key: encryptedPrivKey,
          encrypted_dob: encryptedDob,
          organization: (role === 'doctor') ? organization : null
      })
    });

    const data = await resp.json().catch(() => ({}));
    
    if (!resp.ok || data.status !== "ok") {
      showResult(`Registration failed: ${JSON.stringify(data)}`, "error");
      btn.disabled = false;
      return;
    }

    // E. Save Private Key & Certificate Locally
    localStorage.setItem(`${username}_priv`, privB64);
    
    // --- NEW: Save Certificate ---
    if (data.certificate) {
        localStorage.setItem(`${username}_cert`, data.certificate);
    }

    // Auto-download key file for backup
    downloadBlob(`${username}_private_key.pkcs8`, new Blob([base64ToArrayBuffer(privB64)]));

    // F. Show MFA QR Code Popup
    const uri = `otpauth://totp/SecureMedicalRecords:${encodeURIComponent(username)}?secret=${data.mfa_secret}&issuer=SecureMedicalRecords`;
    
    const div = document.createElement('div');
    new QRCode(div, { text: uri, width: 256, height: 256 });
    
    await new Promise(r => setTimeout(r, 250));
    
    const img = div.querySelector('img') || div.querySelector('canvas');
    let qrDataUrl = '';
    if (img) qrDataUrl = (img.tagName.toLowerCase() === 'canvas') ? img.toDataURL('image/png') : img.src;

    const popup = window.open('', '_blank', 'width=420,height=620,scrollbars=yes,resizable=yes');
    if(popup) {
        popup.document.write(`
          <!DOCTYPE html><html><head><title>MFA Setup</title>
          <style>body{font-family:Arial;margin:20px;text-align:center;}.mono{font-family:monospace;word-break:break-all;}img{border:1px solid #ddd;}</style>
          </head><body>
            <h3>Registration Successful</h3>
            <p>Scan this code with Google Authenticator:</p>
            <img src="${qrDataUrl}" alt="QR Code" />
            <br><br>
            <p><strong>MFA Secret (Backup):</strong><br><span class="mono">${data.mfa_secret}</span></p>
            <p><strong>Public Key Fingerprint:</strong><br><span class="mono">${pubFpr}</span></p>
            <p><small>You can close this window now.</small></p>
          </body></html>
        `);
        popup.document.close();
    }

    showResult(
      `Registered successfully. Certificate issued.<br>
       <small>Fingerprint: ${pubFpr}</small><br>
       Please scan the QR code in the popup window.`, 
      "success", 
      true
    );

  } catch (e) {
    console.error(e);
    showResult(`Error: ${e.message}`, "error");
  } finally {
    btn.disabled = false;
  }
}


// --- Vanilla JS CSR Generator (No Forge) ---

async function generateCSR(keyPair, commonName) {
  // 1. Export Public Key (Subject Public Key Info)
  const spki = await crypto.subtle.exportKey("spki", keyPair.publicKey);
  
  // 2. Create the "Info" sequence (Version + Subject + Public Key)
  // We use a minimal ASN.1 construct here.
  const info = encodeCsrInfo(commonName, spki);
  
  // 3. Sign the Info with the Private Key
  // We must re-import as ECDSA to sign (if it isn't already)
  let signKey = keyPair.privateKey;
  if (signKey.algorithm.name !== "ECDSA") {
     const exported = await crypto.subtle.exportKey("pkcs8", signKey);
     signKey = await crypto.subtle.importKey(
        "pkcs8", exported, 
        { name: "ECDSA", namedCurve: "P-256" }, 
        false, 
        ["sign"]
     );
  }

  const rawSignature = await crypto.subtle.sign(
    { name: "ECDSA", hash: { name: "SHA-256" } },
    signKey,
    info
  );

  // 4. Convert P1363 Signature (WebCrypto) to DER Signature (ASN.1)
  const derSignature = convertP1363ToDer(rawSignature);

  // 5. Assemble the final CSR (Info + Algorithm + Signature)
  const csrDer = encodeCsrFinal(info, derSignature);

  // 6. Convert to PEM
  return formatPEM(csrDer, "CERTIFICATE REQUEST");
}


// --- Minimal ASN.1 Helpers ---

function encodeCsrInfo(cn, spkiRaw) {
  // Hardcoded OID for CommonName (2.5.4.3)
  // Structure: SEQUENCE { Version(0), Subject(CN), PublicKey }
  
  // 1. Version: INTEGER 0
  const version = [0x02, 0x01, 0x00]; 
  
  // 2. Subject: SEQUENCE { SET { SEQUENCE { OID, UTF8String } } }
  // OID 2.5.4.3 (CommonName) -> 06 03 55 04 03
  const cnBytes = new TextEncoder().encode(cn);
  const cnSeq = join([
    [0x06, 0x03, 0x55, 0x04, 0x03], // OID
    [0x0c, cnBytes.length, ...cnBytes] // UTF8String
  ]);
  const cnWrapped = wrap(0x30, cnSeq); // Sequence
  const subject = wrap(0x30, wrap(0x31, cnWrapped)); // Sequence of Sets
  
  // 3. Public Key: Just embed the raw SPKI bytes
  const pubKey = new Uint8Array(spkiRaw);

  // 4. Attributes: [0] (Empty)
  const attributes = [0xa0, 0x00];

  return new Uint8Array(wrap(0x30, join([version, subject, pubKey, attributes])));
}

function encodeCsrFinal(info, signature) {
  // Structure: SEQUENCE { Info, Algorithm(ECDSA-SHA256), BitString(Signature) }
  
  // OID for ecdsa-with-SHA256 (1.2.840.10045.4.3.2)
  const algo = [0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
  
  // BitString wrapper for signature (prepend 0x00 for "0 unused bits")
  const sigBitString = wrap(0x03, [0x00, ...signature]);
  
  return new Uint8Array(wrap(0x30, join([info, algo, sigBitString])));
}

// Convert WebCrypto Raw Signature (r|s) to ASN.1 DER Sequence
function convertP1363ToDer(rawSig) {
  const bytes = new Uint8Array(rawSig);
  const r = bytes.subarray(0, 32);
  const s = bytes.subarray(32, 64);
  
  function encodeInt(buf) {
    // If MSB is set, prepend 0x00 to mark as positive integer
    if (buf[0] & 0x80) {
        return wrap(0x02, [0x00, ...buf]);
    }
    // Remove leading zeros if present (but keep at least one if all zero)
    let start = 0;
    while (start < buf.length - 1 && buf[start] === 0 && !(buf[start+1] & 0x80)) start++;
    return wrap(0x02, buf.subarray(start));
  }

  return new Uint8Array(wrap(0x30, join([encodeInt(r), encodeInt(s)])));
}


function wrap(tag, payload) {
  // ASN.1 Length encoding
  let lenBytes = [];
  const len = payload.length;
  if (len < 128) {
    lenBytes = [len];
  } else if (len < 256) {
    lenBytes = [0x81, len];
  } else {
    lenBytes = [0x82, len >> 8, len & 0xff];
  }
  
  //  Removed dead code 'res'
  const header = [tag, ...lenBytes];
  const out = new Uint8Array(header.length + payload.length);
  out.set(header);
  out.set(payload, header.length);
  return out;
}

function join(arrays) {
  let total = 0;
  for (const arr of arrays) total += arr.length;
  const res = new Uint8Array(total);
  let offset = 0;
  for (const arr of arrays) {
    res.set(arr, offset);
    offset += arr.length;
  }
  return res;
}

function formatPEM(buffer, tag) {
  const b64 = btoa(String.fromCharCode(...buffer));
  let str = `-----BEGIN ${tag}-----\n`;
  for (let i = 0; i < b64.length; i += 64) {
    str += b64.slice(i, i + 64) + '\n';
  }
  str += `-----END ${tag}-----`;
  return str;
}