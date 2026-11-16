// static/js/app_main.js

let user = null;
let privKey = null;

let appointedDoctorsCache = null;

const pubKeyCache = new Map();

const patientDoctorsCache = new Map();

// Keep aligned with server MIN_PASSWORD_LENGTH
const MIN_PASSWORD_LENGTH = 12;
const SPECIAL_CHARS_REGEX = /[!@#$%^&*()\-_=+\[\]{}|;:,.<>?]/;

async function getAppointedDoctorsForPatient(patientUsername) {
  if (patientDoctorsCache.has(patientUsername)) {
    return patientDoctorsCache.get(patientUsername);
  }

  const resp = await fetch('/files/appointed_doctors_for_patient', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: getToken(), patient_username: patientUsername })
  });

  if (!resp.ok) {
    // If forbidden/not found etc. just return empty list to avoid breaking UI
    return [];
  }

  const doctors = await resp.json();
  patientDoctorsCache.set(patientUsername, doctors || []);
  return doctors || [];
}

// --- Key Pinning (TOFU) ---
async function getPinnedUserPubKey(username) {
  if (pubKeyCache.has(username)) return pubKeyCache.get(username);

  const token = getToken();
  const resp = await fetch('/auth/get_pubkey', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ token, username })
  });
  if (!resp.ok) throw new Error("get_pubkey failed: " + username);

  const { pub_key } = await resp.json();
  const spkiBytes = base64ToArrayBuffer(pub_key);
  const fpr = await sha256Hex(spkiBytes);

  const keyName = `${username}_pub_fpr`;
  const pinned = localStorage.getItem(keyName);

  if (!pinned) localStorage.setItem(keyName, fpr);
  else if (pinned !== fpr) {
    alert(`SECURITY ALERT: Public Key Changed for ${username}!`);
    logout();
    throw new Error("Pinned key mismatch");
  }

  const key = await importPublicKeyFromSpkiB64(pub_key);
  pubKeyCache.set(username, key);
  return key;
}

// --- Initialization ---
async function init() {
  const token = getToken();
  if (!token) { window.location.href = '/login.html'; return; }

  const resp = await fetch('/auth/me', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token })
  });

  if (!resp.ok) { logout(); return; }

  user = await resp.json();

  // --- CHANGED START ---
  // Construct Welcome Message using the Organization field
  let welcomeMsg = `Welcome, ${user.username} (${user.role})`;
  
  if (user.role === 'doctor' && user.organization) {
      welcomeMsg += ` - ${user.organization}`;
  }

  document.getElementById("welcome").textContent = welcomeMsg;
  // --- CHANGED END ---

  document.getElementById("logout-btn").addEventListener("click", logout);

  let privKeyB64 = localStorage.getItem(`${user.username}_priv`);

  if (!privKeyB64 && user.encrypted_priv_key) {
      const password = prompt("New device! Enter password to restore key:");
      if (password) {
          try {
              const saltResp = await fetch('/auth/get_salt', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ username: user.username })
              });
              const saltData = await saltResp.json();
              const decryptedBytes = await unwrapPrivateKey(user.encrypted_priv_key, password, saltData.salt);
              privKeyB64 = arrayBufferToBase64(decryptedBytes.buffer);
              localStorage.setItem(`${user.username}_priv`, privKeyB64);
          } catch (e) {
              alert("Restoration failed.");
              return;
          }
      }
  }

  if (!privKeyB64) {
      alert("No private key found.");
      return;
  }

  privKey = await importPrivateKeyFromB64(privKeyB64);

  // Show security settings only after successful key load
  document.getElementById("security-settings").classList.remove("hidden");

  if (user.role === "patient") {
    document.getElementById("patient-dashboard").classList.remove("hidden");
    setupPatientListeners();
    refreshRecordList();
    refreshPendingRequests();
    document.getElementById("list-doctors-btn").click();
  } else {
    document.getElementById("doctor-dashboard").classList.remove("hidden");
    setupDoctorListeners();
    refreshRecordList();
  }
}

// --- CORE: Fetch & Decrypt Helper ---
// static/js/app_main.js

async function fetchAndDecryptRecordStrict(recordId, patientUsername) {
    const resp = await fetch('/files/download', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ token: getToken(), record_id: parseInt(recordId) })
    });

    if (!resp.ok) throw new Error(await resp.text());
    const { encrypted_blob, wrapped_key, encrypted_metadata, signature, public_metadata } = await resp.json();

    const sigBytes = base64ToArrayBuffer(signature);
    const metaBytes = base64ToArrayBuffer(encrypted_metadata);
    const fileBytes = base64ToArrayBuffer(encrypted_blob);
    
    const signedData = new Uint8Array(metaBytes.byteLength + fileBytes.byteLength);
    signedData.set(new Uint8Array(metaBytes));
    signedData.set(new Uint8Array(fileBytes), metaBytes.byteLength);

    // 1. Try Patient (Self/Owner)
    // 2. Try All Appointed Doctors (if available in memory/cache or fetch them)
    
    // We construct a candidate list. 
    // Ideally we should cache appointed doctors list, but fetching here ensures freshness.
    let signerCandidates = [patientUsername];

    // If doctor, also try self (sometimes patient re-shared etc.)
    if (user.username !== patientUsername) signerCandidates.push(user.username);

    // Patient mode: try all appointed doctors
    if (user.role === 'patient') {
      try {
        const dResp = await fetch('/files/appointed_doctors', {
          method:'POST', headers:{'Content-Type':'application/json'},
          body: JSON.stringify({ token: getToken() })
        });
        if (dResp.ok) (await dResp.json()).forEach(d => signerCandidates.push(d));
      } catch(e) {}
    }

    // Doctor mode: fetch the patient's appointed doctors too
    if (user.role === 'doctor') {
      try {
        const docs = await getAppointedDoctorsForPatient(patientUsername);
        docs.forEach(d => signerCandidates.push(d));
      } catch(e) {}
    }

    signerCandidates = [...new Set(signerCandidates)]; // Unique

    let verified = false;
    let validSigner = null;

    for (const candidate of signerCandidates) {
        try {
            const pub = await getPinnedUserPubKey(candidate);
            const isValid = await verifySignature(pub, sigBytes, signedData);
            if (isValid) {
                verified = true;
                validSigner = candidate;
                break;
            }
        } catch (e) { /* Ignore key fetch errors */ }
    }

    if (!verified) {
        throw new Error(`Signature Verification Failed! Could not verify against [${signerCandidates.join(', ')}]`);
    }
    // -------------------------------------------------------------

    // 2. Key Unwrapping (Confidentiality) - Candidate Strategy
    // We can use the 'validSigner' found above as a strong hint for unwrapping!
    let candidates = [patientUsername, user.username];
    if (validSigner) candidates.unshift(validSigner);
    candidates = [...new Set(candidates)];

    let aesKeyRaw = null;
    for (const senderName of candidates) {
        try {
            const senderPub = await getPinnedUserPubKey(senderName);
            const shared = await deriveSharedKey(privKey, senderPub);
            aesKeyRaw = await decryptAes(shared, new Uint8Array(base64ToArrayBuffer(wrapped_key.ct)), new Uint8Array(base64ToArrayBuffer(wrapped_key.iv)));
            if (aesKeyRaw) break;
        } catch (e) { /* continue */ }
    }

    if (!aesKeyRaw) throw new Error("Access Denied: Could not unwrap key.");

    const aesKey = await importKeyRaw(aesKeyRaw);

    const metaIv = new Uint8Array(metaBytes).slice(0, 12);
    const metaCt = new Uint8Array(metaBytes).slice(12);
    const decMetaBytes = await decryptAes(aesKey, metaCt, metaIv);
    const meta = JSON.parse(new TextDecoder().decode(decMetaBytes));

    const decryptedFile = await decryptAes(aesKey, fileBytes, new Uint8Array(base64ToArrayBuffer(wrapped_key.file_iv)));

    return { filename: meta.filename, data: decryptedFile, date: meta.date };
}

// Request Management for Patients
async function refreshPendingRequests() {
    const div = document.getElementById("pending-list");
    if(!div) return;
    div.textContent = "Loading...";
    try {
        const resp = await fetch('/req/list', {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ token: getToken() })
        });
        const reqs = await resp.json();
        
        if (reqs.length === 0) { div.textContent = "No pending requests."; return; }

        div.replaceChildren();
        reqs.forEach(r => {
            const el = document.createElement("div");
            el.className = "notification";
            
            // XSS-Safe DOM construction
            const msgDiv = document.createElement("div");
            if (r.type === "link_doctor") {
                const b = document.createElement("strong");
                b.textContent = `Dr. ${r.requester}`;
                msgDiv.appendChild(b);
                msgDiv.appendChild(document.createTextNode(" wants access to your records."));
            } else if (r.type === "upload_file") {
                const b = document.createElement("strong");
                b.textContent = `Dr. ${r.requester}`;
                msgDiv.appendChild(b);
                
                const dateInfo = r.details.date ? ` (Date: ${r.details.date})` : "";
                msgDiv.appendChild(document.createTextNode(` wants to upload a Secure Medical File${dateInfo}.`));
            }
            
            const btnDiv = document.createElement("div");
            btnDiv.style.marginTop = "5px";
            
            const approveBtn = document.createElement("button");
            approveBtn.textContent = "Approve";
            approveBtn.style.backgroundColor = "#28a745";
            approveBtn.style.color = "white";
            approveBtn.addEventListener("click", () => respondToRequest(r.id, 'approve'));
            
            const rejectBtn = document.createElement("button");
            rejectBtn.textContent = "Reject";
            rejectBtn.style.backgroundColor = "#dc3545";
            rejectBtn.style.color = "white";
            rejectBtn.style.marginLeft = "5px";
            rejectBtn.addEventListener("click", () => respondToRequest(r.id, 'reject'));

            btnDiv.appendChild(approveBtn);
            btnDiv.appendChild(rejectBtn);
            el.appendChild(msgDiv);
            el.appendChild(btnDiv);
            div.appendChild(el);
        });
    } catch(e) { div.textContent = "Error: " + e.message; }
}

async function respondToRequest(id, action) {
    if (!confirm(`${action.toUpperCase()} this request?`)) return;
    try {
        const resp = await fetch(`/req/${action}`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ token: getToken(), request_id: id })
        });
        if (resp.ok) {
            alert("Done!");
            appointedDoctorsCache = null;
            patientDoctorsCache.clear();
            refreshPendingRequests();
            refreshRecordList();
        } else {
            alert("Error: " + await resp.text());
        }
    } catch(e) { alert("Network Error"); }
}

// --- NEW: DOCTOR REQUEST ACCESS LOGIC ---
async function requestAccess() {
    const target = document.getElementById("req-patient-user").value.trim();
    if(!target) return alert("Enter patient username");
    
    try {
        const resp = await fetch('/req/link_patient', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ token: getToken(), patient_username: target })
        });
        const res = await resp.json();
        alert(resp.ok ? "Request sent!" : "Error: " + JSON.stringify(res));
    } catch(e) { alert("Error: " + e.message); }
}

// --- UNIVERSAL UPLOAD (Handles Patient & Doctor) ---
// Replaces the old 'uploadFile' function
async function handleUpload(isDoctor = false) {
    const prefix = isDoctor ? "doc-" : "";
    const resultEl = isDoctor ? document.getElementById("doc-upload-result") : document.getElementById("upload-result");
    
    const dateInput = document.getElementById(prefix + "exam-date").value;
    const fileInput = document.getElementById(prefix + "upload-files");
    
    let targetPatient = user.username;
    if (isDoctor) targetPatient = document.getElementById("doc-upload-patient").value.trim();

    if (!fileInput || !dateInput || fileInput.files.length === 0) return alert("Fill all fields.");
    if(resultEl) resultEl.textContent = "Processing...";

    try {
        const recipients = [user.username];
        if (isDoctor) recipients.push(targetPatient);
        else {
            const dResp = await fetch('/files/appointed_doctors', {
                method:'POST', headers:{'Content-Type':'application/json'},
                body: JSON.stringify({ token: getToken() })
            });
            if(dResp.ok) (await dResp.json()).forEach(d => recipients.push(d));
        }

        for (const file of fileInput.files) {

            const fileName = file.name.toLowerCase();
            const allowedExts = ['.pdf', '.txt', '.png', '.jpg', '.jpeg'];
            const ext = "." + fileName.split('.').pop();

            if (!allowedExts.includes(ext)) {
                alert(`Error: "${file.name}" has an invalid file type. Allowed: PDF, TXT, PNG, JPG.`);
                continue;
            }
            const data = new Uint8Array(await file.arrayBuffer());
            const fileKey = await generateFileKey();
            const fileIv  = crypto.getRandomValues(new Uint8Array(12));
            const encryptedFile = await encryptAes(fileKey, data, fileIv);

            const metaObj = { filename: file.name, date: dateInput, filesize: file.size };
            const metaBytes = new TextEncoder().encode(JSON.stringify(metaObj));
            const metaIv = crypto.getRandomValues(new Uint8Array(12));
            const encryptedMeta = await encryptAes(fileKey, metaBytes, metaIv);
            
            const metaBlob = new Uint8Array(metaIv.length + encryptedMeta.byteLength);
            metaBlob.set(metaIv);
            metaBlob.set(new Uint8Array(encryptedMeta), 12);

            const toSign = new Uint8Array(metaBlob.byteLength + encryptedFile.byteLength);
            toSign.set(metaBlob);
            toSign.set(new Uint8Array(encryptedFile), metaBlob.byteLength);
            const signature = await signData(privKey, toSign);

            const wrapped = {};
            for (const recipient of recipients) {
                try {
                    const pub = await getPinnedUserPubKey(recipient);
                    const shared = await deriveSharedKey(privKey, pub);
                    const wrapIv = crypto.getRandomValues(new Uint8Array(12));
                    const fileKeyRaw = await exportKeyRaw(fileKey);
                    const wrappedCt = await encryptAes(shared, fileKeyRaw, wrapIv);
                    const recipientHash = await sha256Hex(new TextEncoder().encode(recipient));
                    wrapped[recipientHash] = { iv: arrayBufferToBase64(wrapIv.buffer), ct: arrayBufferToBase64(wrappedCt), file_iv: arrayBufferToBase64(fileIv.buffer) };
                } catch(e) {}
            }

            // Check Response Status
            const upResp = await fetch('/files/upload', {
                method:'POST', headers:{'Content-Type':'application/json'},
                body: JSON.stringify({
                    token: getToken(), 
                    encrypted_metadata: arrayBufferToBase64(metaBlob.buffer),
                    encrypted_blob: arrayBufferToBase64(encryptedFile),
                    public_metadata: { 
                        type: "medical_record",
                        file_extension: ext
                    },
                    patient_username: targetPatient,
                    wrapped_keys: wrapped, 
                    signature: arrayBufferToBase64(signature.buffer)
                })
            });

            if (!upResp.ok) throw new Error(await upResp.text());
        }
        alert("Upload complete.");
        if(resultEl) resultEl.textContent = "";
        fileInput.value = "";
        if(!isDoctor) refreshRecordList();
    } catch (e) { 
        if(resultEl) resultEl.textContent = "Error: " + e.message; 
    }
}

// --- UTILS (View, Download, List, Etc) ---

async function viewFile(recordId, patientUsername) {
    const viewer = document.getElementById("file-viewer");
    const content = document.getElementById("viewer-content");
    const title = document.getElementById("viewer-title");
    
    viewer.style.display = "flex";
    content.innerHTML = "<p>Decrypting...</p>";

    try {
        const { filename, data } = await fetchAndDecryptRecordStrict(recordId, patientUsername);
        
        title.textContent = "Viewing: " + filename;
        content.innerHTML = "";

        const ext = filename.split('.').pop().toLowerCase();
        let mimeType = 'application/octet-stream';
        if (ext === 'pdf') mimeType = 'application/pdf';
        else if (['jpg', 'jpeg'].includes(ext)) mimeType = 'image/jpeg';
        else if (ext === 'png') mimeType = 'image/png';
        else if (ext === 'txt') mimeType = 'text/plain';

        const blob = new Blob([data], { type: mimeType });
        const url = URL.createObjectURL(blob);

        if (mimeType.startsWith('image/')) {
            const img = document.createElement("img");
            img.src = url;
            img.style.maxWidth = "100%";
            content.appendChild(img);
        } else if (ext === 'txt') {
            const text = new TextDecoder().decode(data);
            const pre = document.createElement("pre");
            pre.textContent = text;
            content.appendChild(pre);
        } else if (ext === 'pdf') {
            const iframe = document.createElement("iframe");
            iframe.src = url;
            iframe.width = "100%";
            iframe.height = "100%";
            iframe.style.border = "none";
            content.appendChild(iframe);
        } else {
            content.innerHTML = `<p>Cannot preview.</p>`;
            const btn = document.createElement("button");
            btn.textContent = "Download";
            btn.onclick = () => downloadBlob(filename, blob);
            content.appendChild(btn);
        }
    } catch (e) {
        content.innerHTML = `<p style="color:red">Error: ${e.message}</p>`;
    }
}

async function triggerDownload(recordId, patientUsername) {
    try {
        const { filename, data } = await fetchAndDecryptRecordStrict(recordId, patientUsername);
        downloadBlob(filename, new Blob([data]));
    } catch (e) { alert("Download failed: " + e.message); }
}

async function refreshRecordList() {
    const listEl = user.role === 'patient'
    ? document.getElementById("my-records")
    : document.getElementById("patient-records");
    if(!listEl) return;
    listEl.textContent = "Loading..."; 

    const body = { token: getToken() };
    let selectedPatient = null;
    if (user.role === "doctor") {
      selectedPatient = document.getElementById("list-patient-user")?.value.trim();
      if (!selectedPatient) {
        listEl.textContent = "Enter patient username.";
        return;
      }
      body.patient_username = selectedPatient;
    } else {
      selectedPatient = user.username;
    }

    try {
         const resp = await fetch('/files/list', {
          method:'POST',
          headers:{'Content-Type':'application/json'},
          body: JSON.stringify(body)
        });
        
        if (!resp.ok) throw new Error(await resp.text());
        const encryptedRecords = await resp.json();
        const normalizedRecords = encryptedRecords.map(r => ({
          ...r,
          patient: selectedPatient
        }));

        // 1. Decrypt Metadata (Logic remains same)
        const decryptedList = await Promise.all(normalizedRecords.map(async (r) => {
            if (r.encrypted_metadata === "DELETED") return { ...r, filename: "[DELETED]", date: "---" };
            try {
                let candidates = [];

                if (user.role === "doctor") {
                    candidates = [selectedPatient, user.username];
                } else {
                    // Patient Mode
                    candidates = [user.username]; 
                    const docs = await getAppointedDoctorsCached();
                    // We must extract only the .username for the candidate list
                    docs.forEach(d => {
                        if (typeof d === 'string') candidates.push(d); // Backward compatibility
                        else candidates.push(d.username);
                    });
                }

                candidates = [...new Set(candidates)];

                const wKey = r.wrapped_key;
                if (!wKey) return null;

                let aesKeyRaw = null;
                for (const signerUsername of candidates) {
                    try {
                        const signerPub = await getPinnedUserPubKey(signerUsername);
                        const shared = await deriveSharedKey(privKey, signerPub);
                        aesKeyRaw = await decryptAes(shared, new Uint8Array(base64ToArrayBuffer(wKey.ct)), new Uint8Array(base64ToArrayBuffer(wKey.iv)));
                        if (aesKeyRaw) break;
                    } catch (ignore) {}
                }
                if (!aesKeyRaw) throw new Error("No key");

                const aesKey = await importKeyRaw(aesKeyRaw);
                const metaAll = new Uint8Array(base64ToArrayBuffer(r.encrypted_metadata));
                const metaIv = metaAll.slice(0, 12);
                const metaCt = metaAll.slice(12);
                const decMeta = await decryptAes(aesKey, metaCt, metaIv);
                
                const meta = JSON.parse(new TextDecoder().decode(decMeta));
                return { ...r, filename: meta.filename, date: meta.date || "Unknown Date" }; 
            } catch(e) { return { ...r, filename: "(Error)", date: "Error" }; }
        }));

        // 2. Group by Date
        const directories = {};
        decryptedList.forEach(file => {
            if (!file) return; 
            const dateKey = file.date;
            if (!directories[dateKey]) directories[dateKey] = [];
            directories[dateKey].push(file);
        });

        // 3. Render Groups using DOM API (No innerHTML += onclick)
        listEl.replaceChildren(); // Clear content securely
        const dates = Object.keys(directories).sort().reverse();

        if (dates.length === 0) listEl.textContent = "No records found.";

        dates.forEach(date => {
            const dirDiv = document.createElement('div');
            dirDiv.style.backgroundColor = "#e9ecef";
            dirDiv.style.padding = "10px";
            dirDiv.style.marginBottom = "5px";
            const strong = document.createElement("strong");
            strong.textContent = `${date}`; // Secure textContent
            dirDiv.appendChild(strong);
            dirDiv.appendChild(document.createTextNode(` (${directories[date].length} files)`));

            listEl.appendChild(dirDiv);

            directories[date].forEach(r => {
                const row = document.createElement('div');
                row.style.padding = "5px 10px 5px 20px";
                row.style.borderBottom = "1px solid #eee";
                row.style.display = "flex";
                row.style.justifyContent = "space-between";
                
                const isDeleted = (r.filename === "[DELETED]");
                const nameDiv = document.createElement('div');
                nameDiv.textContent = isDeleted ? "[Deleted]" : ` ${r.filename} (id: ${r.id})`;
                row.appendChild(nameDiv);

                const btnGroup = document.createElement('div');
                if (!isDeleted) {
                    const viewBtn = document.createElement('button');
                    viewBtn.textContent = "View";
                    viewBtn.className = "btn-primary"; // Optional: add classes for styling
                    viewBtn.style.backgroundColor = "#007bff"; 
                    viewBtn.style.color = "white";
                    viewBtn.style.marginRight = "5px";
                    viewBtn.addEventListener("click", () => {
                      const dlId = document.getElementById("download-id");
                      const dlPat = document.getElementById("download-patient");
                      if (dlId) dlId.value = r.id;
                      if (dlPat) dlPat.value = r.patient;
                      viewFile(r.id, r.patient);
                    });
                    btnGroup.appendChild(viewBtn);

                    if (user.role === 'patient') {
                        const editBtn = document.createElement('button');
                        editBtn.textContent = "Edit";
                        editBtn.addEventListener("click", () => overwriteFile(r.id, r.filename, r.date));
                        editBtn.style.padding = "2px 5px";
                        editBtn.style.marginLeft = "5px";
                        editBtn.style.backgroundColor = "#ffc107";
                        btnGroup.appendChild(editBtn);

                        const shareBtn = document.createElement('button');
                        shareBtn.textContent = "Share";
                        shareBtn.style.marginLeft = "5px";
                        shareBtn.addEventListener("click", () => shareFile(r.id, r.filename));
                        btnGroup.appendChild(shareBtn);

                        const delBtn = document.createElement('button');
                        delBtn.textContent = "Del";
                        delBtn.style.backgroundColor = "#dc3545"; 
                        delBtn.style.color = "white";
                        delBtn.style.marginLeft = "5px";
                        delBtn.addEventListener("click", () => deleteFile(r.id));
                        btnGroup.appendChild(delBtn);
                    }
                }
                row.appendChild(btnGroup);
                listEl.appendChild(row);
            });
        });

    } catch (e) {
        listEl.textContent = "Error: " + e.message;
        console.error(e);
    }
}

// Doctor Management for Patients
async function refreshDoctorList() {
    const listEl = document.getElementById("doctor-list");
    if(!listEl) return; 
    listEl.innerHTML = "<li>Loading...</li>"; // Temporary loading state is okay
    try {
        const resp = await fetch('/files/appointed_doctors', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: getToken() })
        });
        const doctors = await resp.json();
        
        listEl.replaceChildren(); // Clear
        if (doctors.length === 0) {
            const li = document.createElement("li");
            li.textContent = "No doctors appointed.";
            listEl.appendChild(li);
            return;
        }

        // doctors is now: [{username: "eren", organization: "Hospital"}, ...]
        doctors.forEach(doc => {
            const li = document.createElement('li');
            
            const nameSpan = document.createElement("b");
            // DISPLAY BOTH NAME AND ORG
            nameSpan.textContent = `${doc.username} (${doc.organization}) `; 
            li.appendChild(nameSpan);

            const removeBtn = document.createElement("button");
            removeBtn.textContent = "Remove";
            // Pass specific username to remove function
            removeBtn.addEventListener("click", () => removeDoctor(doc.username)); 
            li.appendChild(removeBtn);

            listEl.appendChild(li);
        });
    } catch (e) { listEl.textContent = "Error: " + e.message; }
}

async function removeDoctor(doctorName) {
    if (!confirm(`Remove?`)) return;
    await fetch('/auth/remove_doctor', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: getToken(), doctor_username: doctorName })
    });
    refreshDoctorList();
    patientDoctorsCache.clear();  // cache invalidate
}

async function appointDoctor() {
  const doctor = document.getElementById("appoint-doctor").value.trim();
  if (!doctor) return alert("Enter doctor username");

  const resp = await fetch('/auth/appoint', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ token: getToken(), doctor_username: doctor })
  });

  if (!resp.ok) {
    const errText = await resp.text();
    alert("Appoint failed: " + errText);
    return;
  }

  alert("Done");
  appointedDoctorsCache = null;
  patientDoctorsCache.clear();   // cache invalidate 
  refreshDoctorList();
}

async function deleteFile(recordId) {
    if(!confirm("Delete?")) return;
    await fetch('/files/delete', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({token:getToken(), record_id: recordId}) });
    refreshRecordList();
}

async function changeCredentials() {
    const newPass = document.getElementById("new-password").value;
    const totp = document.getElementById("change-totp").value.trim();
    
    if (!newPass || !totp) return alert("Enter password and TOTP");
    if (!privKey) return alert("Error: Private Key not loaded. Cannot safely change password."); 

    // 1. Client-Side Validation
    if (newPass.length < MIN_PASSWORD_LENGTH) 
        return alert(`Password must be at least ${MIN_PASSWORD_LENGTH} characters long.`);
    if (!SPECIAL_CHARS_REGEX.test(newPass)) 
        return alert("Password must contain at least one special character.");

    try {
        // 2. Generate New Login Lock (SRP)
        const srpData = await generateVerifier(user.username, newPass);

        // 3. Generate New Data Lock (Re-Encrypt Private Key)
        const privKeyRaw = await crypto.subtle.exportKey("pkcs8", privKey);
        // This creates a "Locked Box" (Encrypted Blob)
        const newEncryptedKey = await wrapPrivateKey(privKeyRaw, newPass, srpData.salt);

        // 4. Send the "Locked Box" to Server
        const resp = await fetch('/auth/change_credentials', {
            method: 'POST', 
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                 token: getToken(),
                 new_salt: srpData.salt,
                 new_verifier: srpData.verifier,
                 encrypted_priv_key: newEncryptedKey, 
                 password_length: newPass.length,
                 totp_code: totp
            })
        });
        
        const res = await resp.json();
        if (resp.ok) {
            alert(res.message || "Credentials updated.");
        } else {
            alert(res.detail || "Error");
        }
    } catch(e) { 
        console.error(e);
        alert("Failed: " + e.message); 
    }
}

function closeViewer() {
    const viewer = document.getElementById("file-viewer");
    const content = document.getElementById("viewer-content");
    if (viewer) viewer.style.display = "none";
    if (content) content.innerHTML = ""; 
}

function toggleFullscreen() {
    const box = document.getElementById("viewer-box");
    if (!box) return;
    if (box.style.width === "100%") {
        box.style.width = "80%"; box.style.height = "80%"; box.style.resize = "both";
    } else {
        box.style.width = "100%"; box.style.height = "100%"; box.style.resize = "none";
    }
}

// --- LISTENERS ---

function setupPatientListeners() {
  // Use handleUpload(false) for patient
  document.getElementById("upload-btn").addEventListener("click", () => handleUpload(false));
  document.getElementById("appoint-btn").addEventListener("click", appointDoctor);
  document.getElementById("list-my-records-btn").addEventListener("click", refreshRecordList);
  document.getElementById("list-doctors-btn").addEventListener("click", refreshDoctorList);

  const notifBtn = document.getElementById("refresh-notif-btn");
  if(notifBtn) notifBtn.addEventListener("click", refreshPendingRequests);
}

function setupDoctorListeners() {
     document.getElementById("list-accessible-btn").addEventListener("click", () => refreshRecordList());
    document.getElementById("download-btn").addEventListener("click", async () => {
         const rid = document.getElementById("download-id").value;
         const pat = document.getElementById("download-patient").value;
         if(rid && pat) triggerDownload(rid, pat);
    });
    // HERE IS THE MISSING PART THAT FIXES YOUR BUTTONS:
    document.getElementById("req-access-btn").addEventListener("click", requestAccess);
    document.getElementById("doc-upload-btn").addEventListener("click", () => handleUpload(true));
}

async function getAppointedDoctorsCached() {
  if (appointedDoctorsCache) return appointedDoctorsCache;
  const dResp = await fetch('/files/appointed_doctors', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ token: getToken() })
  });
  appointedDoctorsCache = dResp.ok ? await dResp.json() : [];
  return appointedDoctorsCache;
}

document.addEventListener("DOMContentLoaded", () => {
    const changeBtn = document.getElementById("change-creds-btn");
    if (changeBtn) changeBtn.addEventListener("click", changeCredentials);
    
    const closeBtn = document.getElementById("close-viewer-btn");
    if (closeBtn) closeBtn.addEventListener("click", closeViewer);

    const fsBtn = document.getElementById("fullscreen-btn");
    if (fsBtn) fsBtn.addEventListener("click", toggleFullscreen);
});


async function shareFile(recordId, filename) {
    const doctor = prompt(`Share "${filename}" with doctor username:`);
    if (!doctor) return;

    try {
        const dlResp = await fetch('/files/download', {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ token: getToken(), record_id: recordId })
        });
        
        if (!dlResp.ok) throw new Error("Could not fetch file info");
        const { wrapped_key, public_metadata } = await dlResp.json();
        
        // Strategy: Try Candidates to unwrap key (Uploader, Patient, Self)
        let candidates = [user.username];
        try {
          const docs = await getAppointedDoctorsCached();
          docs.forEach(d => candidates.push(d));
        } catch (e) {}
        candidates = [...new Set(candidates)];

        let aesKeyRaw = null;
        for (const senderName of candidates) {
            try {
                const senderPub = await getPinnedUserPubKey(senderName);
                const shared = await deriveSharedKey(privKey, senderPub);
                
                // Single break check & Correct Types
                aesKeyRaw = await decryptAes(
                    shared, 
                    new Uint8Array(base64ToArrayBuffer(wrapped_key.ct)), 
                    new Uint8Array(base64ToArrayBuffer(wrapped_key.iv))
                );
                
                if (aesKeyRaw) break; 
            } catch (e) {}
        }

        if (!aesKeyRaw) throw new Error("Could not unwrap key for sharing (permission denied).");

        // Re-wrap for the new Doctor
        const doctorPub = await getPinnedUserPubKey(doctor);
        const sharedWithDoc = await deriveSharedKey(privKey, doctorPub);
        
        const wrapIv = crypto.getRandomValues(new Uint8Array(12));
        const wrappedCt = await encryptAes(sharedWithDoc, aesKeyRaw, wrapIv);
        
        const newWrappedKey = { 
            iv: arrayBufferToBase64(wrapIv.buffer), 
            ct: arrayBufferToBase64(wrappedCt), 
            file_iv: wrapped_key.file_iv 
        };
        
        const resp = await fetch('/files/share', {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ token: getToken(), record_id: recordId, doctor_username: doctor, wrapped_key: newWrappedKey })
        });

        if (resp.ok) alert("Shared successfully!");
        else alert("Share failed: " + await resp.text());

    } catch (e) { 
        alert("Error sharing file: " + e.message); 
        console.error(e);
    }
}


//  Accept oldDate to preserve folder structure
async function overwriteFile(recordId, oldFilename, oldDate) {
    const input = document.createElement('input');
    input.type = 'file';
    input.onchange = async e => {
        const file = e.target.files[0];
        

        const fileName = file.name.toLowerCase();
        const ext = "." + fileName.split('.').pop();
        if (!['.pdf', '.txt', '.png', '.jpg', '.jpeg'].includes(ext)) return alert("Invalid file type.");

        if (!file || !confirm(`Overwrite "${oldFilename}" with "${file.name}"?`)) return;
        
        try {
            //  Fetch CURRENT file info to know who has access
            const dlResp = await fetch('/files/download', {
                method: 'POST', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ token: getToken(), record_id: recordId })
            });
            if (!dlResp.ok) throw new Error("Could not fetch existing access list");
            const existingData = await dlResp.json();
            
            // Since the backend now sends HASHED keys in existingData.wrapped_keys,
            // we cannot easily reverse them to usernames to re-encrypt.
            // However, in this specific app flow, we re-calculate candidates based on 
            // Appointed Doctors + Self.
            
            // RE-CALCULATE RECIPIENTS (Best Effort for Privacy Mode)
            // We give access to: Self + Any currently appointed doctors
            let existingRecipients = [user.username];
            try {
                const docs = await getAppointedDoctorsCached();
                docs.forEach(d => existingRecipients.push(d));
            } catch(e) {}
            
            //  Encrypt New Content
            const data = new Uint8Array(await file.arrayBuffer());
            const fileKey = await generateFileKey(); 
            const fileIv = crypto.getRandomValues(new Uint8Array(12));
            const encryptedFile = await encryptAes(fileKey, data, fileIv);

            // Use oldDate if available, else today
            const dateToUse = oldDate || new Date().toISOString().split('T')[0];

            const metaObj = { filename: file.name, date: dateToUse, filesize: file.size };
            const metaBytes = new TextEncoder().encode(JSON.stringify(metaObj));
            const metaIv = crypto.getRandomValues(new Uint8Array(12));
            const encryptedMeta = await encryptAes(fileKey, metaBytes, metaIv);
            
            const metaBlob = new Uint8Array(metaIv.length + encryptedMeta.byteLength);
            metaBlob.set(metaIv); metaBlob.set(new Uint8Array(encryptedMeta), 12);

            const toSign = new Uint8Array(metaBlob.byteLength + encryptedFile.byteLength);
            toSign.set(metaBlob); toSign.set(new Uint8Array(encryptedFile), metaBlob.byteLength);
            const signature = await signData(privKey, toSign);

            // 3. Wrap Keys 
            const wrapped = {};
            for (const recipient of existingRecipients) {
                try {
                    const pub = await getPinnedUserPubKey(recipient);
                    const shared = await deriveSharedKey(privKey, pub);
                    const wrapIv = crypto.getRandomValues(new Uint8Array(12));
                    const fileKeyRaw = await exportKeyRaw(fileKey);
                    const wrappedCt = await encryptAes(shared, fileKeyRaw, wrapIv);
                    
                    // Hash the username before using it as a key
                    const recipientHash = await sha256Hex(new TextEncoder().encode(recipient));
                    
                    wrapped[recipientHash] = { 
                        iv: arrayBufferToBase64(wrapIv.buffer), 
                        ct: arrayBufferToBase64(wrappedCt), 
                        file_iv: arrayBufferToBase64(fileIv.buffer) 
                    };

                } catch(e) { console.warn(`Could not re-wrap for ${recipient}`, e); }
            }

            const resp = await fetch('/files/update', {
                method: 'POST', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ 
                    token: getToken(), 
                    record_id: recordId, 
                    encrypted_metadata: arrayBufferToBase64(metaBlob.buffer), 
                    encrypted_blob: arrayBufferToBase64(encryptedFile), 
                    signature: arrayBufferToBase64(signature.buffer), 
                    wrapped_keys: wrapped 
                })
            });
            
            if (resp.ok) {
                alert("Updated.");
                refreshRecordList();
            } else {
                alert("Update failed: " + await resp.text());
            }
        } catch (e) { alert("Error: " + e.message); }
    };
    input.click();
}

init();