// static/js/auth.js

function setTokenCookie(token) {
  // Ideally, servers should set HttpOnly cookies. 
  // Since we are client-side only here, we use Secure/SameSite strict.

  const isHttps = window.location.protocol === "https:";
  const securePart = isHttps ? " Secure;" : "";

  document.cookie = `ssd_token=${encodeURIComponent(token)}; path=/;${securePart} SameSite=Strict; Max-Age=3600`;
  sessionStorage.setItem("ssd_token", token);
}


function getToken() {
  const c = document.cookie.split('; ').find(r => r.startsWith('ssd_token='));
  if (c) return decodeURIComponent(c.split('=')[1]);
  return sessionStorage.getItem("ssd_token");
}

function clearToken() {
  const isHttps = window.location.protocol === "https:";
  const securePart = isHttps ? " Secure;" : "";
  
  document.cookie = `ssd_token=; Max-Age=0; path=/;${securePart} SameSite=Strict`;
  sessionStorage.removeItem("ssd_token");
}

function logout() {
  clearToken();
  window.location.href = '/login.html';
}

function downloadBlob(name, blob) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = name; a.click();
  URL.revokeObjectURL(url);
}