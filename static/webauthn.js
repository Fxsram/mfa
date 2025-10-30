// base64url -> ArrayBuffer
window.base64UrlToBuffer = function (b64url) {
  const pad = "=".repeat((4 - (b64url.length % 4)) % 4);
  const b64 = (b64url.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const str = atob(b64);
  const bytes = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i);
  return bytes.buffer;
};

// ArrayBuffer -> base64url
window.bufferToBase64Url = function (buf) {
  const bytes = new Uint8Array(buf);
  let str = "";
  for (let i = 0; i < bytes.byteLength; i++) str += String.fromCharCode(bytes[i]);
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

// CSRF cookie (Django)
window.getCookie = function (name) {
  const m = document.cookie.match(new RegExp("(^|; )" + name + "=([^;]*)"));
  return m ? decodeURIComponent(m[2]) : null;
};

// Feature guard
window.ensureWebAuthn = function () {
  if (!("credentials" in navigator) || typeof navigator.credentials.create !== "function") {
    throw new Error("WebAuthn not available (use HTTPS or http://localhost)");
  }
};
