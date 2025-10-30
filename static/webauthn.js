// Utilities used by templates; duplicate functions for portability
function bufferToBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let str = "";
  for (const ch of bytes) str += String.fromCharCode(ch);
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function base64UrlToBuffer(base64url) {
  const padding = "=".repeat((4 - base64url.length % 4) % 4);
  const base64 = (base64url + padding).replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(base64);
  const buf = new ArrayBuffer(raw.length);
  const arr = new Uint8Array(buf);
  for (let i = 0; i < raw.length; ++i) arr[i] = raw.charCodeAt(i);
  return buf;
}
function getCookie(name) {
  const v = document.cookie.match('(^|;)\s*' + name + '\s*=\s*([^;]+)');
  return v ? v.pop() : '';
}