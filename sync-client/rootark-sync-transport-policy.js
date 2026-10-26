"use strict";

// Credentials, device proofs and (in legacy mode) file bytes must never be
// sent to a non-loopback cleartext origin, even through a rolled-back config.
// The only HTTP compatibility allowance is a literal local development host.
const LOCAL_HTTP_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

function deny() {
  const error = new Error("SYNC_UNTRUSTED_SERVER_URL");
  error.code = error.message;
  throw error;
}

function normalizeTrustedSyncServerUrl(input) {
  if (typeof input !== "string" || input.length < 10 || input.length > 2048
    || input !== input.trim() || /[\x00-\x20\x7f\\?#]/.test(input)
    || !/^https?:\/\//i.test(input)) deny();
  let uri;
  try { uri = new URL(input); } catch (_) { deny(); }
  if (!uri.hostname || uri.username || uri.password || uri.search || uri.hash
    || (uri.protocol !== "https:" && (uri.protocol !== "http:"
      || !LOCAL_HTTP_HOSTS.has(uri.hostname.toLowerCase())))) deny();
  return uri.href.replace(/\/+$/, "");
}

module.exports = { normalizeTrustedSyncServerUrl };
