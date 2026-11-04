"use strict";

// These are operator-pinned browser destinations, never request Origin/Host or
// URLs submitted in the browser form. Root.ark does not proxy their requests.
function parseIndependentCatalogConnectOrigins(raw) {
  if (raw === undefined || raw === "") return [];
  if (typeof raw !== "string" || raw.length > 2048) {
    throw new Error("Invalid ROOTARK_ZK1_INDEPENDENT_CATALOG_CONNECT_ORIGINS");
  }
  const values = raw.split(",");
  if (values.length > 8) {
    throw new Error("Too many independent catalog CSP origins");
  }
  const origins = new Set();
  for (const item of values) {
    const value = item.trim();
    let url;
    try { url = new URL(value); } catch {
      throw new Error("Invalid independent catalog CSP origin");
    }
    const loopback = ["127.0.0.1", "localhost", "[::1]"].includes(url.hostname);
    if (value !== url.origin || url.hostname.includes("*") || url.username || url.password
      || !(url.protocol === "https:" || (url.protocol === "http:" && loopback))) {
      throw new Error("Independent catalog CSP origin must be canonical HTTPS or loopback HTTP");
    }
    origins.add(value);
  }
  return [...origins];
}

module.exports = { parseIndependentCatalogConnectOrigins };
