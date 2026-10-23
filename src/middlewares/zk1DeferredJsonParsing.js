"use strict";

// These opt-in routes authenticate before parsing their own bounded JSON bodies.
// Match Express's default case-insensitive, non-strict route registration so
// alternate path spellings cannot fall through to the global JSON parser.
const DEFERRED_PATHS = new Set([
  "/zk-1/v1/content/read",
  "/zk-1/v1/content/put",
  "/zk-1/v1/catalog/read",
  "/zk-1/v1/catalog/commit",
  "/zk-1/v1/catalog/authority/witness-head",
  "/zk-1/v1/catalog/authority/cas-head",
  "/zk-1/v1/multiprovider-restore/read",
]);

function shouldDeferZk1JsonParsing(req, { contentConfig, environment }) {
  if (!contentConfig || !["development", "test"].includes(environment)
    || req.method !== "POST" || typeof req.path !== "string") return false;
  const routePath = req.path.replace(/\/+$/, "").toLowerCase();
  return DEFERRED_PATHS.has(routePath);
}

module.exports = { shouldDeferZk1JsonParsing };
