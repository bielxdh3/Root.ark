"use strict";

const CACHE_NAME = "rootark-public-shell-v17";
const SHELL_ASSETS = [
  "/",
  "/index.html",
  "/login.html",
  "/dashboard.html",
  "/audit.html",
  "/admin.html",
  "/backups.html",
  "/styles/app.css",
  "/client/rootark-api.js",
  "/client/rootark-ui.js",
  "/client/rootark-login.js",
  "/client/rootark-workspace.js",
  "/client/rootark-management.js",
  "/client/rootark-offline-shell.js",
  "/client/rootark-bootstrap.js",
  "/client/rootark-client-crypto.js",
  "/client/rootark-protected-index.js",
  "/client/rootark-protected-preview.js",
  "/client/rootark-protected-store.js",
  "/client/rootark-protected-session.js",
  "/client/rootark-sync-adapter.js",
  "/client/rootark-offline-queue.js",
  "/assets/logo.svg",
  "/manifest.webmanifest",
];
const BLOCKED_PATHS = [/^\/auth(?:\/|$)/, /^\/api(?:\/|$)/, /^\/files(?:\/|$)/, /^\/preview(?:\/|$)/, /^\/sync(?:\/|$)/, /^\/encrypted(?:\/|$)/, /^\/open-file(?:\/|$)/, /^\/share(?:\/|$)/, /^\/users(?:\/|$)/, /^\/groups(?:\/|$)/, /^\/folders(?:\/|$)/, /^\/list(?:\/|$)/];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_ASSETS)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (event) => {
  event.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key)))).then(() => self.clients.claim()));
});

self.addEventListener("fetch", (event) => {
  const request = event.request;
  const url = new URL(request.url);
  if (request.method !== "GET" || url.origin !== self.location.origin || BLOCKED_PATHS.some((pattern) => pattern.test(url.pathname))) return;
  if (!SHELL_ASSETS.some((asset) => new URL(asset, self.location.origin).pathname === url.pathname)) return;
  event.respondWith(caches.match(request).then((cached) => cached || fetch(request).then((response) => {
    if (response.ok) caches.open(CACHE_NAME).then((cache) => cache.put(request, response.clone()));
    return response;
  })));
});
