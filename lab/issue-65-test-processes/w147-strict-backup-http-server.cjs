"use strict";
// Disposable REAL auth/JWT and backup ROUTE fixture; does not bootstrap the
// production server's unrelated queues, sockets, crypto provisioning and timers.
const bcrypt = require("bcryptjs");
const crypto = require("node:crypto");
const express = require("express");
const fs = require("node:fs");
const jwt = require("jsonwebtoken");
const path = require("node:path");
const { createAuthenticate } = require("../../src/middlewares/auth");
const registerAuthRoutes = require("../../src/routes/auth");
const registerBackupRoutes = require("../../src/routes/backups");
const backupService = require("../../services/backupService");
const restoreService = require("../../services/restoreService");

const secret = process.env.JWT_SECRET;
const loadUsers = () => JSON.parse(fs.readFileSync(path.join("data", "users.json"), "utf8"));
const normalizeUserPermissions = (entry) => entry.permissions || {};
const authenticate = createAuthenticate({ jwt, jwtSecret: secret,
  loadUser: (username) => loadUsers().find((user) => user.username === username),
  normalizeUserPermissions });
const requirePermission = (permission) => (req, res, next) => req.user?.permissions?.[permission]
  ? next() : res.status(403).json({ error: "permission denied" });
const app = express();
app.use(express.json());
registerAuthRoutes(app, { authenticate, auditLog: () => {}, bcrypt, checkAnomalies: () => {},
  getAuditActor: (_req, username) => ({ username, ip: "127.0.0.1", role: "user" }),
  jwt, jwtSecret: secret, loadUsers, saveUsers: () => {},
  getTotpKey: () => crypto.randomBytes(32), logAnalyticsEvent: () => {},
  normalizeUserPermissions, qrcode: {}, requirePermission,
  sessionCookieOptions: { httpOnly: true, sameSite: "lax" } });
registerBackupRoutes(app, {
  auditLog: () => {}, authenticate, backupService, restoreService,
  getAuditActor: (req) => ({ username: req.user.username, role: "user" }),
  requireBackupAccess: (req, res, next) => req.user.permissions.manageBackups
    ? next() : res.status(403).json({ error: "permission denied" }),
  revalidateBackupAccess: async () => null,
  waitForRequestQuiescence: async () => {},
});
app.get("/health", (_req, res) => res.json({ ok: true }));
const server = app.listen(Number(process.env.PORT), "127.0.0.1", () => {
  console.log("ready");
});
process.once("SIGTERM", () => server.close(() => process.exit(0)));
