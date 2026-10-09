const crypto = require("node:crypto");
const { getClientIp: resolveClientIp } = require("../middlewares/auth");
const {
  DEFAULT_WINDOW,
  PERIOD_SECONDS,
  decryptSecret,
  encryptSecret,
  generateRecoveryCodes,
  generateSecret,
  normalizeOtp,
  verifyRecoveryCode,
  verifyTotp,
} = require("../services/totp");
const {
  getTotpPolicy,
  isTotpPolicyError,
  isTotpRequired,
  TOTP_POLICY_ERROR_MESSAGE,
} = require("../services/totpPolicy");
const { getLoginRejection, getLoginSecurityState, registerFailedLoginAttempt, resetLoginUsernameState, getRetryAfterSeconds } = require("../services/loginProtection");

const loginChallenges = new Map();
const verificationAttemptsByIp = new Map();
const verificationAttemptsByUsername = new Map();
const DUMMY_PASSWORD_HASH = "$2a$10$C8U56P8wZK.G7zWKmqF88e3f64PIxJ1xdTJN9WxiHcSVkYCfaSeDG";

function sensitiveAuthResponse(res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
  return res;
}

function sendLoginProtectionError(res, statusCode, retryAfterSeconds) {
  if (retryAfterSeconds) res.setHeader("Retry-After", String(retryAfterSeconds));
  return sensitiveAuthResponse(res).status(statusCode).json({ error: "Invalid credentials or temporarily blocked." });
}

function getTotpKey(getKey) {
  try {
    const key = getKey();
    if (!Buffer.isBuffer(key) || key.length !== 32) throw new Error("invalid key");
    return key;
  } catch {
    throw new Error("TOTP unavailable");
  }
}

function getEncryptedTotpSecret(user, key, pending = false) {
  const record = pending ? user.totpPendingSecret : user.totpSecret;
  return decryptSecret(record, key, `Root.ark/TOTP/${user.username}`);
}

function consumeTotpProof(user, code, key, allowRecovery = true) {
  const otp = normalizeOtp(code);
  if (otp) {
    let secret;
    try { secret = getEncryptedTotpSecret(user, key); } catch { return null; }
    const step = verifyTotp(secret, otp, { window: DEFAULT_WINDOW });
    if (step === null || Number.isSafeInteger(user.totpLastUsedStep) && step <= user.totpLastUsedStep) return null;
    user.totpLastUsedStep = step;
    return { type: "totp", step };
  }

  if (!allowRecovery || !Array.isArray(user.totpRecoveryHashes)) return null;
  const index = user.totpRecoveryHashes.findIndex((hash) => verifyRecoveryCode(code, hash));
  if (index === -1) return null;
  user.totpRecoveryHashes.splice(index, 1);
  return { type: "recovery" };
}

function issueSession({ req, res, user, context, enrollmentOnly = false }) {
  const { auditLog, checkAnomalies, getAuditActor, jwt, jwtSecret, logAnalyticsEvent, normalizeUserPermissions, sessionCookieOptions } = context;
  const token = jwt.sign(
    { username: user.username, sessionVersion: user.sessionVersion || 0, ...(enrollmentOnly ? { totpEnrollment: true } : {}) },
    jwtSecret,
    { algorithm: "HS256", expiresIn: enrollmentOnly ? "15m" : "8h" }
  );
  if (!enrollmentOnly) {
    logAnalyticsEvent("login", { username: user.username, ip: getAuditActor(req, user.username).ip });
    auditLog("auth.login.success", getAuditActor(req, user.username), { type: "user", id: user.username }, "authenticated", "success", {
      username: user.username,
      role: user.role,
      tokenExpiry: "8h",
    });
    checkAnomalies(req, user.username);
    const csrfToken = crypto.randomBytes(32).toString("base64url");
    res.cookie("rootark_session", token, sessionCookieOptions);
    res.cookie("rootark_csrf", csrfToken, { ...sessionCookieOptions, httpOnly: false });
  }
  return token;
}

function cleanupChallenges(now = Date.now()) {
  for (const [id, challenge] of loginChallenges) if (challenge.expiresAt <= now) loginChallenges.delete(id);
}

function cleanupVerificationRateStore(store, now, windowMs) {
  for (const [key, state] of store) if (now - state.windowStart >= windowMs) store.delete(key);
}

function getChallengeRateState(store, key, now) {
  let state = store.get(key);
  if (!state || now - state.windowStart >= state.windowMs) {
    state = { attempts: 0, windowStart: now, windowMs: 5 * 60 * 1000 };
    store.set(key, state);
  }
  return state;
}

function getRequestIp(req) {
  return String(resolveClientIp(req) || "unknown");
}

function verificationRateLimit(req, username) {
  const now = Date.now();
  const maxAttempts = Math.max(5, Math.min(100, Number(process.env.TOTP_CHALLENGE_MAX_ATTEMPTS) || 10));
  cleanupVerificationRateStore(verificationAttemptsByIp, now, 5 * 60 * 1000);
  cleanupVerificationRateStore(verificationAttemptsByUsername, now, 5 * 60 * 1000);
  const ipState = getChallengeRateState(verificationAttemptsByIp, getRequestIp(req), now);
  const userState = username ? getChallengeRateState(verificationAttemptsByUsername, String(username).toLowerCase(), now) : null;
  if (ipState.attempts >= maxAttempts || userState?.attempts >= maxAttempts) return false;
  ipState.attempts += 1;
  if (userState) userState.attempts += 1;
  return true;
}

function genericTotpFailure(res, status = 401) {
  return sensitiveAuthResponse(res).status(status).json({ error: "Autenticacao de dois fatores invalida." });
}

function getRuntimeTotpPolicy(res) {
  try {
    return getTotpPolicy();
  } catch (error) {
    if (!isTotpPolicyError(error)) throw error;
    sensitiveAuthResponse(res).status(503).json({ error: TOTP_POLICY_ERROR_MESSAGE });
    return null;
  }
}

function requireAdminReauthentication(actor, body, key, bcrypt) {
  if (!actor || !bcrypt.compareSync(String(body?.password || ""), actor.password || DUMMY_PASSWORD_HASH)) return null;
  if (!actor.totpEnabled) return { type: "password" };
  return consumeTotpProof(actor, body?.code, key);
}

function registerAuthRoutes(app, context) {
  const {
    authenticate,
    auditLog,
    bcrypt,
    checkAnomalies,
    getAuditActor,
    jwt,
    jwtSecret,
    loadUsers,
    saveUsers,
    getTotpKey,
    logAnalyticsEvent,
    normalizeUserPermissions,
    qrcode,
    requirePermission,
    sessionCookieOptions,
  } = context;

  const totpKey = () => getTotpKey();
  const challengeTtlMs = Math.max(60 * 1000, Math.min(10 * 60 * 1000, Number(process.env.TOTP_CHALLENGE_TTL_MS) || 5 * 60 * 1000));

  app.post("/auth/login", (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
      return sensitiveAuthResponse(res).status(400).json({ error: "Usuario e senha obrigatorios" });
    }

    const security = getLoginSecurityState(req, username, getAuditActor);
    const { actor, config, ip, ipState, normalizedUsername, usernameState, now } = security;
    const rejection = getLoginRejection(security);
    if (rejection) {
      const eventType = rejection.reason === "blocked" ? "auth.login.blocked" : "auth.login.rate_limited";
      auditLog(eventType, actor, { type: "auth", id: username || "unknown_user" }, "attempted", "failure", {
        reason: rejection.reason,
        attemptedUsername: username || "",
        ip,
        retryAfterSeconds: rejection.retryAfter,
      });
      return sendLoginProtectionError(res, 429, rejection.retryAfter);
    }

    const users = loadUsers();
    const user = users.find((u) => u.username === username && !u.disabled);
    const passwordHash = user?.password || DUMMY_PASSWORD_HASH;
    const passwordMatches = bcrypt.compareSync(password, passwordHash);

    if (!user || !passwordMatches) {
      ipState.attempts += 1;
      registerFailedLoginAttempt(ipState, now, config);
      registerFailedLoginAttempt(usernameState, now, config);
      const retryAfter = getRetryAfterSeconds(ipState, usernameState);
      const blocked = Boolean(
        (ipState.blockedUntil && ipState.blockedUntil > now) ||
        (usernameState?.blockedUntil && usernameState.blockedUntil > now)
      );

      auditLog(blocked ? "auth.login.blocked" : "auth.login.failed", actor, {
        type: "auth",
        id: username || "unknown_user",
      }, "attempted", "failure", {
        reason: blocked ? "block_threshold" : "invalid_credentials",
        attemptedUsername: username || "",
        ip,
        retryAfterSeconds: retryAfter,
      });
      return sendLoginProtectionError(res, blocked ? 429 : 401, retryAfter);
    }

    resetLoginUsernameState(security);

    const totpPolicy = getRuntimeTotpPolicy(res);
    if (!totpPolicy) return;
    cleanupChallenges(now);
    if (user.totpEnabled) {
      try { getEncryptedTotpSecret(user, totpKey()); } catch {
        auditLog("auth.login.failed", getAuditActor(req, user.username), { type: "user", id: user.username }, "challenge", "failure", { reason: "totp_unavailable" });
        return sensitiveAuthResponse(res).status(503).json({ error: "Autenticacao indisponivel." });
      }
      const challengeId = crypto.randomBytes(32).toString("base64url");
      loginChallenges.set(challengeId, { username: user.username, sessionVersion: user.sessionVersion || 0, expiresAt: now + challengeTtlMs, attempts: 0 });
      auditLog("auth.login.challenge", getAuditActor(req, user.username), { type: "user", id: user.username }, "challenge", "pending", { expiresInMs: challengeTtlMs });
      return sensitiveAuthResponse(res).json({ challengeRequired: true, challengeId, expiresIn: Math.ceil(challengeTtlMs / 1000) });
    }

    if (isTotpRequired(user, totpPolicy)) {
      const token = issueSession({ req, res, user, context, enrollmentOnly: true });
      return sensitiveAuthResponse(res).status(403).json({ enrollmentRequired: true, token, username: user.username, expiresIn: 900 });
    }

    const token = issueSession({ req, res, user, context });
    sensitiveAuthResponse(res).json({ token, username: user.username, role: user.role, permissions: normalizeUserPermissions(user) });
  });

  app.post("/auth/login/2fa", (req, res) => {
    cleanupChallenges();
    const challengeId = typeof req.body?.challengeId === "string" ? req.body.challengeId : "";
    const code = req.body?.code;
    const challenge = loginChallenges.get(challengeId);
    if (!verificationRateLimit(req, challenge?.username)) return genericTotpFailure(res, 429);
    if (!challenge || challenge.expiresAt <= Date.now() || challenge.attempts >= 5) {
      loginChallenges.delete(challengeId);
      return genericTotpFailure(res);
    }
    challenge.attempts += 1;
    const user = loadUsers().find((entry) => entry.username === challenge.username && !entry.disabled && (entry.sessionVersion || 0) === challenge.sessionVersion);
    if (!user) return genericTotpFailure(res);
    let proof;
    try { proof = consumeTotpProof(user, code, totpKey()); } catch { proof = null; }
    if (!proof) {
      auditLog("auth.login.challenge.failed", getAuditActor(req, challenge.username), { type: "user", id: challenge.username }, "challenge", "failure", { reason: "invalid_proof" });
      if (challenge.attempts >= 5) loginChallenges.delete(challengeId);
      return genericTotpFailure(res);
    }
    try { saveUsers(loadUsers().map((entry) => entry.username === user.username ? user : entry)); } catch {
      return sensitiveAuthResponse(res).status(503).json({ error: "Autenticacao indisponivel." });
    }
    loginChallenges.delete(challengeId);
    const token = issueSession({ req, res, user, context });
    auditLog("auth.login.challenge.success", getAuditActor(req, user.username), { type: "user", id: user.username }, "challenge", "success", { method: proof.type });
    sensitiveAuthResponse(res).json({ token, username: user.username, role: user.role, permissions: normalizeUserPermissions(user) });
  });

  app.get("/auth/2fa/policy", authenticate, (req, res) => {
    const policy = getRuntimeTotpPolicy(res);
    if (!policy) return;
    sensitiveAuthResponse(res).json({ mode: policy.mode, requiredRoles: [...policy.roles] });
  });

  app.get("/auth/2fa/status", authenticate, (req, res) => {
    const policy = getRuntimeTotpPolicy(res);
    if (!policy) return;
    const required = isTotpRequired(req.user, policy);
    sensitiveAuthResponse(res).json({ enabled: Boolean(req.user.totpEnabled), required, enrollmentRequired: required && !req.user.totpEnabled });
  });

  app.post("/auth/2fa/enroll", authenticate, async (req, res) => {
    const users = loadUsers();
    const user = users.find((entry) => entry.username === req.user.username);
    if (!user || user.totpEnabled) return sensitiveAuthResponse(res).status(409).json({ error: "2FA ja configurado." });
    try {
      const secret = generateSecret();
      user.totpPendingSecret = { ...encryptSecret(secret, totpKey(), `Root.ark/TOTP/${user.username}`), createdAt: Date.now() };
      saveUsers(users);
      const issuer = String(process.env.TOTP_ISSUER || "Root.ark").trim() || "Root.ark";
      const otpauthUri = `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(user.username)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=${PERIOD_SECONDS}`;
      const qrCode = await context.qrcode.toDataURL(otpauthUri, { errorCorrectionLevel: "M" });
      auditLog("auth.2fa.enrollment.started", getAuditActor(req), { type: "user", id: user.username }, "started", "success", { algorithm: "SHA1", digits: 6, period: PERIOD_SECONDS });
      return sensitiveAuthResponse(res).json({ secret, otpauthUri, qrCode, expiresIn: 10 * 60 });
    } catch {
      auditLog("auth.2fa.enrollment.failed", getAuditActor(req), { type: "user", id: user.username }, "started", "failure", { reason: "key_unavailable" });
      return sensitiveAuthResponse(res).status(503).json({ error: "2FA indisponivel." });
    }
  });

  app.post("/auth/2fa/confirm", authenticate, (req, res) => {
    const users = loadUsers();
    const user = users.find((entry) => entry.username === req.user.username);
    if (!verificationRateLimit(req, user?.username)) return genericTotpFailure(res, 429);
    if (!user?.totpPendingSecret || !Number.isFinite(user.totpPendingSecret.createdAt) || Date.now() - user.totpPendingSecret.createdAt > 10 * 60 * 1000) return genericTotpFailure(res, 400);
    try {
      const key = totpKey();
      const secret = getEncryptedTotpSecret(user, key, true);
      const step = verifyTotp(secret, req.body?.code, { window: DEFAULT_WINDOW });
      if (step === null) return genericTotpFailure(res, 400);
      const recovery = generateRecoveryCodes();
      user.totpSecret = user.totpPendingSecret;
      user.totpPendingSecret = null;
      user.totpEnabled = true;
      user.totpRecoveryHashes = recovery.hashes;
      user.totpLastUsedStep = step;
      user.totpEnrolledAt = new Date().toISOString();
      user.sessionVersion = (user.sessionVersion || 0) + 1;
      saveUsers(users);
      auditLog("auth.2fa.enabled", getAuditActor(req), { type: "user", id: user.username }, "enabled", "success", { recoveryCodeCount: recovery.codes.length });
      return sensitiveAuthResponse(res).json({ enabled: true, recoveryCodes: recovery.codes, loginRequired: true });
    } catch {
      return sensitiveAuthResponse(res).status(503).json({ error: "2FA indisponivel." });
    }
  });

  app.post("/auth/2fa/disable", authenticate, (req, res) => {
    const users = loadUsers();
    const user = users.find((entry) => entry.username === req.user.username);
    if (!verificationRateLimit(req, user?.username)) return genericTotpFailure(res, 429);
    if (!user?.totpEnabled || !bcrypt.compareSync(String(req.body?.password || ""), user.password || DUMMY_PASSWORD_HASH)) return genericTotpFailure(res);
    try {
      const key = totpKey();
      const proof = consumeTotpProof(user, req.body?.code, key);
      if (!proof) return genericTotpFailure(res);
      user.totpEnabled = false;
      user.totpSecret = null;
      user.totpPendingSecret = null;
      user.totpRecoveryHashes = [];
      user.totpLastUsedStep = null;
      user.totpEnrolledAt = null;
      user.sessionVersion = (user.sessionVersion || 0) + 1;
      saveUsers(users);
      res.clearCookie("rootark_session", sessionCookieOptions);
      res.clearCookie("rootark_csrf", sessionCookieOptions);
      auditLog("auth.2fa.disabled", getAuditActor(req), { type: "user", id: user.username }, "disabled", "success", { method: proof.type });
      return sensitiveAuthResponse(res).json({ enabled: false, loginRequired: true });
    } catch {
      return sensitiveAuthResponse(res).status(503).json({ error: "2FA indisponivel." });
    }
  });

  app.post("/users/:username/2fa/reset", authenticate, requirePermission("manageUsers"), (req, res) => {
    const users = loadUsers();
    const actor = users.find((entry) => entry.username === req.user.username);
    const user = users.find((entry) => entry.username === req.params.username);
    if (!user) return sensitiveAuthResponse(res).status(404).json({ error: "Usuario nao encontrado" });
    const totpPolicy = getRuntimeTotpPolicy(res);
    if (!totpPolicy) return;
    if (!verificationRateLimit(req, actor?.username)) return genericTotpFailure(res, 429);
    let proof;
    try { proof = requireAdminReauthentication(actor, req.body, actor?.totpEnabled ? totpKey() : null, bcrypt); } catch { proof = null; }
    if (!proof) {
      auditLog("auth.2fa.admin_reset", getAuditActor(req), { type: "user", id: user.username }, "reset", "failure", { reason: "reauthentication_failed" });
      return genericTotpFailure(res);
    }
    user.totpEnabled = false;
    user.totpSecret = null;
    user.totpPendingSecret = null;
    user.totpRecoveryHashes = [];
    user.totpLastUsedStep = null;
    user.totpEnrolledAt = null;
    user.sessionVersion = (user.sessionVersion || 0) + 1;
    saveUsers(users);
    auditLog("auth.2fa.admin_reset", getAuditActor(req), { type: "user", id: user.username }, "reset", "success", { resetBy: req.user.username, method: proof.type });
    return sensitiveAuthResponse(res).json({ enabled: false, enrollmentRequired: isTotpRequired(user, totpPolicy), loginRequired: true });
  });

  app.get("/auth/me", authenticate, (req, res) => {
    res.json({
      username: req.user.username,
      role: req.user.role,
      permissions: normalizeUserPermissions(req.user),
    });
  });

  app.post("/auth/logout", authenticate, (req, res) => {
    try {
      const users = loadUsers();
      const user = users.find((entry) => entry.username === req.user.username);
      if (user && !user.disabled && (user.sessionVersion || 0) === req.user.sessionVersion) {
        user.sessionVersion = (user.sessionVersion || 0) + 1;
        saveUsers(users);
      }
    } catch {
      return sensitiveAuthResponse(res).status(503).json({ error: "Sessao nao pode ser revogada agora." });
    }
    res.clearCookie("rootark_session", sessionCookieOptions);
    res.clearCookie("rootark_csrf", sessionCookieOptions);
    res.status(204).end();
  });
}

module.exports = registerAuthRoutes;
