const crypto = require("node:crypto");
const { getClientIp: resolveClientIp } = require("../middlewares/auth");
const {
  DEFAULT_WINDOW,
  PERIOD_SECONDS,
  decryptSecret,
  encryptSecret,
  generateRecoveryCodesAsync,
  generateSecret,
  normalizeOtp,
  verifyRecoveryCodeAsync,
  verifyTotp,
} = require("../services/totp");
const {
  getTotpPolicy,
  isTotpPolicyError,
  isTotpRequired,
  TOTP_POLICY_ERROR_MESSAGE,
} = require("../services/totpPolicy");
const { reserveLoginAttempt, getLoginRejection, getLoginSecurityState, registerFailedLoginAttempt, resetLoginUsernameState, getRetryAfterSeconds } = require("../services/loginProtection");

const loginChallenges = new Map();
const verificationAttemptsByIp = new Map();
const verificationAttemptsByUsername = new Map();
const totpConfirmationsInProgress = new Set();
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

// Async, non-mutating verification (recovery codes use async scrypt so the event loop is not blocked).
// The returned proof must be applied with commitTotpProof() on freshly loaded user data, synchronously, right before saving.
async function consumeTotpProof(user, code, key, allowRecovery = true) {
  const otp = normalizeOtp(code);
  if (otp) {
    let secret;
    try { secret = getEncryptedTotpSecret(user, key); } catch { return null; }
    const step = verifyTotp(secret, otp, { window: DEFAULT_WINDOW });
    if (step === null || Number.isSafeInteger(user.totpLastUsedStep) && step <= user.totpLastUsedStep) return null;
    return { type: "totp", step };
  }

  if (!allowRecovery || !Array.isArray(user.totpRecoveryHashes)) return null;
  for (const hash of [...user.totpRecoveryHashes]) {
    if (await verifyRecoveryCodeAsync(code, hash)) return { type: "recovery", hash };
  }
  return null;
}

// Synchronous single-use enforcement on the fresh user record; returns false if the proof was already consumed.
function commitTotpProof(target, proof) {
  if (!target || !proof) return false;
  if (proof.type === "totp") {
    if (Number.isSafeInteger(target.totpLastUsedStep) && proof.step <= target.totpLastUsedStep) return false;
    target.totpLastUsedStep = proof.step;
    return true;
  }
  if (proof.type === "recovery") {
    if (!Array.isArray(target.totpRecoveryHashes)) return false;
    const index = target.totpRecoveryHashes.indexOf(proof.hash);
    if (index === -1) return false;
    target.totpRecoveryHashes.splice(index, 1);
    return true;
  }
  return proof.type === "password";
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

function verificationRateLimit(req, username, onFirstRejection) {
  const now = Date.now();
  const maxAttempts = Math.max(5, Math.min(100, Number(process.env.TOTP_CHALLENGE_MAX_ATTEMPTS) || 10));
  cleanupVerificationRateStore(verificationAttemptsByIp, now, 5 * 60 * 1000);
  cleanupVerificationRateStore(verificationAttemptsByUsername, now, 5 * 60 * 1000);
  const ipState = getChallengeRateState(verificationAttemptsByIp, getRequestIp(req), now);
  const userState = username ? getChallengeRateState(verificationAttemptsByUsername, String(username).toLowerCase(), now) : null;
  const limitedStates = [ipState, userState].filter((state) => state?.attempts >= maxAttempts);
  if (limitedStates.length) {
    if (onFirstRejection && limitedStates.some((state) => !state.rateLimitAuditLogged)) {
      limitedStates.forEach((state) => { state.rateLimitAuditLogged = true; });
      onFirstRejection();
    }
    return false;
  }
  ipState.attempts += 1;
  if (userState) userState.attempts += 1;
  return true;
}

function claimLoginChallengeAudit(req, field) {
  const now = Date.now();
  cleanupVerificationRateStore(verificationAttemptsByIp, now, 5 * 60 * 1000);
  const state = getChallengeRateState(verificationAttemptsByIp, getRequestIp(req), now);
  if (state[field]) return false;
  state[field] = true;
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

async function requireAdminReauthentication(actor, body, key, bcrypt) {
  if (!actor || !await bcrypt.compare(String(body?.password || ""), actor.password || DUMMY_PASSWORD_HASH)) return null;
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

  app.post("/auth/login", async (req, res) => {
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
    let user = users.find((u) => u.username === username && !u.disabled);
    const passwordHash = user?.password || DUMMY_PASSWORD_HASH;
    // Reserve the attempt synchronously (no await since getLoginRejection) so concurrent requests count toward the limits.
    const reservation = reserveLoginAttempt(security);
    const verifiedSessionVersion = user ? (user.sessionVersion || 0) : 0;
    let passwordMatches = false;
    try { passwordMatches = await bcrypt.compare(String(password), passwordHash); } catch { passwordMatches = false; }

    // Re-validate against fresh data after the await: the account must still exist, be enabled and keep the same credentials.
    if (user && passwordMatches) {
      const current = loadUsers().find((u) => u.username === username && !u.disabled);
      passwordMatches = Boolean(current) && current.password === passwordHash && (current.sessionVersion || 0) === verifiedSessionVersion;
      user = passwordMatches ? current : null;
    }

    if (!user || !passwordMatches) {
      reservation.failure();
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

    reservation.success();
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

  app.post("/auth/login/2fa", async (req, res) => {
    cleanupChallenges();
    const challengeId = typeof req.body?.challengeId === "string" ? req.body.challengeId : "";
    const code = req.body?.code;
    const challenge = loginChallenges.get(challengeId);
    if (!verificationRateLimit(req, challenge?.username, () => {
      auditLog("auth.login.challenge.failed", getAuditActor(req, "anonymous"), { type: "auth", id: "login/2fa" }, "attempted", "failure", {
        reason: "rate_limited",
        ip: getRequestIp(req),
      });
    })) return genericTotpFailure(res, 429);
    if (!challenge || challenge.expiresAt <= Date.now() || challenge.attempts >= 5) {
      loginChallenges.delete(challengeId);
      if (claimLoginChallengeAudit(req, "invalidChallengeAuditLogged")) {
        auditLog("auth.login.challenge.failed", getAuditActor(req, "anonymous"), { type: "auth", id: "login/2fa" }, "attempted", "failure", {
          reason: "invalid_challenge",
          ip: getRequestIp(req),
        });
      }
      return genericTotpFailure(res);
    }
    challenge.attempts += 1;
    const user = loadUsers().find((entry) => entry.username === challenge.username && !entry.disabled && (entry.sessionVersion || 0) === challenge.sessionVersion);
    if (!user) {
      loginChallenges.delete(challengeId);
      auditLog("auth.login.challenge.failed", getAuditActor(req, "anonymous"), { type: "user", id: challenge.username }, "challenge", "failure", {
        reason: "account_unavailable",
        ip: getRequestIp(req),
      });
      return genericTotpFailure(res);
    }
    let proof;
    try { proof = await consumeTotpProof(user, code, totpKey()); } catch { proof = null; }
    // Re-load after the async work and enforce single use synchronously on the fresh record.
    const allUsers = loadUsers();
    const freshUser = allUsers.find((entry) => entry.username === challenge.username && !entry.disabled && (entry.sessionVersion || 0) === challenge.sessionVersion);
    if (!proof || !freshUser || !commitTotpProof(freshUser, proof)) {
      auditLog("auth.login.challenge.failed", getAuditActor(req, "anonymous"), { type: "user", id: challenge.username }, "challenge", "failure", { reason: "invalid_proof" });
      if (challenge.attempts >= 5) loginChallenges.delete(challengeId);
      return genericTotpFailure(res);
    }
    try { saveUsers(allUsers); } catch {
      return sensitiveAuthResponse(res).status(503).json({ error: "Autenticacao indisponivel." });
    }
    loginChallenges.delete(challengeId);
    const token = issueSession({ req, res, user: freshUser, context });
    auditLog("auth.login.challenge.success", getAuditActor(req, user.username), { type: "user", id: user.username }, "challenge", "success", { method: proof.type });
    sensitiveAuthResponse(res).json({ token, username: freshUser.username, role: freshUser.role, permissions: normalizeUserPermissions(freshUser) });
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

  app.post("/auth/2fa/confirm", authenticate, async (req, res) => {
    const users = loadUsers();
    const user = users.find((entry) => entry.username === req.user.username);
    if (!verificationRateLimit(req, user?.username)) return genericTotpFailure(res, 429);
    if (!user?.totpPendingSecret || !Number.isFinite(user.totpPendingSecret.createdAt) || Date.now() - user.totpPendingSecret.createdAt > 10 * 60 * 1000) return genericTotpFailure(res, 400);
    let reservedUsername;
    try {
      const verifiedHash = user.password;
      const verifiedVersion = user.sessionVersion || 0;
      const pendingSecretRecord = JSON.stringify(user.totpPendingSecret);
      const key = totpKey();
      const secret = getEncryptedTotpSecret(user, key, true);
      const step = verifyTotp(secret, req.body?.code, { window: DEFAULT_WINDOW });
      if (step === null) return genericTotpFailure(res, 400);
      const confirmationKey = String(user.username);
      if (totpConfirmationsInProgress.has(confirmationKey)) return genericTotpFailure(res, 429);
      totpConfirmationsInProgress.add(confirmationKey);
      reservedUsername = confirmationKey;
      const recovery = await generateRecoveryCodesAsync();
      const freshUsers = loadUsers();
      const freshUser = freshUsers.find((entry) => entry.username === user.username);
      if (!freshUser || freshUser.disabled || freshUser.password !== verifiedHash || (freshUser.sessionVersion || 0) !== verifiedVersion || freshUser.totpEnabled || JSON.stringify(freshUser.totpPendingSecret) !== pendingSecretRecord || !Number.isFinite(freshUser.totpPendingSecret?.createdAt) || Date.now() - freshUser.totpPendingSecret.createdAt > 10 * 60 * 1000) {
        return genericTotpFailure(res, 400);
      }
      freshUser.totpSecret = freshUser.totpPendingSecret;
      freshUser.totpPendingSecret = null;
      freshUser.totpEnabled = true;
      freshUser.totpRecoveryHashes = recovery.hashes;
      freshUser.totpLastUsedStep = step;
      freshUser.totpEnrolledAt = new Date().toISOString();
      freshUser.sessionVersion = (freshUser.sessionVersion || 0) + 1;
      saveUsers(freshUsers);
      auditLog("auth.2fa.enabled", getAuditActor(req), { type: "user", id: freshUser.username }, "enabled", "success", { recoveryCodeCount: recovery.codes.length });
      return sensitiveAuthResponse(res).json({ enabled: true, recoveryCodes: recovery.codes, loginRequired: true });
    } catch {
      return sensitiveAuthResponse(res).status(503).json({ error: "2FA indisponivel." });
    } finally {
      if (reservedUsername) totpConfirmationsInProgress.delete(reservedUsername);
    }
  });

  app.post("/auth/2fa/disable", authenticate, async (req, res) => {
    let users = loadUsers();
    let user = users.find((entry) => entry.username === req.user.username);
    if (!verificationRateLimit(req, user?.username)) return genericTotpFailure(res, 429);
    const verifiedHash = user?.password;
    const verifiedVersion = user?.sessionVersion || 0;
    let passwordOk = false;
    try { passwordOk = await bcrypt.compare(String(req.body?.password || ""), user?.password || DUMMY_PASSWORD_HASH); } catch { passwordOk = false; }
    if (!user?.totpEnabled || !passwordOk) return genericTotpFailure(res);
    try {
      const key = totpKey();
      const proof = await consumeTotpProof(user, req.body?.code, key);
      if (!proof) return genericTotpFailure(res);
      const freshUsers = loadUsers();
      const freshUser = freshUsers.find((entry) => entry.username === user.username);
      if (!freshUser?.totpEnabled || freshUser.disabled || freshUser.password !== verifiedHash || (freshUser.sessionVersion || 0) !== verifiedVersion || !commitTotpProof(freshUser, proof)) return genericTotpFailure(res);
      user = freshUser;
      users = freshUsers;
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

  app.post("/users/:username/2fa/reset", authenticate, requirePermission("manageUsers"), async (req, res) => {
    const users = loadUsers();
    const actor = users.find((entry) => entry.username === req.user.username);
    const user = users.find((entry) => entry.username === req.params.username);
    if (!user) return sensitiveAuthResponse(res).status(404).json({ error: "Usuario nao encontrado" });
    if (user.role === "admin" && req.user.role !== "admin") {
      return sensitiveAuthResponse(res).status(403).json({ error: "Somente administradores podem alterar administradores" });
    }
    const totpPolicy = getRuntimeTotpPolicy(res);
    if (!totpPolicy) return;
    if (!verificationRateLimit(req, actor?.username)) return genericTotpFailure(res, 429);
    const actorVersion = actor?.sessionVersion || 0;
    let proof;
    try { proof = await requireAdminReauthentication(actor, req.body, actor?.totpEnabled ? totpKey() : null, bcrypt); } catch { proof = null; }
    const freshUsers = loadUsers();
    const freshActor = freshUsers.find((entry) => entry.username === req.user.username);
    const freshTarget = freshUsers.find((entry) => entry.username === req.params.username);
    // Re-check authorization on the fresh records after the async re-authentication.
    if (proof && (!freshActor || freshActor.disabled || (freshActor.sessionVersion || 0) !== actorVersion || !normalizeUserPermissions(freshActor).manageUsers)) {
      return sensitiveAuthResponse(res).status(403).json({ error: "Permissao negada" });
    }
    if (proof && freshTarget && freshTarget.role === "admin" && freshActor.role !== "admin") {
      return sensitiveAuthResponse(res).status(403).json({ error: "Somente administradores podem alterar administradores" });
    }
    if (!proof || !freshActor || !freshTarget || !commitTotpProof(freshActor, proof)) {
      auditLog("auth.2fa.admin_reset", getAuditActor(req), { type: "user", id: user.username }, "reset", "failure", { reason: "reauthentication_failed" });
      return genericTotpFailure(res);
    }
    freshTarget.totpEnabled = false;
    freshTarget.totpSecret = null;
    freshTarget.totpPendingSecret = null;
    freshTarget.totpRecoveryHashes = [];
    freshTarget.totpLastUsedStep = null;
    freshTarget.totpEnrolledAt = null;
    freshTarget.sessionVersion = (freshTarget.sessionVersion || 0) + 1;
    saveUsers(freshUsers);
    auditLog("auth.2fa.admin_reset", getAuditActor(req), { type: "user", id: freshTarget.username }, "reset", "success", { resetBy: req.user.username, method: proof.type });
    return sensitiveAuthResponse(res).json({ enabled: false, enrollmentRequired: isTotpRequired(freshTarget, totpPolicy), loginRequired: true });
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
      const users = loadUsers({ failOnDatabaseError: true, allowJsonFallback: false });
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
