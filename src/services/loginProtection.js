"use strict";

const { getClientIp: resolveClientIp } = require("../middlewares/auth");

const loginAttemptsByIp = new Map();
const loginAttemptsByUsername = new Map();

function getLoginSecurityConfig() {
  const getEnvNumber = (name, fallback) => {
    const value = Number(process.env[name]);
    return Number.isFinite(value) && value >= 0 ? value : fallback;
  };
  return {
    windowMs: getEnvNumber("LOGIN_RATE_LIMIT_WINDOW", 60) * 1000,
    maxAttempts: getEnvNumber("LOGIN_RATE_LIMIT_MAX", 5),
    blockThreshold: getEnvNumber("LOGIN_BLOCK_THRESHOLD", 10),
    blockDurationMs: getEnvNumber("LOGIN_BLOCK_DURATION", 900) * 1000,
    delayBaseMs: getEnvNumber("LOGIN_DELAY_BASE", 1) * 1000,
  };
}

function normalizeLoginUsername(username) {
  return String(username || "").trim().toLowerCase();
}

function getLoginState(store, key, now, config) {
  const safeKey = key || "unknown";
  let state = store.get(safeKey);
  if (!state) {
    state = { attempts: 0, failures: 0, pending: 0, windowStart: now, blockedUntil: 0, nextAllowedAt: 0 };
    store.set(safeKey, state);
  }
  if (now - state.windowStart >= config.windowMs) {
    state.attempts = 0;
    state.windowStart = now;
  }
  if (state.blockedUntil && state.blockedUntil <= now) {
    state.blockedUntil = 0;
    state.failures = 0;
    state.nextAllowedAt = 0;
  }
  return state;
}

function pruneLoginStore(store, now, config) {
  for (const [key, state] of store.entries()) {
    const latestActivity = Math.max(state.windowStart || 0, state.blockedUntil || 0, state.nextAllowedAt || 0);
    const inactiveFor = now - latestActivity;
    if (!state.blockedUntil && !state.pending && inactiveFor > Math.max(config.windowMs * 4, config.blockDurationMs * 2, 5 * 60 * 1000)) store.delete(key);
  }
}

function getLoginSecurityState(req, username, getAuditActor) {
  const config = getLoginSecurityConfig();
  const now = Date.now();
  const actor = getAuditActor(req, "anonymous");
  const ip = actor?.ip || resolveClientIp(req) || "unknown";
  const normalizedUsername = normalizeLoginUsername(username);
  pruneLoginStore(loginAttemptsByIp, now, config);
  pruneLoginStore(loginAttemptsByUsername, now, config);
  return {
    actor,
    config,
    ip,
    ipState: getLoginState(loginAttemptsByIp, ip, now, config),
    normalizedUsername,
    usernameState: normalizedUsername ? getLoginState(loginAttemptsByUsername, normalizedUsername, now, config) : null,
    now,
  };
}

function getLoginRejection({ config, ipState, usernameState, now }) {
  const blockedState = [ipState, usernameState].find((state) => state?.blockedUntil && state.blockedUntil > now);
  if (blockedState) return { reason: "blocked", retryAfter: getRetryAfterSeconds(ipState, usernameState) };
  // In-flight (reserved) attempts count toward the limits so concurrent async password checks cannot all pass before any failure is recorded.
  if (ipState.attempts + (ipState.pending || 0) >= config.maxAttempts) {
    return { reason: "rate_limit", retryAfter: Math.max(1, Math.ceil(((ipState.windowStart + config.windowMs) - now) / 1000)) };
  }
  if (usernameState && (usernameState.pending || 0) > 0 && usernameState.failures + usernameState.pending >= config.blockThreshold) {
    return { reason: "rate_limit", retryAfter: Math.max(1, Math.ceil(((usernameState.windowStart + config.windowMs) - now) / 1000)) };
  }
  const delayedState = [ipState, usernameState].find((state) => state?.nextAllowedAt && state.nextAllowedAt > now);
  if (delayedState) return { reason: "progressive_delay", retryAfter: getRetryAfterSeconds(ipState, usernameState) };
  return null;
}

function getProgressiveDelay(failures, baseMs) {
  if (failures <= 1 || baseMs <= 0) return 0;
  return baseMs * (2 ** Math.min(failures - 2, 5));
}

function registerFailedLoginAttempt(state, now, config) {
  if (!state) return;
  state.failures += 1;
  const delay = getProgressiveDelay(state.failures, config.delayBaseMs);
  state.nextAllowedAt = delay ? now + delay : 0;
  if (state.failures >= config.blockThreshold) {
    state.blockedUntil = now + config.blockDurationMs;
    state.nextAllowedAt = state.blockedUntil;
  }
}

function resetLoginState(store, key) {
  if (!key) return;
  const state = store.get(key);
  if (state && state.pending > 0) {
    // Keep the object so in-flight reservations can still be released.
    state.attempts = 0; state.failures = 0; state.blockedUntil = 0; state.nextAllowedAt = 0;
    return;
  }
  store.delete(key);
}

// Reserve an attempt synchronously BEFORE awaiting an async password check.
// failure() converts the reservation into a registered failure; success() just releases it.
function reserveLoginAttempt(security) {
  const states = [security.ipState, security.usernameState].filter(Boolean);
  for (const state of states) state.pending = (state.pending || 0) + 1;
  let settled = false;
  const release = () => {
    if (settled) return false;
    settled = true;
    for (const state of states) state.pending = Math.max(0, (state.pending || 0) - 1);
    return true;
  };
  return {
    release,
    success() { release(); },
    failure() {
      if (!release()) return;
      const now = Date.now();
      security.now = now;
      security.ipState.attempts += 1;
      registerFailedLoginAttempt(security.ipState, now, security.config);
      registerFailedLoginAttempt(security.usernameState, now, security.config);
    },
  };
}

function resetLoginUsernameState({ normalizedUsername }) {
  resetLoginState(loginAttemptsByUsername, normalizedUsername);
}

function getRetryAfterSeconds(...states) {
  const now = Date.now();
  const retryAt = states.filter(Boolean)
    .map((state) => Math.max(state.blockedUntil || 0, state.nextAllowedAt || 0))
    .filter((value) => value > now)
    .sort((a, b) => a - b)[0];
  return retryAt ? Math.max(1, Math.ceil((retryAt - now) / 1000)) : 1;
}

module.exports = { reserveLoginAttempt, getLoginRejection, getLoginSecurityState, getRetryAfterSeconds, registerFailedLoginAttempt, resetLoginUsernameState };
