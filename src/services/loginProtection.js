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
    state = { attempts: 0, failures: 0, windowStart: now, blockedUntil: 0, nextAllowedAt: 0 };
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
    if (!state.blockedUntil && inactiveFor > Math.max(config.windowMs * 4, config.blockDurationMs * 2, 5 * 60 * 1000)) store.delete(key);
  }
}

function getLoginSecurityState(req, username, getAuditActor) {
  const config = getLoginSecurityConfig();
  const now = Date.now();
  const actor = getAuditActor(req, username || "unknown_user");
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
  if (ipState.attempts >= config.maxAttempts) {
    return { reason: "rate_limit", retryAfter: Math.max(1, Math.ceil(((ipState.windowStart + config.windowMs) - now) / 1000)) };
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
  if (key) store.delete(key);
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

module.exports = { getLoginRejection, getLoginSecurityState, getRetryAfterSeconds, registerFailedLoginAttempt, resetLoginUsernameState };
