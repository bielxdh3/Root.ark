const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

function requestIsBlocked(isBlocked, res) {
  if (!isBlocked()) return false;
  res.status(503).set("Retry-After", "30").json({ error: "O servidor está bloqueado durante a recuperação do backup. Reinicie todas as instâncias e revise o estado antes de tentar novamente.", recoveryRequired: true });
  return true;
}

function createRestoreRequestGate({ directory, isBlocked }) {
  if (!directory || typeof isBlocked !== "function") throw new TypeError("Restore request gate requires a directory and blocking predicate");

  function releaseLease(leasePath) {
    if (!leasePath) return;
    try { fs.rmSync(leasePath, { force: true }); } catch {}
  }

  function release(req) {
    if (!req.rootarkRestoreRequestLease) return;
    const leasePath = req.rootarkRestoreRequestLease;
    req.rootarkRestoreRequestLease = null;
    releaseLease(leasePath);
  }

  function createLease() {
    fs.mkdirSync(directory, { recursive: true });
    const leasePath = path.join(directory, `${process.pid}-${crypto.randomUUID()}.json`);
    fs.writeFileSync(leasePath, `${JSON.stringify({ pid: process.pid, createdAt: new Date().toISOString() })}\n`, { flag: "wx", mode: 0o600 });
    return leasePath;
  }

  function acquire({ allowBlocked = false } = {}) {
    if (!allowBlocked && isBlocked()) return null;
    const leasePath = createLease();
    if (!allowBlocked && isBlocked()) {
      releaseLease(leasePath);
      return null;
    }
    let released = false;
    return () => {
      if (released) return;
      released = true;
      releaseLease(leasePath);
    };
  }

  function middleware(req, res, next) {
    if (requestIsBlocked(isBlocked, res)) return;
    try {
      req.rootarkRestoreRequestLease = createLease();
      res.once("finish", () => release(req));
      res.once("close", () => release(req));
    } catch {
      return res.status(503).json({ error: "O servidor esta temporariamente indisponivel." });
    }
    if (requestIsBlocked(isBlocked, res)) {
      release(req);
      return;
    }
    return next();
  }

  async function run(work) {
    let releaseOperation;
    try { releaseOperation = acquire(); } catch { return undefined; }
    if (!releaseOperation) return undefined;
    try { return await work(); }
    finally { releaseOperation(); }
  }

  async function waitForQuiescence(excludedLeasePath, timeoutMs = Number(process.env.RESTORE_QUIESCE_TIMEOUT_MS || 30_000)) {
    const boundedTimeoutMs = Number.isFinite(timeoutMs) ? Math.max(1000, Math.min(120_000, timeoutMs)) : 30_000;
    const deadline = Date.now() + boundedTimeoutMs;
    fs.mkdirSync(directory, { recursive: true });
    while (true) {
      const active = [];
      for (const name of fs.readdirSync(directory)) {
        const leasePath = path.join(directory, name);
        if (leasePath === excludedLeasePath) continue;
        active.push(name);
      }
      if (!active.length) return;
      if (Date.now() >= deadline) {
        const error = new Error("Restore could not reach request quiescence; no restore data was changed");
        error.code = "RESTORE_QUIESCE_TIMEOUT";
        throw error;
      }
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
  }

  return { acquire, middleware, release, run, waitForQuiescence };
}

module.exports = { createRestoreRequestGate };
