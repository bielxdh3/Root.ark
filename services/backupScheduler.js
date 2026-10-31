let registration = null;
const { isZk10LegacyBackupStrict } = require("../src/services/zk10LegacyBackupDeny");

function parseBackupTime(value) {
  const match = /^(\d{2}):(\d{2})$/.exec(String(value || ""));
  if (!match) return null;
  const hour = Number(match[1]);
  const minute = Number(match[2]);
  return hour >= 0 && hour <= 23 && minute >= 0 && minute <= 59 ? { hour, minute } : null;
}

function isValidTimezone(value) {
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: value }).format();
    return true;
  } catch {
    return false;
  }
}

function scheduleAutomaticBackups({ env = process.env, cron, createBackup, auditLog = () => {}, onInvalid = () => {} }) {
  // A scheduling decision is advisory only; backupService enforces the same
  // denial at its physical ZIP source for direct/manual/pre-restore callers.
  if (isZk10LegacyBackupStrict(env)) return null;
  if (String(env.BACKUP_ENABLED || "true").toLowerCase() === "false" || String(env.BACKUP_AUTO_ENABLED || "true").toLowerCase() === "false") return null;
  const time = parseBackupTime(env.BACKUP_TIME || "03:00");
  if (!time) { onInvalid("BACKUP_TIME invalido. Use HH:mm."); return null; }
  const timezone = env.BACKUP_TIMEZONE || "UTC";
  if (!isValidTimezone(timezone)) { onInvalid("BACKUP_TIMEZONE invalido."); return null; }
  if (registration?.cron === cron) return registration.task;
  if (registration?.task?.destroy) registration.task.destroy();
  let running = false;
  const latest = { state: "idle", startedAt: null, finishedAt: null, backupId: null, error: null };
  const callback = async () => {
    if (running) return;
    running = true;
    latest.state = "running";
    latest.startedAt = new Date().toISOString();
    latest.finishedAt = null;
    latest.error = null;
    try {
      const backup = await createBackup({ type: "automatic", createdBy: "system" });
      latest.state = "success";
      latest.backupId = backup.id;
      auditLog("backup.created", { username: "system" }, { type: "backup", id: backup.id }, "created", "success", { filename: backup.filename, automatic: true });
    } catch (error) {
      latest.state = "failure";
      latest.error = "backup_failed";
      auditLog("backup.failed", { username: "system" }, { type: "backup", id: error.backup?.id || null }, "created", "failure", { error: error.message, automatic: true });
    } finally {
      latest.finishedAt = new Date().toISOString();
      running = false;
    }
  };
  const task = cron.schedule(`${time.minute} ${time.hour} * * *`, callback, { timezone });
  const originalStop = typeof task?.stop === "function" ? task.stop.bind(task) : () => {};
  const originalDestroy = typeof task?.destroy === "function" ? task.destroy.bind(task) : originalStop;
  const close = (method) => {
    method();
    latest.state = "stopped";
    latest.finishedAt = new Date().toISOString();
    if (registration?.task === task) registration = null;
  };
  if (task && typeof task === "object") {
    task.latestStatus = () => ({ ...latest });
    task.getLatestStatus = task.latestStatus;
    task.stop = () => close(originalStop);
    task.destroy = () => close(originalDestroy);
  }
  registration = { cron, task };
  return task;
}

module.exports = { isValidTimezone, parseBackupTime, scheduleAutomaticBackups };
