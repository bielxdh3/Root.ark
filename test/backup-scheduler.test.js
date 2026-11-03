const assert = require("node:assert/strict");
const test = require("node:test");
const { parseBackupTime, scheduleAutomaticBackups } = require("../services/backupScheduler");

test("scheduler validates time and preserves explicit UTC scheduling", async (t) => {
  for (const [value, expected] of [["03:00", { hour: 3, minute: 0 }], ["23:59", { hour: 23, minute: 59 }], ["24:00", null], ["03:60", null], ["3:00", null], ["bad", null]]) {
    await t.test(`time ${value}`, () => assert.deepEqual(parseBackupTime(value), expected));
  }
  await t.test("disabled settings do not register", () => {
    let calls = 0;
    const cron = { schedule: () => { calls += 1; } };
    assert.equal(scheduleAutomaticBackups({ env: { BACKUP_ENABLED: "false" }, cron, createBackup: async () => {} }), null);
    assert.equal(scheduleAutomaticBackups({ env: { BACKUP_AUTO_ENABLED: "false" }, cron, createBackup: async () => {} }), null);
    assert.equal(calls, 0);
  });
  await t.test("automatic run is serialized and auditable", async () => {
    let callback; let options; let resolve;
    const pending = new Promise((done) => { resolve = done; });
    const events = [];
    scheduleAutomaticBackups({ env: { BACKUP_TIME: "01:02" }, cron: { schedule: (_expr, fn, opts) => { callback = fn; options = opts; return { stop() {} }; } }, createBackup: async () => { await pending; return { id: "id", filename: "backup.zip" }; }, auditLog: (...args) => events.push(args) });
    const first = callback(); const second = callback(); resolve(); await Promise.all([first, second]);
    assert.equal(options.timezone, "UTC");
    assert.equal(events.length, 1);
    assert.equal(events[0][0], "backup.created");
  });
  await t.test("scheduled failures are audited", async () => {
    let callback; const events = [];
    scheduleAutomaticBackups({ env: {}, cron: { schedule: (_expr, fn) => { callback = fn; return { stop() {} }; } }, createBackup: async () => { throw new Error("failed"); }, auditLog: (...args) => events.push(args) });
    await callback(); assert.equal(events[0][0], "backup.failed");
  });
  await t.test("restore-paused automatic backup does not emit a false backup.failed event", async () => {
    let callback; const events = [];
    const task = scheduleAutomaticBackups({
      env: {},
      cron: { schedule: (_expr, fn) => { callback = fn; return { stop() {} }; } },
      createBackup: async () => {
        throw Object.assign(new Error("restore in progress"), { code: "BACKUP_PAUSED_DURING_RESTORE" });
      },
      auditLog: (...args) => events.push(args),
    });
    await callback();
    assert.deepEqual(events, []);
    assert.equal(task.latestStatus().state, "paused");
    assert.equal(task.latestStatus().error, "restore_pending");
  });
  await t.test("invalid configuration is reported without registration", () => {
    let invalid; let registered = false;
    const task = scheduleAutomaticBackups({ env: { BACKUP_TIME: "99:00" }, cron: { schedule: () => { registered = true; } }, createBackup: async () => {}, onInvalid: (message) => { invalid = message; } });
    assert.equal(task, null); assert.equal(registered, false); assert.match(invalid, /BACKUP_TIME/);
  });
  await t.test("configured timezone reaches cron and task can stop", () => {
    let options; let stopped = false;
    const task = { stop: () => { stopped = true; } };
    assert.equal(scheduleAutomaticBackups({ env: { BACKUP_TIMEZONE: "America/Cuiaba" }, cron: { schedule: (_expr, _callback, received) => { options = received; return task; } }, createBackup: async () => {} }), task);
    task.stop(); assert.equal(options.timezone, "America/Cuiaba"); assert.equal(stopped, true);
  });
});
