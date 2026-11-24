"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

test("audit event filter offers documented backup events without removing existing options", () => {
  const root = path.join(__dirname, "..");
  const source = fs.readFileSync(path.join(root, "public", "client", "rootark-management.js"), "utf8");
  const docs = fs.readFileSync(path.join(root, "BACKUP.md"), "utf8");
  const select = source.match(/<select\b[^>]*\bid="audit-event-type"[^>]*>([\s\S]*?)<\/select>/);
  assert.ok(select, "audit event filter must exist");
  const group = select[1].match(/<optgroup label="Backup e restauração">([\s\S]*?)<\/optgroup>/);
  assert.ok(group, "backup event group must exist");
  const audit = docs.match(/^## Auditoria\s*[\s\S]*?(?=^## |\s*$)/m);
  assert.ok(audit, "backup audit documentation must exist");
  const section = docs.split(/^## Auditoria\s*$/m)[1].split(/^## /m)[0];
  const documented = Array.from(section.matchAll(/^- `(backup\.[^`]+)`\s*$/gm), (match) => match[1]);
  const options = (markup) => Array.from(markup.matchAll(/<option value="([^"]*)">([^<]+)<\/option>/g), (match) => [match[1], match[2]]);
  const backupOptions = options(group[1]);
  assert.equal(documented.length, 7);
  assert.deepEqual(backupOptions.map(([value]) => value), documented);
  assert.deepEqual(backupOptions.map(([, label]) => label), [
    "Backup criado", "Falha no backup", "Backup excluído", "Backup baixado",
    "Restauração iniciada", "Restauração concluída", "Falha na restauração",
  ]);
  const previous = options(select[1].replace(group[0], ""));
  assert.deepEqual(previous, [
    ["", "Todos os eventos"],
    ["auth.login.success", "Login bem-sucedido"],
    ["auth.login.failed", "Login falho"],
    ["file.upload", "Envio de arquivo"],
    ["file.download", "Download"],
    ["file.delete", "Exclusão de arquivo"],
    ["file.approve", "Aprovação"],
    ["user.permission.changed", "Permissão alterada"],
    ["user.deleted", "Conta excluída"],
    ["system.anomaly.detected", "Anomalia"],
  ]);
  const allValues = options(select[1]).map(([value]) => value);
  assert.equal(new Set(allValues).size, allValues.length);
});
