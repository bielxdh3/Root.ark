function registerBackupRoutes(app, context) {
  const {
    auditLog,
    authenticate,
    backupService,
    getAuditActor,
    requireBackupAccess,
    restoreService,
    waitForRequestQuiescence,
  } = context;

  app.get("/backups", authenticate, requireBackupAccess, (req, res) => {
    res.json({ backups: backupService.listBackups() });
  });

  app.get("/backups/latest-status", authenticate, requireBackupAccess, (req, res) => {
    res.json({ latest: backupService.latestStatus() });
  });

  app.post("/backups", authenticate, requireBackupAccess, async (req, res) => {
    try {
      const backup = await backupService.createBackup({
        type: "manual",
        createdBy: req.user.username,
        notes: typeof req.body?.notes === "string" ? req.body.notes.slice(0, 500) : "",
      });
      auditLog("backup.created", getAuditActor(req), { type: "backup", id: backup.id }, "created", "success", {
        filename: backup.filename,
        sizeBytes: backup.sizeBytes,
        checksum: backup.checksum,
      });
      res.status(201).json({ backup });
    } catch (error) {
      auditLog("backup.failed", getAuditActor(req), { type: "backup", id: error.backup?.id || null }, "created", "failure", {
        error: error.message,
      });
      res.status(error.code === "BACKUP_LOCKED" ? 409 : 500).json({ error: error.message });
    }
  });

  app.get("/backups/:id/download", authenticate, requireBackupAccess, (req, res) => {
    try {
      const { backup, archivePath } = backupService.getBackupOrThrow(req.params.id);
      auditLog("backup.downloaded", getAuditActor(req), { type: "backup", id: backup.id }, "downloaded", "success", {
        filename: backup.filename,
      });
      res.download(archivePath, backup.filename);
    } catch (error) {
      res.status(404).json({ error: error.message });
    }
  });

  app.get("/backups/:id/manifest", authenticate, requireBackupAccess, async (req, res) => {
    try {
      const manifest = await restoreService.getBackupManifest(req.params.id);
      res.json(manifest);
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  });

  app.post("/backups/:id/restore", authenticate, requireBackupAccess, async (req, res) => {
    auditLog("backup.restore.started", getAuditActor(req), { type: "backup", id: req.params.id }, "restore", "partial", {});
    try {
      const result = await restoreService.restoreBackup(req.params.id, {
        confirmation: req.body?.confirmation,
        username: req.user.username,
        waitForRequestQuiescence: () => waitForRequestQuiescence(req.rootarkRestoreRequestLease),
      });
      auditLog("backup.restore.completed", getAuditActor(req), { type: "backup", id: result.backup.id }, "restore", "success", {
        preRestoreBackupId: result.preRestore.id,
        restartRecommended: result.restartRecommended,
      });
      res.json({
        message: "Backup restaurado",
        backup: result.backup,
        preRestoreBackup: result.preRestore,
        restartRecommended: result.restartRecommended,
      });
    } catch (error) {
      const restorePhase = restoreService.getWholeRestorePhase?.() || null;
      auditLog("backup.restore.failed", getAuditActor(req), { type: "backup", id: req.params.id }, "restore", "failure", {
        error: restorePhase ? "restore_recovery_pending" : error.message,
        phase: restorePhase,
      });
      if (restorePhase === "restart_required") {
        res.status(503).json({
          error: "Backup restaurado, mas a limpeza temporária falhou. Reinicie todas as instâncias; o serviço tentará remover a área temporária antes de aceitar novas solicitações.",
          restartRequired: true,
          cleanupPending: true,
        });
      } else if (restorePhase) {
        res.status(503).json({
          error: "A restauração permanece bloqueada para recuperação. Reinicie todas as instâncias e revise o estado antes de tentar novamente.",
          recoveryRequired: true,
        });
      } else {
        res.status(error.code === "BACKUP_LOCKED" ? 409 : 400).json({ error: error.message });
      }
    }
  });

  app.delete("/backups/:id", authenticate, requireBackupAccess, (req, res) => {
    try {
      const backup = backupService.deleteBackup(req.params.id);
      auditLog("backup.deleted", getAuditActor(req), { type: "backup", id: backup.id }, "deleted", "success", {
        filename: backup.filename,
      });
      res.json({ message: "Backup excluido", backup });
    } catch (error) {
      res.status(error.code === "BACKUP_LOCKED" ? 409 : 400).json({ error: error.message });
    }
  });
}

module.exports = registerBackupRoutes;
