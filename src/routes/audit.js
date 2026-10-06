function registerAuditRoutes(app, context) {
  const {
    auditLog,
    authenticate,
    convertAuditLogsToCSV,
    countBy,
    findSuspiciousIPs,
    getAuditActor,
    getFilteredAuditLogs,
    loadAuditLogs,
    requireAuditAccess,
  } = context;

  app.get("/audit/logs", authenticate, requireAuditAccess, (req, res) => {
    const page = Math.max(1, Number(req.query.page) || 1);
    const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), 200);
    const logs = getFilteredAuditLogs(req.query);
    const start = (page - 1) * limit;

    res.json({
      total: logs.length,
      page,
      limit,
      logs: logs.slice(start, start + limit),
    });
  });

  app.get("/audit/summary", authenticate, requireAuditAccess, (req, res) => {
    const logs = loadAuditLogs().logs;
    const critical = logs
      .filter((log) => log.severity === "critical")
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
      .slice(0, 10);

    res.json({
      totalLogs: logs.length,
      bySeverity: countBy(logs, "severity"),
      byEventType: countBy(logs, "eventType"),
      byResult: countBy(logs, "result"),
      recentCritical: critical,
      failedLogins: logs.filter((log) => log.eventType === "auth.login.failed").length,
      suspiciousIPs: findSuspiciousIPs(logs),
    });
  });

  app.get("/audit/export", authenticate, requireAuditAccess, (_req, res) => {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Use POST to export audit logs." });
  });

  app.post("/audit/export", authenticate, requireAuditAccess, (req, res) => {
    const format = String(req.query.format || "json").toLowerCase();
    const logs = getFilteredAuditLogs(req.query);

    auditLog("audit.exported", getAuditActor(req), { type: "audit", id: "export" }, "exported", "success", {
      format,
      count: logs.length,
    });

    if (format === "csv") {
      res.setHeader("Content-Type", "text/csv; charset=utf-8");
      res.setHeader("Content-Disposition", "attachment; filename=audit-logs.csv");
      return res.send(convertAuditLogsToCSV(logs));
    }

    res.json(logs);
  });
}

module.exports = registerAuditRoutes;
