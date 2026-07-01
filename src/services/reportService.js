function createReportService(store, monitoring) {
  function generateReport({ summaryOnly = false } = {}) {
    const keyHealth = monitoring.getKeyHealth();
    const metrics = monitoring.getMetrics();
    const alerts = monitoring.getAlerts();
    const risk = monitoring.calculateRiskScore();
    const auditEventsCount = monitoring.getAuditEvents().length;

    const recommendations = [];
    if (keyHealth.status !== 'healthy') {
      recommendations.push('Rotate the active key and confirm the rotation policy is enforced');
    }
    if (metrics.tamperDetectedCount > 0) {
      recommendations.push('Investigate tamper events and verify ciphertext integrity controls');
    }
    if (metrics.cryptoErrorCount > 0) {
      recommendations.push('Reduce crypto errors by validating inputs and handling failures explicitly');
    }
    if (metrics.keyRotationCount === 0) {
      recommendations.push('Perform a baseline key rotation to establish operational hygiene');
    }
    if (recommendations.length === 0) {
      recommendations.push('Continue routine monitoring and periodic key rotation');
    }

    const report = {
      projectName: store.projectName,
      keyHealth,
      metrics,
      alerts,
      riskScore: risk.score,
      riskLevel: risk.riskLevel,
      auditEventsCount,
      recommendations,
      generatedAt: new Date().toISOString()
    };

    if (summaryOnly) {
      return {
        projectName: report.projectName,
        keyHealth: report.keyHealth.status,
        riskScore: report.riskScore,
        riskLevel: report.riskLevel,
        alertsCount: report.alerts.length,
        auditEventsCount: report.auditEventsCount,
        generatedAt: report.generatedAt
      };
    }

    return report;
  }

  return {
    generateReport
  };
}

module.exports = {
  createReportService
};
