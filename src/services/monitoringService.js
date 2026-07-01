const crypto = require('crypto');

function createMonitoringService(store) {
  function recordEvent(event) {
    const normalized = {
      id: crypto.randomBytes(8).toString('hex'),
      type: event.type,
      severity: event.severity || 'info',
      message: event.message || '',
      keyVersion: event.keyVersion || store.activeKeyVersion,
      actor: event.actor || null,
      meta: event.meta || null,
      createdAt: new Date().toISOString()
    };

    store.cryptoEvents.push(normalized);
    store.auditEvents.push({
      ...normalized,
      category: 'crypto'
    });

    return normalized;
  }

  function getEvents(filters = {}) {
    return store.cryptoEvents.filter((event) => {
      if (filters.type && event.type !== filters.type) return false;
      if (filters.severity && event.severity !== filters.severity) return false;
      if (filters.keyVersion && Number(event.keyVersion) !== Number(filters.keyVersion)) return false;
      return true;
    });
  }

  function getMetrics() {
    const metrics = {
      totalCryptoEvents: store.cryptoEvents.length,
      encryptionCount: 0,
      decryptionCount: 0,
      hmacSignCount: 0,
      hmacVerifyCount: 0,
      keyRotationCount: 0,
      tamperDetectedCount: 0,
      cryptoErrorCount: 0,
      eventsByType: {},
      eventsBySeverity: {}
    };

    for (const event of store.cryptoEvents) {
      metrics.eventsByType[event.type] = (metrics.eventsByType[event.type] || 0) + 1;
      metrics.eventsBySeverity[event.severity] = (metrics.eventsBySeverity[event.severity] || 0) + 1;

      if (event.type === 'encryption_performed') metrics.encryptionCount += 1;
      if (event.type === 'decryption_performed') metrics.decryptionCount += 1;
      if (event.type === 'hmac_signed') metrics.hmacSignCount += 1;
      if (event.type === 'hmac_verified') metrics.hmacVerifyCount += 1;
      if (event.type === 'key_rotated') metrics.keyRotationCount += 1;
      if (event.type === 'tamper_detected') metrics.tamperDetectedCount += 1;
      if (event.type === 'crypto_error') metrics.cryptoErrorCount += 1;
    }

    return metrics;
  }

  function getKeyHealth() {
    const key = store.keys.find((item) => item.version === store.activeKeyVersion);
    const keyAgeDays = key
      ? Math.floor((Date.now() - new Date(key.createdAt).getTime()) / (1000 * 60 * 60 * 24))
      : null;
    const metrics = getMetrics();

    let status = 'healthy';
    const issues = [];

    if (!key) {
      status = 'critical';
      issues.push('Active cryptographic key is missing');
    }

    if (!store.rotationPolicyDays || store.rotationPolicyDays <= 0) {
      status = 'warning';
      issues.push('Rotation policy is missing');
    }

    if (keyAgeDays !== null && keyAgeDays >= store.rotationPolicyDays) {
      status = 'warning';
      issues.push('Active key is stale');
    }

    if (metrics.cryptoErrorCount >= store.thresholds.cryptoErrors) {
      status = 'critical';
      issues.push('Excessive crypto errors detected');
    }

    if (metrics.tamperDetectedCount >= store.thresholds.tamper) {
      status = 'critical';
      issues.push('Tamper events detected');
    }

    return {
      status,
      activeKeyVersion: store.activeKeyVersion,
      keyAgeDays,
      rotationPolicyDays: store.rotationPolicyDays,
      issues
    };
  }

  function getAlerts() {
    const keyHealth = getKeyHealth();
    const metrics = getMetrics();
    const alerts = [];

    if (keyHealth.issues.includes('Active key is stale')) {
      alerts.push({
        type: 'key_stale',
        severity: 'warning',
        message: 'Active key is stale and should be rotated'
      });
    }

    if (keyHealth.issues.includes('Rotation policy is missing')) {
      alerts.push({
        type: 'missing_rotation_policy',
        severity: 'warning',
        message: 'No key rotation policy is configured'
      });
    }

    if (metrics.tamperDetectedCount >= store.thresholds.tamper) {
      alerts.push({
        type: 'tamper_threshold_exceeded',
        severity: 'critical',
        message: 'Tamper events exceeded the configured threshold'
      });
    }

    if (metrics.cryptoErrorCount >= store.thresholds.cryptoErrors) {
      alerts.push({
        type: 'crypto_error_threshold_exceeded',
        severity: 'critical',
        message: 'Crypto errors exceeded the configured threshold'
      });
    }

    if (metrics.eventsBySeverity.critical > 0) {
      alerts.push({
        type: 'critical_crypto_event',
        severity: 'critical',
        message: 'Critical crypto events were observed'
      });
    }

    if (store.alerts.length) {
      return [...alerts, ...store.alerts];
    }

    return alerts;
  }

  function calculateRiskScore() {
    const keyHealth = getKeyHealth();
    const metrics = getMetrics();
    let score = 0;

    if (keyHealth.issues.includes('Active key is stale')) score += 35;
    if (keyHealth.issues.includes('Rotation policy is missing')) score += 15;
    if (metrics.tamperDetectedCount > 0) score += 25;
    if (metrics.cryptoErrorCount > 0) score += Math.min(25, metrics.cryptoErrorCount * 8);
    if (metrics.keyRotationCount === 0) score += 25;
    if (metrics.eventsBySeverity.critical > 0) score += 20;

    score = Math.min(100, score);

    let riskLevel = 'low';
    if (score >= 70) riskLevel = 'critical';
    else if (score >= 40) riskLevel = 'high';
    else if (score >= 20) riskLevel = 'medium';

    return { score, riskLevel };
  }

  function addAlert(alert) {
    store.alerts.push({
      id: crypto.randomBytes(8).toString('hex'),
      createdAt: new Date().toISOString(),
      ...alert
    });
  }

  function getAuditEvents() {
    return [...store.auditEvents];
  }

  return {
    recordEvent,
    getEvents,
    getMetrics,
    getKeyHealth,
    getAlerts,
    calculateRiskScore,
    addAlert,
    getAuditEvents
  };
}

module.exports = {
  createMonitoringService
};
