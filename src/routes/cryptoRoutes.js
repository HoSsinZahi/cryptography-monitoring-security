const express = require('express');
const asyncHandler = require('../middleware/asyncHandler');
const { authenticate, authorize, hasPermission } = require('../middleware/auth');
const { ForbiddenError } = require('../errors/AppError');

function createCryptoRoutes(services) {
  const router = express.Router();

  router.post('/encrypt', authenticate, authorize('crypto_ops'), asyncHandler(async (req, res) => {
    const result = services.crypto.encrypt(req.body.plaintext, req.user.email);
    res.json({ success: true, data: result });
  }));

  router.post('/decrypt', authenticate, authorize('crypto_ops'), asyncHandler(async (req, res) => {
    const result = services.crypto.decrypt(req.body, req.user.email);
    res.json({ success: true, data: result });
  }));

  router.post('/sign', authenticate, authorize('crypto_ops'), asyncHandler(async (req, res) => {
    const result = services.crypto.sign(req.body.message, req.user.email);
    res.json({ success: true, data: result });
  }));

  router.post('/verify', authenticate, authorize('crypto_ops'), asyncHandler(async (req, res) => {
    const result = services.crypto.verify(req.body, req.user.email);
    res.json({ success: true, data: result });
  }));

  router.post('/rotate-key', authenticate, authorize('rotate_key'), asyncHandler(async (req, res) => {
    const result = services.crypto.rotateKey(req.user.email);
    res.json({ success: true, data: result });
  }));

  router.get('/key-health', authenticate, authorize('view_reports'), asyncHandler(async (req, res) => {
    const data = services.monitoring.getKeyHealth();
    res.json({ success: true, data });
  }));

  router.get('/metrics', authenticate, authorize('view_reports'), asyncHandler(async (req, res) => {
    const data = services.monitoring.getMetrics();
    res.json({ success: true, data });
  }));

  router.get('/alerts', authenticate, authorize('view_alerts'), asyncHandler(async (req, res) => {
    const data = services.monitoring.getAlerts();
    res.json({ success: true, data });
  }));

  router.get('/report', authenticate, asyncHandler(async (req, res) => {
    const summaryOnly = req.user.role === 'viewer';
    if (!summaryOnly) {
      if (!hasPermission(req.user.role, 'view_reports') && req.user.role !== 'auditor') {
        throw new ForbiddenError('Insufficient role permissions');
      }
    }
    const data = services.report.generateReport({ summaryOnly });
    res.json({ success: true, data });
  }));

  router.get('/audit', authenticate, authorize('view_audit'), asyncHandler(async (req, res) => {
    const data = services.monitoring.getAuditEvents();
    res.json({ success: true, data });
  }));

  return router;
}

module.exports = createCryptoRoutes;
