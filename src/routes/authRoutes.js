const express = require('express');
const asyncHandler = require('../middleware/asyncHandler');

function createAuthRoutes(services) {
  const router = express.Router();

  router.post('/register', asyncHandler(async (req, res) => {
    const user = await services.auth.register(req.body);
    services.monitoring.recordEvent({
      type: 'crypto_event',
      severity: 'info',
      message: 'Registration completed',
      actor: user.email
    });
    res.status(201).json({ success: true, data: user });
  }));

  router.post('/login', asyncHandler(async (req, res) => {
    const result = await services.auth.login(req.body);
    res.json({ success: true, data: result });
  }));

  return router;
}

module.exports = createAuthRoutes;
