const express = require('express');
const createAuthRoutes = require('./authRoutes');
const createCryptoRoutes = require('./cryptoRoutes');

function createRoutes(services) {
  const router = express.Router();

  router.get('/health', (req, res) => {
    res.json({
      success: true,
      data: {
        status: 'ok',
        service: 'cryptography-monitoring-security',
        activeKeyVersion: services.crypto.getActiveKeyVersion(),
        timestamp: new Date().toISOString()
      }
    });
  });

  router.use('/auth', createAuthRoutes(services));
  router.use('/crypto', createCryptoRoutes(services));

  return router;
}

module.exports = createRoutes;
