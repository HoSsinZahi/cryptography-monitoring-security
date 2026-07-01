const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const createRoutes = require('./routes');
const errorHandler = require('./middleware/errorHandler');
const { createStore } = require('./services/storage');
const { createMonitoringService } = require('./services/monitoringService');
const { createAuthService } = require('./services/authService');
const { createCryptoService } = require('./services/cryptoService');
const { createReportService } = require('./services/reportService');
const { generateRequestId } = require('./config');

function createServices(store) {
  const monitoring = createMonitoringService(store);
  const auth = createAuthService(store, monitoring);
  const crypto = createCryptoService(store, monitoring);
  const report = createReportService(store, monitoring);

  return { store, monitoring, auth, crypto, report };
}

function createApp(existingStore) {
  const app = express();
  const store = existingStore || createStore();
  const services = createServices(store);

  app.locals.services = services;
  app.use(helmet());
  app.use(rateLimit({
    windowMs: 60 * 1000,
    limit: 100
  }));
  app.use(express.json({ limit: '100kb' }));
  app.use((req, res, next) => {
    req.requestId = generateRequestId();
    res.setHeader('X-Request-Id', req.requestId);
    next();
  });
  app.use(createRoutes(services));
  app.use(errorHandler);

  return { app, services };
}

module.exports = {
  createApp,
  createServices
};
