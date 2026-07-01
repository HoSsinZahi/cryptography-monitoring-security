const { AppError } = require('../errors/AppError');

function errorHandler(err, req, res, next) {
  const statusCode = err.statusCode || 500;
  const code = err.code || 'INTERNAL_ERROR';
  const message = statusCode === 500 ? 'Internal Server Error' : err.message;

  if (req && req.app && req.app.locals && req.app.locals.services) {
    req.app.locals.services.monitoring.recordEvent({
      type: 'crypto_error',
      severity: statusCode >= 500 ? 'critical' : 'high',
      message: err.message,
      keyVersion: req.app.locals.services.crypto.getActiveKeyVersion(),
      meta: { code }
    });
  }

  res.status(statusCode).json({
    success: false,
    error: {
      code,
      message,
      details: err.details || null
    }
  });
}

module.exports = errorHandler;
