const crypto = require('crypto');

const config = {
  appName: 'Cryptography Monitoring Security Platform',
  jwtSecret: process.env.JWT_SECRET || 'dev-jwt-secret-change-me',
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || '2h',
  defaultRotationPolicyDays: Number(process.env.ROTATION_POLICY_DAYS || 30),
  tamperAlertThreshold: Number(process.env.TAMPER_ALERT_THRESHOLD || 1),
  cryptoErrorAlertThreshold: Number(process.env.CRYPTO_ERROR_ALERT_THRESHOLD || 3),
  passwordMinLength: 12,
  requestIdLength: 12
};

function generateRequestId() {
  return crypto.randomBytes(config.requestIdLength).toString('hex');
}

module.exports = {
  config,
  generateRequestId
};
