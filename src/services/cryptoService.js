const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { config } = require('../config');
const { AppError, ValidationError } = require('../errors/AppError');
const { generateKeyMaterial, encryptAes256Gcm, decryptAes256Gcm, signHmacSha256, verifyHmacSha256 } = require('../utils/crypto');

function createCryptoService(store, monitoring) {
  function getActiveKey() {
    return store.keys.find((key) => key.version === store.activeKeyVersion);
  }

  function getActiveKeyVersion() {
    return store.activeKeyVersion;
  }

  function validateTextPayload(payload, fieldName) {
    if (!payload || typeof payload[fieldName] !== 'string' || payload[fieldName].length === 0) {
      throw new ValidationError(`Field ${fieldName} is required`);
    }
  }

  function encrypt(plaintext, actor) {
    validateTextPayload({ plaintext }, 'plaintext');
    const key = getActiveKey();
    const result = encryptAes256Gcm(plaintext, key);
    monitoring.recordEvent({
      type: 'encryption_performed',
      severity: 'info',
      message: 'AES-256-GCM encryption performed',
      keyVersion: key.version,
      actor
    });
    return result;
  }

  function decrypt(payload, actor) {
    if (!payload || typeof payload !== 'object') {
      throw new ValidationError('Cipher payload is required');
    }
    const key = store.keys.find((item) => item.version === Number(payload.keyVersion));
    if (!key) {
      monitoring.recordEvent({
        type: 'tamper_detected',
        severity: 'critical',
        message: 'Key version not found for decrypt',
        keyVersion: payload.keyVersion,
        actor
      });
      throw new AppError('Invalid key version', 400, 'TAMPER_DETECTED');
    }

    try {
      const plaintext = decryptAes256Gcm(payload, key);
      monitoring.recordEvent({
        type: 'decryption_performed',
        severity: 'info',
        message: 'AES-256-GCM decryption performed',
        keyVersion: key.version,
        actor
      });
      return { plaintext };
    } catch (error) {
      monitoring.recordEvent({
        type: 'tamper_detected',
        severity: 'critical',
        message: 'Ciphertext tampering detected',
        keyVersion: key.version,
        actor
      });
      throw error;
    }
  }

  function sign(message, actor) {
    validateTextPayload({ message }, 'message');
    const key = getActiveKey();
    const signature = signHmacSha256(message, key);
    monitoring.recordEvent({
      type: 'hmac_signed',
      severity: 'info',
      message: 'HMAC signed',
      keyVersion: key.version,
      actor
    });
    return {
      message,
      signature,
      keyVersion: key.version
    };
  }

  function verify(payload, actor) {
    if (!payload || typeof payload !== 'object') {
      throw new ValidationError('Verification payload is required');
    }
    validateTextPayload({ message: payload.message }, 'message');
    validateTextPayload({ signature: payload.signature }, 'signature');
    const key = store.keys.find((item) => item.version === Number(payload.keyVersion)) || getActiveKey();
    const verified = verifyHmacSha256(payload.message, payload.signature, key);

    monitoring.recordEvent({
      type: 'hmac_verified',
      severity: verified ? 'info' : 'high',
      message: verified ? 'HMAC verified' : 'HMAC verification failed',
      keyVersion: key.version,
      actor
    });

    if (!verified) {
      throw new AppError('Signature verification failed', 400, 'TAMPER_DETECTED');
    }

    return { verified: true };
  }

  function verifyJwtToken(token) {
    try {
      const payload = jwt.verify(token, config.jwtSecret);
      monitoring.recordEvent({
        type: 'jwt_verified',
        severity: 'info',
        message: 'JWT verified',
        keyVersion: getActiveKeyVersion(),
        actor: payload.email
      });
      return payload;
    } catch (error) {
      monitoring.recordEvent({
        type: 'crypto_error',
        severity: 'high',
        message: 'JWT verification failed',
        keyVersion: getActiveKeyVersion()
      });
      throw new AppError('Invalid token', 401, 'UNAUTHORIZED');
    }
  }

  function rotateKey(actor) {
    const nextVersion = store.keys.reduce((max, key) => Math.max(max, key.version), 0) + 1;
    const keyMaterial = generateKeyMaterial(nextVersion);
    store.keys.push(keyMaterial);
    store.activeKeyVersion = nextVersion;
    monitoring.recordEvent({
      type: 'key_rotated',
      severity: 'info',
      message: `Key rotated to version ${nextVersion}`,
      keyVersion: nextVersion,
      actor
    });
    return {
      activeKeyVersion: nextVersion,
      createdAt: keyMaterial.createdAt
    };
  }

  function simulateTamperDetection(actor) {
    monitoring.recordEvent({
      type: 'tamper_detected',
      severity: 'critical',
      message: 'Simulated tamper event',
      keyVersion: getActiveKeyVersion(),
      actor
    });
    return { tamperDetected: true };
  }

  return {
    getActiveKey,
    getActiveKeyVersion,
    encrypt,
    decrypt,
    sign,
    verify,
    verifyJwtToken,
    rotateKey,
    simulateTamperDetection
  };
}

module.exports = {
  createCryptoService
};
