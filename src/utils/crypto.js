const crypto = require('crypto');
const { AppError } = require('../errors/AppError');

function generateKeyMaterial(version) {
  return {
    version,
    encryptionKey: crypto.randomBytes(32),
    hmacKey: crypto.randomBytes(32),
    createdAt: new Date().toISOString()
  };
}

function encryptAes256Gcm(plaintext, keyMaterial) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', keyMaterial.encryptionKey, iv);
  const ciphertext = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    algorithm: 'aes-256-gcm',
    keyVersion: keyMaterial.version,
    iv: iv.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
    authTag: authTag.toString('base64')
  };
}

function decryptAes256Gcm(payload, keyMaterial) {
  try {
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      keyMaterial.encryptionKey,
      Buffer.from(payload.iv, 'base64')
    );
    decipher.setAuthTag(Buffer.from(payload.authTag, 'base64'));
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(payload.ciphertext, 'base64')),
      decipher.final()
    ]);
    return plaintext.toString('utf8');
  } catch (error) {
    throw new AppError('Ciphertext tampering detected', 400, 'TAMPER_DETECTED');
  }
}

function signHmacSha256(message, keyMaterial) {
  return crypto.createHmac('sha256', keyMaterial.hmacKey).update(String(message)).digest('hex');
}

function verifyHmacSha256(message, signature, keyMaterial) {
  const expected = signHmacSha256(message, keyMaterial);
  const left = Buffer.from(expected, 'hex');
  const right = Buffer.from(String(signature), 'hex');

  if (left.length !== right.length) {
    return false;
  }

  return crypto.timingSafeEqual(left, right);
}

module.exports = {
  generateKeyMaterial,
  encryptAes256Gcm,
  decryptAes256Gcm,
  signHmacSha256,
  verifyHmacSha256
};
