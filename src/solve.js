const request = require('supertest');
const { createApp } = require('./app');

async function solve() {
  const { app, services } = createApp();

  const adminRegister = await request(app).post('/auth/register').send({
    name: 'Admin User',
    email: 'admin@example.com',
    password: 'StrongAdmin#12345',
    role: 'admin'
  });

  const operatorRegister = await request(app).post('/auth/register').send({
    name: 'Crypto Operator',
    email: 'operator@example.com',
    password: 'StrongOperator#12345',
    role: 'crypto_operator'
  });

  const login = await request(app).post('/auth/login').send({
    email: 'operator@example.com',
    password: 'StrongOperator#12345'
  });

  const token = login.body.data.token;

  const encryption = await request(app)
    .post('/crypto/encrypt')
    .set('Authorization', `Bearer ${token}`)
    .send({ plaintext: 'sensitive payload' });

  const decrypted = await request(app)
    .post('/crypto/decrypt')
    .set('Authorization', `Bearer ${token}`)
    .send(encryption.body.data);

  const signed = await request(app)
    .post('/crypto/sign')
    .set('Authorization', `Bearer ${token}`)
    .send({ message: 'signed message' });

  const verified = await request(app)
    .post('/crypto/verify')
    .set('Authorization', `Bearer ${token}`)
    .send({ message: 'signed message', signature: signed.body.data.signature, keyVersion: signed.body.data.keyVersion });

  await request(app).post('/crypto/rotate-key').set('Authorization', `Bearer ${token}`).send({});
  services.crypto.simulateTamperDetection('operator@example.com');

  const report = services.report.generateReport();
  return {
    success: true,
    riskLevel: report.riskLevel,
    alertsCount: report.alerts.length,
    reportSummary: {
      projectName: report.projectName,
      keyHealth: report.keyHealth.status,
      riskScore: report.riskScore,
      auditEventsCount: report.auditEventsCount,
      encrypted: Boolean(encryption.body.data.ciphertext),
      decrypted: decrypted.body.data.plaintext,
      verified: verified.body.data.verified
    },
    report
  };
}

module.exports = solve;
