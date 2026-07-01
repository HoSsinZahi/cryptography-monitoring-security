const request = require('supertest');
const { createApp } = require('../src/app');
const solve = require('../src/solve');

async function register(app, overrides = {}) {
  return request(app).post('/auth/register').send({
    name: 'Test User',
    email: 'user@example.com',
    password: 'StrongPass#12345',
    role: 'viewer',
    ...overrides
  });
}

async function login(app, email = 'user@example.com', password = 'StrongPass#12345') {
  return request(app).post('/auth/login').send({ email, password });
}

describe('Cryptography monitoring platform', () => {
  test('registration hashes password', async () => {
    const { app, services } = createApp();
    const response = await register(app);
    expect(response.status).toBe(201);
    expect(response.body.data.email).toBe('user@example.com');
    expect(services.store.users[0].passwordHash).not.toBe('StrongPass#12345');
    expect(services.store.users[0].passwordHash).toMatch(/^\$2[aby]\$/);
  });

  test('duplicate email rejected', async () => {
    const { app } = createApp();
    await register(app);
    const response = await register(app);
    expect(response.status).toBe(409);
    expect(response.body.error.code).toBe('DUPLICATE_EMAIL');
  });

  test('weak password rejected', async () => {
    const { app } = createApp();
    const response = await request(app).post('/auth/register').send({
      name: 'Weak User',
      email: 'weak@example.com',
      password: 'weak',
      role: 'viewer'
    });
    expect(response.status).toBe(400);
    expect(response.body.error.code).toBe('VALIDATION_ERROR');
  });

  test('login returns JWT', async () => {
    const { app } = createApp();
    await register(app);
    const response = await login(app);
    expect(response.status).toBe(200);
    expect(response.body.data.token).toBeDefined();
  });

  test('invalid login rejected', async () => {
    const { app } = createApp();
    const response = await login(app);
    expect(response.status).toBe(401);
    expect(response.body.error.code).toBe('INVALID_CREDENTIALS');
  });

  test('missing token returns 401', async () => {
    const { app } = createApp();
    const response = await request(app).get('/crypto/metrics');
    expect(response.status).toBe(401);
  });

  test('forbidden role returns 403', async () => {
    const { app } = createApp();
    await register(app, { role: 'viewer', email: 'viewer@example.com' });
    const loginResponse = await login(app, 'viewer@example.com');
    const response = await request(app)
      .post('/crypto/rotate-key')
      .set('Authorization', `Bearer ${loginResponse.body.data.token}`)
      .send({});
    expect(response.status).toBe(403);
  });

  test('AES encrypt/decrypt works', async () => {
    const { app } = createApp();
    await register(app, { role: 'crypto_operator', email: 'operator@example.com' });
    const loginResponse = await login(app, 'operator@example.com');
    const token = loginResponse.body.data.token;

    const encryptResponse = await request(app)
      .post('/crypto/encrypt')
      .set('Authorization', `Bearer ${token}`)
      .send({ plaintext: 'hello crypto' });

    expect(encryptResponse.status).toBe(200);
    expect(encryptResponse.body.data.ciphertext).toBeDefined();

    const decryptResponse = await request(app)
      .post('/crypto/decrypt')
      .set('Authorization', `Bearer ${token}`)
      .send(encryptResponse.body.data);

    expect(decryptResponse.status).toBe(200);
    expect(decryptResponse.body.data.plaintext).toBe('hello crypto');
  });

  test('tampered ciphertext rejected', async () => {
    const { app } = createApp();
    await register(app, { role: 'crypto_operator', email: 'operator@example.com' });
    const loginResponse = await login(app, 'operator@example.com');
    const token = loginResponse.body.data.token;

    const encryptResponse = await request(app)
      .post('/crypto/encrypt')
      .set('Authorization', `Bearer ${token}`)
      .send({ plaintext: 'hello crypto' });

    const tampered = {
      ...encryptResponse.body.data,
      ciphertext: encryptResponse.body.data.ciphertext.slice(0, -2) + 'aa'
    };

    const decryptResponse = await request(app)
      .post('/crypto/decrypt')
      .set('Authorization', `Bearer ${token}`)
      .send(tampered);

    expect(decryptResponse.status).toBe(400);
    expect(decryptResponse.body.error.code).toBe('TAMPER_DETECTED');
  });

  test('HMAC sign/verify works', async () => {
    const { app } = createApp();
    await register(app, { role: 'crypto_operator', email: 'operator@example.com' });
    const loginResponse = await login(app, 'operator@example.com');
    const token = loginResponse.body.data.token;

    const signResponse = await request(app)
      .post('/crypto/sign')
      .set('Authorization', `Bearer ${token}`)
      .send({ message: 'signed message' });

    expect(signResponse.status).toBe(200);

    const verifyResponse = await request(app)
      .post('/crypto/verify')
      .set('Authorization', `Bearer ${token}`)
      .send({
        message: 'signed message',
        signature: signResponse.body.data.signature,
        keyVersion: signResponse.body.data.keyVersion
      });

    expect(verifyResponse.status).toBe(200);
    expect(verifyResponse.body.data.verified).toBe(true);
  });

  test('modified message rejected', async () => {
    const { app } = createApp();
    await register(app, { role: 'crypto_operator', email: 'operator@example.com' });
    const loginResponse = await login(app, 'operator@example.com');
    const token = loginResponse.body.data.token;

    const signResponse = await request(app)
      .post('/crypto/sign')
      .set('Authorization', `Bearer ${token}`)
      .send({ message: 'signed message' });

    const verifyResponse = await request(app)
      .post('/crypto/verify')
      .set('Authorization', `Bearer ${token}`)
      .send({
        message: 'modified message',
        signature: signResponse.body.data.signature,
        keyVersion: signResponse.body.data.keyVersion
      });

    expect(verifyResponse.status).toBe(400);
    expect(verifyResponse.body.error.code).toBe('TAMPER_DETECTED');
  });

  test('key rotation works', async () => {
    const { app } = createApp();
    await register(app, { role: 'crypto_operator', email: 'operator@example.com' });
    const loginResponse = await login(app, 'operator@example.com');
    const token = loginResponse.body.data.token;

    const response = await request(app)
      .post('/crypto/rotate-key')
      .set('Authorization', `Bearer ${token}`)
      .send({});

    expect(response.status).toBe(200);
    expect(response.body.data.activeKeyVersion).toBe(2);
  });

  test('crypto events logged', async () => {
    const { app, services } = createApp();
    await register(app, { role: 'crypto_operator', email: 'operator@example.com' });
    const loginResponse = await login(app, 'operator@example.com');
    const token = loginResponse.body.data.token;

    await request(app)
      .post('/crypto/encrypt')
      .set('Authorization', `Bearer ${token}`)
      .send({ plaintext: 'hello crypto' });

    expect(services.store.cryptoEvents.length).toBeGreaterThan(0);
    expect(services.store.cryptoEvents.some((event) => event.type === 'encryption_performed')).toBe(true);
  });

  test('key health calculated', async () => {
    const { app } = createApp();
    await register(app, { role: 'security_engineer', email: 'security@example.com' });
    const loginResponse = await login(app, 'security@example.com');
    const token = loginResponse.body.data.token;

    const response = await request(app)
      .get('/crypto/key-health')
      .set('Authorization', `Bearer ${token}`);

    expect(response.status).toBe(200);
    expect(response.body.data.status).toBeDefined();
  });

  test('alerts generated', async () => {
    const { app, services } = createApp();
    services.store.rotationPolicyDays = 0;
    services.store.alerts.push({
      type: 'manual_alert',
      severity: 'critical',
      message: 'manual'
    });
    await register(app, { role: 'security_engineer', email: 'security@example.com' });
    const loginResponse = await login(app, 'security@example.com');
    const token = loginResponse.body.data.token;

    const response = await request(app)
      .get('/crypto/alerts')
      .set('Authorization', `Bearer ${token}`);

    expect(response.status).toBe(200);
    expect(response.body.data.length).toBeGreaterThan(0);
  });

  test('metrics calculated', async () => {
    const { app } = createApp();
    await register(app, { role: 'crypto_operator', email: 'operator@example.com' });
    await register(app, { role: 'security_engineer', email: 'security@example.com' });
    const operatorLogin = await login(app, 'operator@example.com');
    const securityLogin = await login(app, 'security@example.com');

    await request(app)
      .post('/crypto/sign')
      .set('Authorization', `Bearer ${operatorLogin.body.data.token}`)
      .send({ message: 'metrics message' });

    const response = await request(app)
      .get('/crypto/metrics')
      .set('Authorization', `Bearer ${securityLogin.body.data.token}`);

    expect(response.status).toBe(200);
    expect(response.body.data.totalCryptoEvents).toBeGreaterThan(0);
    expect(response.body.data.hmacSignCount).toBeGreaterThan(0);
  });

  test('report generated', async () => {
    const { app } = createApp();
    await register(app, { role: 'security_engineer', email: 'security@example.com' });
    const loginResponse = await login(app, 'security@example.com');
    const token = loginResponse.body.data.token;

    const response = await request(app)
      .get('/crypto/report')
      .set('Authorization', `Bearer ${token}`);

    expect(response.status).toBe(200);
    expect(response.body.data.projectName).toBeDefined();
    expect(response.body.data.riskLevel).toBeDefined();
  });

  test('solve workflow passes', async () => {
    const result = await solve();
    expect(result.success).toBe(true);
    expect(result.riskLevel).toBeDefined();
    expect(result.alertsCount).toBeGreaterThanOrEqual(0);
    expect(result.reportSummary.projectName).toBeDefined();
  });
});
