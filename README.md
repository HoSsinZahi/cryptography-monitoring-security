# Cryptography Monitoring Security Platform

Production-style CommonJS Node.js API for cryptography monitoring, key health tracking, crypto event logging, alerts, metrics, risk scoring, and reporting.

## Setup

```bash
npm install
npm test
npm start
```

## Stack

- Node.js CommonJS
- Express
- bcryptjs
- jsonwebtoken
- helmet
- express-rate-limit
- Jest
- Supertest
- Built-in `crypto`
- In-memory storage only

## Architecture

- `src/routes` handles HTTP routing
- `src/services` holds business logic
- `src/middleware` centralizes auth, validation, and errors
- `src/utils` contains cryptographic helpers
- `src/errors` defines typed API errors

## Authentication

### Register

`POST /auth/register`

```json
{
  "name": "Admin User",
  "email": "admin@example.com",
  "password": "StrongAdmin#12345",
  "role": "admin"
}
```

### Login

`POST /auth/login`

```json
{
  "email": "admin@example.com",
  "password": "StrongAdmin#12345"
}
```

Returns a JWT for protected routes.

## Authorization

- `admin`: full access
- `security_engineer`: reports and alerts
- `crypto_operator`: crypto operations and key rotation
- `auditor`: audit logs
- `viewer`: public summary only

## Crypto Operations

- AES-256-GCM encryption/decryption
- HMAC-SHA256 signing/verification
- JWT verification in middleware
- Secure random key generation
- Key rotation with version metadata
- Tamper detection for ciphertext and signatures

## Monitoring Strategy

The platform records crypto events in memory:

- `encryption_performed`
- `decryption_performed`
- `hmac_signed`
- `hmac_verified`
- `jwt_verified`
- `key_rotated`
- `tamper_detected`
- `crypto_error`

It calculates:

- key health
- metrics
- alerts
- risk score
- final report

Alerts fire when:

- the key is stale
- tamper events exceed threshold
- crypto errors exceed threshold
- no rotation exists
- critical crypto events appear

## API

- `GET /health`
- `POST /auth/register`
- `POST /auth/login`
- `POST /crypto/encrypt`
- `POST /crypto/decrypt`
- `POST /crypto/sign`
- `POST /crypto/verify`
- `POST /crypto/rotate-key`
- `GET /crypto/key-health`
- `GET /crypto/metrics`
- `GET /crypto/alerts`
- `GET /crypto/report`
- `GET /crypto/audit`

## Demo

```bash
npm run demo
```

Runs the full solve workflow:

- register admin and crypto operator
- login crypto operator
- verify JWT
- encrypt/decrypt
- sign/verify HMAC
- rotate key
- simulate tamper detection
- generate metrics, alerts, health, and final report

## Tests

Coverage includes:

- registration password hashing
- duplicate email rejection
- weak password rejection
- login success and failure
- auth failures and role enforcement
- AES encryption/decryption
- tamper rejection
- HMAC sign/verify
- key rotation
- crypto event logging
- key health
- alerts
- metrics
- report generation
- solve workflow

## Production Considerations

- Move secrets to environment variables
- Persist state in a database instead of memory
- Rotate JWT signing keys with a key management system
- Add distributed rate limiting
- Add observability export to SIEM or metrics backend
- Use request logging and trace correlation
- Add stricter input schemas and audit retention controls
