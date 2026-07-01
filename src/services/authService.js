const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { config } = require('../config');
const { AppError, ValidationError, ForbiddenError } = require('../errors/AppError');
const { validatePassword, hashPassword, comparePassword } = require('../utils/password');

const roles = ['admin', 'security_engineer', 'crypto_operator', 'auditor', 'viewer'];

function createAuthService(store, monitoring) {
  function validateRegistrationInput(payload) {
    const errors = [];
    if (!payload || typeof payload !== 'object') {
      return {
        valid: false,
        message: 'Invalid registration payload',
        errors: ['Request body is required'],
        value: {}
      };
    }
    if (!payload.name || typeof payload.name !== 'string' || payload.name.trim().length < 2) {
      errors.push('Name is required');
    }
    if (!payload.email || typeof payload.email !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(payload.email)) {
      errors.push('Valid email is required');
    }
    if (!payload.password) {
      errors.push('Password is required');
    }
    if (payload.role && !roles.includes(payload.role)) {
      errors.push('Invalid role');
    }
    const passwordCheck = validatePassword(payload.password || '');
    if (!passwordCheck.valid) errors.push(...passwordCheck.errors);

    return {
      valid: errors.length === 0,
      message: 'Invalid registration payload',
      errors,
      value: {
        name: String(payload.name || '').trim(),
        email: String(payload.email || '').trim().toLowerCase(),
        password: String(payload.password || ''),
        role: payload.role || 'viewer'
      }
    };
  }

  function validateLoginInput(payload) {
    const errors = [];
    if (!payload || typeof payload !== 'object') {
      return {
        valid: false,
        message: 'Invalid login payload',
        errors: ['Request body is required'],
        value: {}
      };
    }
    if (!payload.email || typeof payload.email !== 'string') errors.push('Valid email is required');
    if (!payload.password || typeof payload.password !== 'string') errors.push('Password is required');
    return {
      valid: errors.length === 0,
      message: 'Invalid login payload',
      errors,
      value: {
        email: String(payload.email || '').trim().toLowerCase(),
        password: String(payload.password || '')
      }
    };
  }

  async function register(payload) {
    const validation = validateRegistrationInput(payload);
    if (!validation.valid) {
      throw new ValidationError(validation.message, validation.errors);
    }

    if (store.users.some((user) => user.email === validation.value.email)) {
      throw new AppError('Email already exists', 409, 'DUPLICATE_EMAIL');
    }

    const passwordHash = await hashPassword(validation.value.password);
    const user = {
      id: crypto.randomBytes(8).toString('hex'),
      name: validation.value.name,
      email: validation.value.email,
      passwordHash,
      role: validation.value.role,
      createdAt: new Date().toISOString()
    };
    store.users.push(user);

    monitoring.recordEvent({
      type: 'crypto_event',
      severity: 'info',
      message: 'User registered',
      actor: user.email
    });

    return {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      createdAt: user.createdAt
    };
  }

  async function login(payload) {
    const validation = validateLoginInput(payload);
    if (!validation.valid) {
      throw new ValidationError(validation.message, validation.errors);
    }

    const user = store.users.find((item) => item.email === validation.value.email);
    if (!user) {
      throw new AppError('Invalid credentials', 401, 'INVALID_CREDENTIALS');
    }

    const ok = await comparePassword(validation.value.password, user.passwordHash);
    if (!ok) {
      throw new AppError('Invalid credentials', 401, 'INVALID_CREDENTIALS');
    }

    const token = jwt.sign(
      { sub: user.id, email: user.email, role: user.role, name: user.name },
      config.jwtSecret,
      { expiresIn: config.jwtExpiresIn }
    );

    store.authSessions.push({
      id: crypto.randomBytes(8).toString('hex'),
      userId: user.id,
      createdAt: new Date().toISOString()
    });

    return {
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    };
  }

  return {
    validateRegistrationInput,
    validateLoginInput,
    register,
    login
  };
}

module.exports = {
  createAuthService,
  roles
};
