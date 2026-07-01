const bcrypt = require('bcryptjs');

function validatePassword(password) {
  const errors = [];
  if (typeof password !== 'string') {
    errors.push('Password must be a string');
  } else {
    if (password.length < 12) errors.push('Password must be at least 12 characters');
    if (!/[a-z]/.test(password)) errors.push('Password must contain a lowercase letter');
    if (!/[A-Z]/.test(password)) errors.push('Password must contain an uppercase letter');
    if (!/[0-9]/.test(password)) errors.push('Password must contain a digit');
    if (!/[^A-Za-z0-9]/.test(password)) errors.push('Password must contain a special character');
  }
  return {
    valid: errors.length === 0,
    errors
  };
}

function hashPassword(password) {
  return bcrypt.hash(password, 12);
}

function comparePassword(password, hash) {
  return bcrypt.compare(password, hash);
}

module.exports = {
  validatePassword,
  hashPassword,
  comparePassword
};
