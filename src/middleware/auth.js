const jwt = require('jsonwebtoken');
const { UnauthorizedError, ForbiddenError } = require('../errors/AppError');
const { config } = require('../config');

const rolePermissions = {
  admin: ['*'],
  security_engineer: ['view_reports', 'view_alerts'],
  crypto_operator: ['crypto_ops', 'rotate_key'],
  auditor: ['view_audit'],
  viewer: ['view_public_summary']
};

function hasPermission(role, permission) {
  const permissions = rolePermissions[role] || [];
  return permissions.includes('*') || permissions.includes(permission);
}

function authenticate(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) {
    return next(new UnauthorizedError('Missing access token'));
  }

  try {
    const payload = jwt.verify(token, config.jwtSecret);
    req.user = payload;
    if (req.app && req.app.locals && req.app.locals.services) {
      req.app.locals.services.monitoring.recordEvent({
        type: 'jwt_verified',
        severity: 'info',
        message: 'JWT verified',
        keyVersion: req.app.locals.services.crypto.getActiveKeyVersion(),
        actor: payload.email
      });
    }
    return next();
  } catch (error) {
    return next(new UnauthorizedError('Invalid or expired token'));
  }
}

function authorize(permission) {
  return function permissionGuard(req, res, next) {
    const role = req.user && req.user.role;
    if (!role || !hasPermission(role, permission)) {
      return next(new ForbiddenError('Insufficient role permissions'));
    }
    return next();
  };
}

module.exports = {
  authenticate,
  authorize,
  hasPermission,
  rolePermissions
};
