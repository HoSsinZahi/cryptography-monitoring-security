const { ValidationError } = require('../errors/AppError');

function validate(bodySchema) {
  return function validator(req, res, next) {
    const result = bodySchema(req.body || {});
    if (!result.valid) {
      return next(new ValidationError(result.message, result.errors));
    }
    req.body = result.value;
    return next();
  };
}

module.exports = validate;
