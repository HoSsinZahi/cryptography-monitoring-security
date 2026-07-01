const { config } = require('../config');
const { generateKeyMaterial } = require('../utils/crypto');

function createInitialState() {
  const initialKey = generateKeyMaterial(1);
  return {
    users: [],
    authSessions: [],
    cryptoEvents: [],
    auditEvents: [],
    alerts: [],
    keys: [initialKey],
    activeKeyVersion: 1,
    rotationPolicyDays: config.defaultRotationPolicyDays,
    thresholds: {
      tamper: config.tamperAlertThreshold,
      cryptoErrors: config.cryptoErrorAlertThreshold
    },
    projectName: 'Day 26 Engineer - Cryptography Monitoring Platform'
  };
}

function createStore() {
  const state = createInitialState();
  return state;
}

module.exports = {
  createStore,
  createInitialState
};
