"use strict";

const crypto = require("node:crypto");

function pbkdf2Async(password, salt, iterations, keyLength, digest) {
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(password, salt, iterations, keyLength, digest, (error, derivedKey) => {
      if (error) return reject(error);
      resolve(derivedKey);
    });
  });
}

module.exports = { pbkdf2Async };
