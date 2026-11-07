'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { readdirSync } = require('node:fs');
const { join } = require('node:path');
const { scripts } = require('../package.json');

test('npm test explicitly runs every tests/*.test.cjs exactly once', () => {
  const script = scripts.test;
  assert.match(script, /^node --test(?: tests\/[\w-]+\.test\.cjs)+$/,
    'test script must explicitly register Node test files');
  const registered = script.split(/\s+/).slice(2);
  assert.equal(new Set(registered).size, registered.length,
    'test script must not register duplicate test files');
  const available = readdirSync(join(__dirname))
    .filter(name => name.endsWith('.test.cjs'))
    .map(name => 'tests/' + name)
    .sort();
  assert.deepEqual([...registered].sort(), available,
    'test script must include every tests/*.test.cjs file');
});
