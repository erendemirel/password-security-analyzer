#!/usr/bin/env node
const assert = require('assert');
const { analyzeOffline, modelInfo } = require('./index.js');

const info = modelInfo();
assert.strictEqual(info.advisory, true);

const weak = analyzeOffline('password');
assert.strictEqual(weak.label, 'weak');

const alpha = analyzeOffline('abcdefghijklmnopqrstuvwxyz');
assert.strictEqual(alpha.label, 'weak');
assert.ok((alpha.reasons || []).includes('sequential_run'));

console.log('node smoke OK');
