// Self-test for new-packages.js, no network: node --test scripts/*.test.js
'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { addedPackages, judge } = require('./new-packages.js');

const now = Date.parse('2026-11-13T00:00:00Z');
const ago = (d) => new Date(now - d * 86400000).toISOString();
const rules = (r) => r.f.map((x) => x.rule);

test('finds packages added in package.json and in the lockfile', () => {
  const files = {
    'base:package.json': { dependencies: { express: '^4' } },
    'head:package.json': { dependencies: { express: '^4', 'left-padx': '^1' } },
    'base:package-lock.json': { packages: { '': {}, 'node_modules/express': { version: '4.22.3', resolved: 'https://registry.npmjs.org/express/-/express-4.22.3.tgz' } } },
    'head:package-lock.json': { packages: { '': {},
      'node_modules/express': { version: '4.22.3', resolved: 'https://registry.npmjs.org/express/-/express-4.22.3.tgz' },
      'node_modules/a/node_modules/@s/b': { version: '1.0.0', resolved: 'https://registry.npmjs.org/@s/b/-/b-1.0.0.tgz' },
      'node_modules/local': { link: true } } },
  };
  const added = addedPackages('base', 'head', ['package.json', 'package-lock.json'], (r, p) => files[`${r}:${p}`]);
  assert.deepStrictEqual([...added.keys()].sort(), ['@s/b', 'left-padx']);
  assert.strictEqual(added.get('left-padx').direct, true);
  assert.deepStrictEqual([...added.get('@s/b').versions], ['1.0.0']);
});

test('a name that is not on the registry fails', () => {
  assert.deepStrictEqual(rules(judge('left-padx', { versions: new Set(), direct: true }, null, now)), ['package-not-found']);
});

test('a package created last week fails, and so does a version from yesterday', () => {
  const doc = { time: { created: ago(5), '1.0.0': ago(1) }, maintainers: [{}, {}], repository: {} };
  assert.deepStrictEqual(rules(judge('fresh', { versions: new Set(['1.0.0']) }, doc, now)), ['package-too-new', 'version-too-new']);
});

test('an old package with an old version passes; missing repository and one maintainer only warn', () => {
  const doc = { time: { created: ago(4000), '2.1.3': ago(2000) }, maintainers: [{}], 'dist-tags': { latest: '2.1.3' }, versions: { '2.1.3': {} } };
  const r = judge('ms', { versions: new Set(['2.1.3']), direct: true }, doc, now);
  assert.deepStrictEqual(r.f, []);
  assert.strictEqual(r.w.length, 2);
});
