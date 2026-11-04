'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(ROOT, f), 'utf8');
const pkg = JSON.parse(read('package.json'));

test('version is the same in package.json, package-lock.json and the top CHANGELOG release', () => {
  const lock = JSON.parse(read('package-lock.json'));
  assert.equal(lock.version, pkg.version);
  assert.equal(lock.packages[''].version, pkg.version);
  const top = /^## \[(\d+\.\d+\.\d+)\]/m.exec(read('CHANGELOG.md'));
  assert.ok(top, 'CHANGELOG.md has no release heading');
  assert.equal(top[1], pkg.version);
});

test('runtime dependencies are exactly the ones the code requires; no dev dependencies', () => {
  assert.equal(pkg.private, true);
  assert.equal(pkg.engines.node, '>=22.23.4');
  assert.equal(pkg.devDependencies, undefined);
  const sources = ['http-server-rw.cjs', ...fs.readdirSync(path.join(ROOT, 'lib')).map((f) => `lib/${f}`), ...fs.readdirSync(path.join(ROOT, 'scripts')).map((f) => `scripts/${f}`)];
  const required = new Set();
  for (const f of sources) {
    for (const m of read(f).matchAll(/require\('([^'.][^']*)'\)/g)) {
      if (!m[1].startsWith('node:')) required.add(m[1].startsWith('@') ? m[1].split('/').slice(0, 2).join('/') : m[1].split('/')[0]);
    }
  }
  assert.deepEqual([...required].sort(), Object.keys(pkg.dependencies).sort());
});

test('"files" covers every runtime file, and every entry exists', () => {
  for (const entry of pkg.files) assert.ok(fs.existsSync(path.join(ROOT, entry)), entry);
  const covered = (f) => pkg.files.some((e) => (e.endsWith('/') ? f.startsWith(e) : f === e));
  for (const f of ['http-server-rw.cjs', 'unifi-mcp-rw.service', ...fs.readdirSync(path.join(ROOT, 'lib')).map((x) => `lib/${x}`), ...fs.readdirSync(path.join(ROOT, 'scripts')).map((x) => `scripts/${x}`)]) {
    assert.ok(covered(f), f);
  }
  assert.ok(!pkg.files.some((e) => e.startsWith('test')), 'tests are not shipped');
});
