'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createAuditLog, formatLocalIso } = require('../lib/audit-log.cjs');
const { redact } = require('../lib/redact.cjs');
const { tmpDir } = require('./helpers.cjs');

const dir = tmpDir();
test.after(() => fs.rmSync(dir, { recursive: true, force: true }));

test('formatLocalIso has a numeric offset and represents the same instant', () => {
  const d = new Date('2026-10-18T20:30:00.123Z');
  const s = formatLocalIso(d);
  assert.match(s, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}[+-]\d\d:\d\d$/);
  assert.equal(new Date(s).getTime(), d.getTime());
});

test('redact replaces secret-looking keys deeply', () => {
  const r = redact({ a: 1, passphrase: 'p', nested: [{ x_passphrase: 'q', Authorization: 'Bearer x', apiKey: 'k', radius_secret: 's' }], token: 't' });
  assert.deepEqual(r, { a: 1, passphrase: '[REDACTED]', nested: [{ x_passphrase: '[REDACTED]', Authorization: '[REDACTED]', apiKey: '[REDACTED]', radius_secret: '[REDACTED]' }], token: '[REDACTED]' });
});

test('writes one JSON line with timestamps, redacted args; dir 0700, file 0600', () => {
  const stateDir = path.join(dir, 'state');
  fs.mkdirSync(stateDir, { mode: 0o755 });
  fs.chmodSync(stateDir, 0o755);
  const log = createAuditLog({ stateDir });
  log.write({
    tool: 'unifi_rw_create_wifi_broadcast',
    args: { broadcast: { name: 'Guest', securityConfiguration: { type: 'WPA2_PERSONAL', passphrase: 'hunter22hunter22' } }, dry_run: false },
    method: 'POST',
    endpoint: '/proxy/network/integration/v1/sites/x/wifi/broadcasts',
    dry_run: false,
    status: 201,
  });
  // existing file with loose perms is tightened
  fs.chmodSync(log.file, 0o644);
  log.write({ tool: 't', args: {}, method: 'PUT', endpoint: '/e', dry_run: true, status: 'refused', error: 'Refused by guard: x' });

  const text = fs.readFileSync(log.file, 'utf8');
  assert.ok(!text.includes('hunter22'));
  const lines = text.trim().split('\n').map(JSON.parse);
  assert.equal(lines.length, 2);
  const [a, b] = lines;
  assert.match(a.ts_utc, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);
  assert.match(a.ts_local, /[+-]\d\d:\d\d$/);
  assert.equal(a.args.broadcast.securityConfiguration.passphrase, '[REDACTED]');
  assert.equal(a.status, 201);
  assert.equal(a.method, 'POST');
  assert.equal(a.dry_run, false);
  assert.equal(b.status, 'refused');
  assert.equal(b.error, 'Refused by guard: x');
  assert.equal(fs.statSync(stateDir).mode & 0o777, 0o700);
  assert.equal(fs.statSync(log.file).mode & 0o777, 0o600);
});

test('scrubs configured secrets from every field, before truncating errors', () => {
  const key = 'api-key-value-0123456789abcdef';
  const token = 'bearer-token-value-0123456789abcdef';
  const log = createAuditLog({ stateDir: path.join(dir, 'scrub'), secrets: [key, token] });
  // the secret straddles the 300-char truncation point of the error field
  const error = 'x'.repeat(290) + key;
  const line = log.write({ tool: 't', args: { note: `t=${token}`, q: encodeURIComponent(key) }, status: 'error', error });
  const text = fs.readFileSync(log.file, 'utf8');
  for (const s of [key, token, key.slice(0, 10), encodeURIComponent(key)]) assert.ok(!text.includes(s), s);
  assert.equal(line.args.note, 't=[REDACTED]');
  assert.match(line.error, /x{290}\[REDACTED\]$/);
});

test('creates missing state dir with 0700', () => {
  const stateDir = path.join(dir, 'a', 'b');
  const log = createAuditLog({ stateDir });
  log.write({ tool: 't', args: null, status: 'error' });
  assert.equal(fs.statSync(stateDir).mode & 0o777, 0o700);
  assert.equal(fs.statSync(log.file).mode & 0o777, 0o600);
});
