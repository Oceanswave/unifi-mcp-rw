'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { readSecretFile, validateConfig, loadConfig, loadSecrets, normalizeFingerprint, parseLocalHost, ConfigError, DEFAULTS } = require('../lib/config.cjs');
const { tmpDir } = require('./helpers.cjs');

const dir = tmpDir();
test.after(() => fs.rmSync(dir, { recursive: true, force: true }));

function secret(name, content, mode) {
  const p = path.join(dir, name);
  fs.writeFileSync(p, content);
  fs.chmodSync(p, mode);
  return p;
}

test('token file: mode 644 refused', () => {
  const p = secret('t644', 'a'.repeat(64), 0o644);
  assert.throws(() => readSecretFile(p), (e) => e instanceof ConfigError && /mode 0600/.test(e.message));
});

test('token file: mode 640 / 400 / 700 refused', () => {
  for (const m of [0o640, 0o400, 0o700, 0o604]) {
    const p = secret(`t${m.toString(8)}`, 'a'.repeat(64), m);
    assert.throws(() => readSecretFile(p), /mode 0600/);
  }
});

test('token file: < 32 chars refused', () => {
  const p = secret('tshort', 'a'.repeat(31) + '\n', 0o600);
  assert.throws(() => readSecretFile(p), /at least 32/);
});

test('token file: 600 + 32 chars accepted (trimmed)', () => {
  const p = secret('tok', '  ' + 'b'.repeat(32) + '\n', 0o600);
  assert.equal(readSecretFile(p), 'b'.repeat(32));
});

test('token file: symlink, directory, missing refused', () => {
  const target = secret('real', 'c'.repeat(40), 0o600);
  const link = path.join(dir, 'link');
  fs.symlinkSync(target, link);
  assert.throws(() => readSecretFile(link), /regular file/);
  assert.throws(() => readSecretFile(dir), /regular file/);
  assert.throws(() => readSecretFile(path.join(dir, 'nope')), /not readable/);
});

const CONSOLE = '942A6FF664C0000000000964970E0000000009E710560000000068A9873F:9999999999';
const L = (o) => validateConfig({ backend: 'local', ...o });

test('local config validation (backend: "local")', () => {
  const c = L({ local_host: '192.168.1.1', local_tls_cert_sha256: 'AB:'.repeat(31) + 'AB', other_tool_key: 'ignored' });
  assert.equal(c.backend, 'local');
  assert.equal(c.cloud, null);
  assert.equal(c.target.host, '192.168.1.1');
  assert.equal(c.target.port, 443);
  assert.equal(c.tls.mode, 'pin');
  assert.equal(c.tls.pin, 'ab'.repeat(32));
  assert.equal(c.siteName, 'default');
  assert.equal(c.listenHost, '127.0.0.1');
  assert.equal(c.listenPort, 18778);
  assert.equal(c.keyFile, DEFAULTS.keyFile);
  assert.equal(L({ local_host: 'udm.lan' }).tls.mode, 'system');
  assert.equal(L({ local_host: 'udm.lan', local_tls_ca_file: '/x/ca.pem' }).tls.mode, 'ca');
  assert.equal(parseLocalHost('udm.lan:8443').port, 8443);

  for (const bad of ['https://udm', 'udm/path', 'udm:99999', '', 'a b', '1.2.3.999', 'user@udm', '[::1]']) {
    assert.throws(() => L({ local_host: bad }), ConfigError, bad);
  }
  assert.throws(() => L({}), /local_host is required/);
  assert.throws(() => L({ local_host: 'udm', local_tls_cert_sha256: 'abc' }), /fingerprint/);
  assert.throws(() => L({ local_host: 'udm', local_tls_cert_sha256: 'ab'.repeat(32), local_tls_ca_file: '/x' }), /not both/);
  assert.throws(() => L({ local_host: 'udm', rw_listen_host: '0.0.0.0' }), /loopback/);
  assert.throws(() => L({ local_host: 'udm', local_site_id: 'nope' }), /local_site_id must be a UUID/);
  assert.throws(() => L({ local_host: 'udm', local_site_name: '../x' }), /local_site_name/);
  assert.equal(normalizeFingerprint('zz'), null);
});

test('backend selection: cloud is the default; unknown backend refused', () => {
  const c = validateConfig({ console_id: CONSOLE });
  assert.equal(c.backend, 'cloud');
  assert.deepEqual(c.cloud, { consoleId: CONSOLE, classicCapabilities: [] });
  assert.equal(c.target, null);
  assert.deepEqual(c.tls, { mode: 'system' });
  assert.equal(c.keyFile, DEFAULTS.cloudKeyFile);
  assert.match(c.keyFile, /\.config\/unifi-connectivity\/cloud-rw-key$/);
  assert.deepEqual(validateConfig({ backend: 'cloud', console_id: CONSOLE, cloud_allow_classic: true }).cloud.classicCapabilities, ['firewallrule', 'fixed_ip', 'radio']);
  for (const b of ['Cloud', 'LOCAL', 'remote', '', 1, null]) {
    if (b === null) continue; // null == absent -> default
    assert.throws(() => validateConfig({ backend: b, console_id: CONSOLE, local_host: 'udm' }), /backend must be/, String(b));
  }
});

test('cloud config: console_id required and strictly validated', () => {
  assert.throws(() => validateConfig({}), /console_id is required/);
  assert.throws(() => validateConfig({ local_host: '192.168.1.1' }), /console_id is required/); // old local-only config now needs backend: "local"
  for (const ok of [CONSOLE, 'ABCDEFGH', 'abcdef0123456789', 'A1B2C3D4:0']) {
    assert.equal(validateConfig({ console_id: ok }).cloud.consoleId, ok);
  }
  for (const bad of [
    'abc/defgh123', '../../../../x', 'abcdefgh/..', 'abcdefgh?x=1', 'abcdefgh#f', 'abcdefgh%2F', 'abcdefgh x', 'abcdefgh.example',
    'abcdefgh:', 'abcdefgh:1:2', 'abcdefgh:abc', 'short', 'a'.repeat(129), 'abcdefgh\n', 42, ['abcdefgh'], '',
  ]) {
    assert.throws(() => validateConfig({ console_id: bad }), ConfigError, JSON.stringify(bad));
  }
});

test('cloud config: host / TLS overrides refused, local keys ignored with a warning', () => {
  for (const k of ['cloud_host', 'cloud_base_url', 'cloud_url', 'cloud_port', 'cloud_api_host', 'cloud_tls_ca_file', 'cloud_tls_cert_sha256']) {
    assert.throws(() => validateConfig({ console_id: CONSOLE, [k]: 'x' }), /not supported/, k);
  }
  const c = validateConfig({ console_id: CONSOLE, local_host: 'udm', local_tls_cert_sha256: 'ab'.repeat(32), local_tls_ca_file: '/x' });
  assert.deepEqual(c.tls, { mode: 'system' });
  assert.equal(c.target, null);
  assert.match(c.warnings.join(), /local_host, local_tls_ca_file, local_tls_cert_sha256 ignored/);
});

test('site_id / site_name: neutral keys or local_ aliases, in both modes', () => {
  const S = '88f7af54-98f8-306a-a1c7-c9349722b1f6';
  assert.equal(validateConfig({ console_id: CONSOLE, site_id: S.toUpperCase() }).siteId, S);
  assert.equal(validateConfig({ console_id: CONSOLE, local_site_id: S }).siteId, S);
  assert.equal(L({ local_host: 'udm', site_id: S, local_site_id: S }).siteId, S);
  assert.equal(L({ local_host: 'udm', site_name: 'office' }).siteName, 'office');
  assert.throws(() => validateConfig({ console_id: CONSOLE, site_id: S, local_site_id: '0' + S.slice(1) }), /differ/);
  assert.throws(() => validateConfig({ console_id: CONSOLE, site_id: 'x' }), /site_id must be a UUID/);
  assert.throws(() => validateConfig({ console_id: CONSOLE, site_name: 'a/b' }), /site_name/);
});

test('loadSecrets: cloud key file must be a 0600 regular file', () => {
  const tokenFile = secret('ls-token', 'a'.repeat(64), 0o600);
  const cloudKey = secret('cloud-rw-key', 'site-manager-key-0123456789', 0o644);
  const cfg = validateConfig({ console_id: CONSOLE, cloud_rw_key_file: cloudKey, rw_token_file: tokenFile });
  assert.equal(cfg.keyFile, cloudKey);
  assert.throws(() => loadSecrets(cfg), (e) => e instanceof ConfigError && /Site Manager API key file.*mode 0600/.test(e.message));
  fs.chmodSync(cloudKey, 0o600);
  assert.deepEqual(loadSecrets(cfg), { token: 'a'.repeat(64), apiKey: 'site-manager-key-0123456789' });
  fs.writeFileSync(cloudKey, '\n');
  assert.throws(() => loadSecrets(cfg), /at least 16/);

  const localKey = secret('local-rw-key', 'local-udm-key-0123456789', 0o600);
  const lc = L({ local_host: 'udm', local_rw_key_file: localKey, rw_token_file: tokenFile, cloud_rw_key_file: cloudKey });
  assert.equal(loadSecrets(lc).apiKey, 'local-udm-key-0123456789');
});

test('loadConfig honours UNIFI_MCP_RW_CONFIG-style path (both backends)', () => {
  const p = path.join(dir, 'config.json');
  fs.writeFileSync(p, JSON.stringify({ backend: 'local', local_host: 'udm.lan', local_site_name: 'default' }));
  const c = loadConfig({ configPath: p });
  assert.equal(c.target.hostHeader, 'udm.lan');
  fs.writeFileSync(p, JSON.stringify({ console_id: CONSOLE }));
  assert.equal(loadConfig({ configPath: p }).backend, 'cloud');
  fs.writeFileSync(p, JSON.stringify({ console_id: 'x/../y' }));
  assert.throws(() => loadConfig({ configPath: p }), /console_id/);
  fs.writeFileSync(p, '{bad');
  assert.throws(() => loadConfig({ configPath: p }), /not valid JSON/);
});

test('example configs validate', () => {
  const root = path.join(__dirname, '..');
  const cloud = validateConfig(JSON.parse(fs.readFileSync(path.join(root, 'config.example.json'), 'utf8')));
  assert.equal(cloud.backend, 'cloud');
  const local = validateConfig(JSON.parse(fs.readFileSync(path.join(root, 'config.local.example.json'), 'utf8')));
  assert.equal(local.backend, 'local');
  assert.equal(local.tls.mode, 'pin');
  for (const c of [cloud, local]) {
    assert.equal(c.firewall.internalZoneIds.length, 2);
    assert.equal(c.firewall.wanZoneIds.length, 1);
  }
});

test('firewall zone id lists: strict UUID arrays, disjoint, default empty with a warning', () => {
  const Z1 = 'AAAAAAAA-0000-4000-8000-000000000001';
  const Z2 = 'aaaaaaaa-0000-4000-8000-000000000002';
  const C = (o) => validateConfig({ console_id: CONSOLE, ...o });
  const c = C({ firewall_internal_zone_ids: [Z1, Z1.toLowerCase()], firewall_wan_zone_ids: [Z2] });
  assert.deepEqual(c.firewall, { internalZoneIds: [Z1.toLowerCase()], wanZoneIds: [Z2] });
  assert.doesNotMatch(c.warnings.join(), /firewall_internal_zone_ids/);
  for (const value of [undefined, null, []]) {
    const none = C({ firewall_internal_zone_ids: value });
    assert.deepEqual(none.firewall, { internalZoneIds: [], wanZoneIds: [] });
    assert.ok(none.warnings.includes('firewall_internal_zone_ids not set: zone-based ALLOW policies will be refused, and every BLOCK/REJECT policy is treated as WAN-side (cosmetic changes only)'));
  }
  for (const bad of ['', Z1, {}, [Z1, 'Internal'], [1], [null], [`${Z1} `], Array(257).fill(Z1)]) {
    assert.throws(() => C({ firewall_internal_zone_ids: bad }), ConfigError, JSON.stringify(bad).slice(0, 40));
    assert.throws(() => C({ firewall_wan_zone_ids: bad }), ConfigError);
  }
  assert.throws(() => C({ firewall_internal_zone_ids: [Z1], firewall_wan_zone_ids: [Z1.toLowerCase()] }), /is in both firewall_internal_zone_ids and firewall_wan_zone_ids/);
});

test('cloud_allow_classic: false (default), true (all) or a strict subset array of capabilities', () => {
  const caps = (v) => validateConfig({ console_id: CONSOLE, cloud_allow_classic: v }).cloud.classicCapabilities;
  assert.deepEqual(validateConfig({ console_id: CONSOLE }).cloud.classicCapabilities, []);
  assert.deepEqual(caps(false), []);
  assert.deepEqual(caps(null), []);
  assert.deepEqual(caps([]), []);
  assert.deepEqual(caps(true), ['firewallrule', 'fixed_ip', 'radio']);
  assert.deepEqual(caps(['radio']), ['radio']);
  assert.deepEqual(caps(['radio', 'firewallrule']), ['firewallrule', 'radio']);
  assert.deepEqual(caps(['fixed_ip', 'radio', 'firewallrule']), ['firewallrule', 'fixed_ip', 'radio']);
  assert.ok(Object.isFrozen(caps(['radio'])));
  assert.match(validateConfig({ console_id: CONSOLE, cloud_allow_classic: ['radio'] }).warnings.join(), /cloud_allow_classic: .* for radio/);
  assert.doesNotMatch(validateConfig({ console_id: CONSOLE }).warnings.join(), /cloud_allow_classic/);
  for (const bad of ['yes', 'true', 1, 0, {}, { radio: true }, ['Radio'], ['radio', 'radio'], ['firewall'], ['all'], [true], [null], ['radio', 1], ['fixed-ip'], ['radio ']]) {
    assert.throws(() => caps(bad), (e) => e instanceof ConfigError && /^cloud_allow_classic /.test(e.message), JSON.stringify(bad));
  }
  assert.throws(() => caps(['radio', 'radio']), /twice/);
  assert.throws(() => caps(['firewall']), /unknown capability "firewall"/);
  // local mode ignores the key (all classic tools, as before)
  assert.equal(L({ local_host: 'udm', cloud_allow_classic: ['radio'] }).cloud, null);
});
